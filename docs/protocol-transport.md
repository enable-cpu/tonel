# Transport Notes: Raw HY2 Packet Transport

This document records the current transport model in the working tree.

## Summary

Tonel carries raw UDP payload bytes over its fake TCP transport.
It does not add any Tonel-level frame header, tunnel identifier, path identifier,
connection identifier, or other application-level envelope around the payload.

For the current use case, those raw UDP payloads are expected to be hy2 packets.

## Wire Behavior

The transport behavior is intentionally minimal:

1. Establish the fake TCP sub-connection.
2. Optionally exchange the configured `handshake_packet`.
3. Send and receive raw UDP payload bytes directly.

If encryption is enabled, the raw payload bytes are encrypted in place before being sent
on the fake TCP transport and decrypted after they are received.

## Flow Binding

Each incoming UDP flow maintains two fakeTCP pools:

- One concurrent pool is active for business traffic and a second pool is kept hot as standby.
- Client-originated packets are striped across live fakeTCP connections in the active pool.
- Server-originated packets are sent toward the connections that have recently carried business payloads.
- If the active concurrent pool degrades or fails, Tonel switches the flow to the hot standby pool.
- The previously active pool is then repaired in the background and becomes the new standby pool.
- Close events are fed into a per-flow learner, which adjusts business send width and repair backoff.

## What Was Removed

The previous working-tree design introduced a Tonel mux layer with:

- a custom frame header
- explicit frame types
- on-wire tunnel, path, and logical connection identifiers
- extra control traffic for path setup and multiplexing

That layer has been removed.

## Current Session Model

Session association is again implicit in transport topology rather than explicit on the wire:

- A client UDP peer is represented by one UDP flow session with a fakeTCP pool.
- The server groups accepted fakeTCP connections for the same UDP flow into one shared transport session.
- The server prefers the connections that have recently carried business payloads, so the hot standby pool stays reserved until failover.
- Payload routing depends on socket ownership and connection setup, not on a Tonel frame envelope.

The `--tcp-connections` client option controls the size of each per-flow pool.

On Linux, `--auto-rule` is expected to manage both NAT rules and the necessary `FORWARD`
accept rules between the TUN interface and the selected physical interface.

This keeps the wire format minimal and avoids adding a second protocol on top of hy2.

## Benefits

- No Tonel-specific wire overhead beyond the underlying IP and TCP headers.
- hy2 packets are transported unchanged at the Tonel protocol layer.
- Per-flow failover is possible without adding a second framing protocol.
- Concurrent striping is still available when raw throughput matters more than deterministic path ownership.
- There is no duplicate multiplexing scheme competing with hy2's own packet semantics.

## Tradeoffs

- There is no Tonel-level wire versioning or self-description.
- There are no explicit tunnel/path/connection identifiers on the wire.
- Future transport-side control features would need to be added carefully to avoid reintroducing a second framing layer.

## Operational Impact

- Deployments using the removed mux frame layer are not compatible with this raw-payload transport.
- Both ends must expect direct UDP payload forwarding after the optional handshake packet.
