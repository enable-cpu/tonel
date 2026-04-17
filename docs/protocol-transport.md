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

Each incoming UDP flow can maintain a small fakeTCP connection pool, and the behavior of that
pool is selected by `--tcp-mode`.

### `pool` mode

- One fakeTCP connection is active for payload delivery.
- Additional fakeTCP connections stay established as hot standbys.
- Tonel does not stripe one UDP flow across multiple fakeTCP connections at the same time.
- If the active fakeTCP connection breaks, Tonel fails over the flow to another live connection in the pool.
- Other UDP flows still keep their own independent pools and are not affected by a different flow's failure.

### `concurrent` mode

- All live fakeTCP connections in the pool participate in payload delivery.
- Client-originated packets are striped across live fakeTCP connections.
- Server-originated packets are also striped across live fakeTCP connections for the same flow.
- If one fakeTCP connection breaks, the flow continues on the remaining live connections.

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
- In `pool` mode, the server sends return traffic on the currently active connection.
- In `concurrent` mode, the server stripes return traffic across live connections in the same flow session.
- Payload routing depends on socket ownership and connection setup, not on a Tonel frame envelope.

The `--tcp-connections` client option controls the size of this per-flow pool, and `--tcp-mode`
controls whether the pool behaves as failover hot standbys or as concurrent transport channels.

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
