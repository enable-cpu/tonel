use cfg_if::cfg_if;
use clap::ArgMatches;
use clap::{crate_version, Arg, ArgAction, Command};
use log::{debug, error, info, trace};
use std::fmt;
use std::fs;
use std::future::Future;
use std::io;
#[cfg(any(
    target_os = "openbsd",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    target_os = "macos",
    target_os = "ios"
))]
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::broadcast;
use tokio::task::JoinSet;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tonel::tcp::packet::MAX_PACKET_LEN;
use tonel::tcp::{Socket, Stack};
use tonel::utils::{assign_ipv6_address, new_udp_reuseport};
use tonel::Encryption;
use tun::Device;

use tonel::UDP_SOCK_READ_DEADLINE;

cfg_if! {
    if #[cfg(all(feature = "alloc-jem", not(target_env = "msvc")))] {
        use jemallocator::Jemalloc;
        #[global_allocator]
        static GLOBAL: Jemalloc = Jemalloc;
    } else if #[cfg(all(feature = "alloc-mi", unix))] {
        use mimalloc::MiMalloc;
        #[global_allocator]
        static GLOBAL: MiMalloc = MiMalloc;
    }
}

fn main() {
    #[cfg(not(target_os = "macos"))]
    let tun_value_name = "tunX|fd";
    #[cfg(target_os = "macos")]
    let tun_value_name = "utunX|fd";
    let matches = Command::new("Tonel Client")
        .version(crate_version!())
        .author("Saber Haj Rabiee")
        .arg(
            Arg::new("local")
                .short('l')
                .long("local")
                .required(true)
                .value_name("IP:PORT")
                .help("Sets the IP and port where Tonel Client listens for incoming UDP datagrams, \n\
                    IPv6 address need to be specified as: \"[IPv6]:PORT\"")
        )
        .arg(
            Arg::new("remote")
                .short('r')
                .long("remote")
                .required(true)
                .value_name("IP or HOST NAME:PORT")
                .help("Sets the address or host name and port where Tonel Client connects to Tonel Server, \n\
                    IPv6 address need to be specified as: \"[IPv6]:PORT\"")
        )
        .arg(
            Arg::new("tun_local")
                .long("tun-local")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv4 local address (O/S's end)")
                .default_value("192.168.200.1")
        )
        .arg(
            Arg::new("tun_peer")
                .long("tun-peer")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv4 destination (peer) address (Tonel Client's end). \n\
                       You will need to setup SNAT/MASQUERADE rules on your Internet facing interface \n\
                       in order for Tonel Client to connect to Tonel Server")
                .default_value("192.168.200.2")
        )
        .arg(
            Arg::new("ipv4_only")
                .long("ipv4-only")
                .short('4')
                .required(false)
                .help("Only use IPv4 address when connecting to remote")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["tun_local6", "tun_peer6"]),
        )
        .arg(
            Arg::new("tun_local6")
                .long("tun-local6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 local address (O/S's end)")
                .default_value("fcc8::1")
        )
        .arg(
            Arg::new("tun_peer6")
                .long("tun-peer6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 destination (peer) address (Tonel Client's end). \n\
                       You will need to setup SNAT/MASQUERADE rules on your Internet facing interface \n\
                       in order for Tonel Client to connect to Tonel Server")
                .default_value("fcc8::2")
        )
        .arg(
            Arg::new("handshake_packet")
                .long("handshake-packet")
                .required(false)
                .value_name("PATH")
                .help("Specify a file, which, after TCP handshake, its content will be sent as the \n\
                      first data packet to the server.\n\
                      Note: ensure this file's size does not exceed the MTU of the outgoing interface. \n\
                      The content is always sent out in a single packet and will not be further segmented")
        )
        .arg(
            Arg::new("tcp_connections")
                .long("tcp-connections")
                .required(false)
                .value_name("number")
                .help("The number of TCP connections per each client.")
                .default_value("1")
        )
        .arg(
            Arg::new("udp_connections")
                .long("udp-connections")
                .required(false)
                .value_name("number")
                .help("The number of UDP connections per each client.")
                .default_value("1")
                )
        .arg(
            Arg::new("tun_queues")
                .long("tun-queues")
                .required(false)
                .value_name("number")
                .help("The number of queues for TUN interface. Default is \n\
                       set to 1. The platform should support multiple queues feature.")
                .default_value("1")
                )
        .arg(
            Arg::new("encryption")
                .long("encryption")
                .required(false)
                .value_name("encryption")
                .help("Specify an encryption algorithm for using in TCP connections. \n\
                       Server and client should use the same encryption. \n\
                       Currently XOR is only supported and the format should be 'xor:key'.")
        )
        .arg(
            Arg::new("auto_rule")
                .long("auto-rule")
                .required(false)
                .value_name("interface-name")
                .help("Automatically adds and removes required firewall and sysctl rules.\n\
                       The argument needs the name of an active network interface \n\
                       that the firewall will route the traffic over it. (e.g. eth0)")
        )
        .arg(
            Arg::new("daemonize")
                .long("daemonize")
                .short('d')
                .required(false)
                .action(ArgAction::SetTrue)
                .help("Start the process as a daemon.")
        )
        .arg(
            Arg::new("log_output")
                .long("log-output")
                .value_name("path")
                .required(false)
                .help("Log output path. Default is stderr.")
        )
        .arg(
            Arg::new("log_level")
                .long("log-level")
                .required(false)
                .value_name("level")
                .default_value("info")
                .help("Log output level. It could be one of the following:\n\
                    off, error, warn, info, debug, trace.")
        )
        .arg(
            Arg::new("deadline")
                .long("deadline")
                .required(false)
                .value_name("deadline")
                .help("An open connection will be closed forcibly after provided seconds. Default is disabled.")
        )
        .arg(
        Arg::new("tun")
            .long("tun")
            .required(false)
            .value_name(tun_value_name)
            .help(
                "Sets the Tun interface name and if it is absent, the OS \n\
                   will pick the next available name. \n\
                   You can also create your TUN device and \n\
                   pass the int32 file descriptor to this switch.",
            ),
    ).get_matches();

    let mut log_builder = env_logger::Builder::new();
    log_builder.filter(
        None,
        matches
            .get_one::<String>("log_level")
            .unwrap()
            .parse()
            .unwrap(),
    );

    log_builder.init();

    let daemonize = matches.get_flag("daemonize");
    if daemonize {
        let mut daemon = daemonize::Daemonize::new().working_directory("/tmp");

        if let Some(path) = matches.get_one::<String>("log_output") {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)
                .expect("log output path does not exist.");

            daemon = daemon.stderr(file);
        }
        daemon.start().unwrap_or_else(|e| {
            eprintln!("failed to daemonize: {e}");
            std::process::exit(1);
        });
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(main_async(matches))
        .unwrap();
}

enum ClientUdpActivity {
    Cancelled,
    Received(usize),
    PacketReceived,
    IdleTimeout,
    UdpError(io::Error),
}

struct ClientSessionState {
    live_tcp_sockets: AtomicUsize,
    next_tcp_socket_index: AtomicUsize,
}

impl ClientSessionState {
    fn new(live_tcp_sockets: usize) -> Self {
        Self {
            live_tcp_sockets: AtomicUsize::new(live_tcp_sockets),
            next_tcp_socket_index: AtomicUsize::new(0),
        }
    }

    fn live_tcp_sockets(&self) -> usize {
        self.live_tcp_sockets.load(Ordering::Acquire)
    }

    fn reserve_next_tcp_socket(&self, tcp_socks_len: usize) -> usize {
        self.next_tcp_socket_index.fetch_add(1, Ordering::Relaxed) % tcp_socks_len
    }

    fn note_tcp_socket_closed(&self) -> usize {
        loop {
            let current = self.live_tcp_sockets.load(Ordering::Acquire);
            if current == 0 {
                return 0;
            }
            if self
                .live_tcp_sockets
                .compare_exchange(current, current - 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return current - 1;
            }
        }
    }
}

struct ClientTcpSocketState {
    alive: AtomicBool,
}

impl ClientTcpSocketState {
    fn new() -> Self {
        Self {
            alive: AtomicBool::new(true),
        }
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    fn mark_dead(&self) -> bool {
        self.alive.swap(false, Ordering::AcqRel)
    }
}

struct ClientTcpSocket {
    socket: Arc<Socket>,
    state: ClientTcpSocketState,
}

impl ClientTcpSocket {
    fn new(socket: Socket) -> Self {
        Self {
            socket: Arc::new(socket),
            state: ClientTcpSocketState::new(),
        }
    }

    fn is_alive(&self) -> bool {
        self.state.is_alive()
    }
}

impl fmt::Display for ClientTcpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.socket)
    }
}

trait ClientSocketLiveness {
    fn is_alive(&self) -> bool;
}

impl ClientSocketLiveness for ClientTcpSocket {
    fn is_alive(&self) -> bool {
        self.is_alive()
    }
}

impl ClientSocketLiveness for ClientTcpSocketState {
    fn is_alive(&self) -> bool {
        self.is_alive()
    }
}

impl<T: ClientSocketLiveness + ?Sized> ClientSocketLiveness for Arc<T> {
    fn is_alive(&self) -> bool {
        (**self).is_alive()
    }
}

fn close_tcp_socket_state(
    tcp_sock_state: &ClientTcpSocketState,
    session_state: &ClientSessionState,
) -> (usize, bool) {
    if tcp_sock_state.mark_dead() {
        (session_state.note_tcp_socket_closed(), true)
    } else {
        (session_state.live_tcp_sockets(), false)
    }
}

fn close_tcp_socket(
    tcp_sock: &ClientTcpSocket,
    session_state: &ClientSessionState,
    reason: &str,
) -> usize {
    let (remaining, newly_closed) = close_tcp_socket_state(&tcp_sock.state, session_state);
    if newly_closed {
        info!(
            "TCP sub-connection {} closed: {}. Remaining live sub-connections: {}",
            tcp_sock.socket, reason, remaining
        );
    }
    remaining
}

fn find_next_live_tcp_socket_index<T: ClientSocketLiveness>(
    tcp_socks: &[T],
    session_state: &ClientSessionState,
) -> Option<usize> {
    for _ in 0..tcp_socks.len() {
        let index = session_state.reserve_next_tcp_socket(tcp_socks.len());
        if tcp_socks[index].is_alive() {
            return Some(index);
        }
    }

    None
}

async fn wait_for_client_udp_activity(
    udp_sock: &UdpSocket,
    buf_udp: &mut [u8],
    packet_received_rx: &mut broadcast::Receiver<()>,
    cancellation: &CancellationToken,
    idle_timeout: std::time::Duration,
) -> ClientUdpActivity {
    let read_timeout = time::sleep(idle_timeout);
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => ClientUdpActivity::Cancelled,
        res = udp_sock.recv(buf_udp) => match res {
            Ok(size) => ClientUdpActivity::Received(size),
            Err(err) => ClientUdpActivity::UdpError(err),
        },
        _ = packet_received_rx.recv() => ClientUdpActivity::PacketReceived,
        _ = read_timeout => ClientUdpActivity::IdleTimeout,
    }
}

type TcpSendFuture<'a> = Pin<Box<dyn Future<Output = Option<()>> + Send + 'a>>;
type TcpRecvFuture<'a> = Pin<Box<dyn Future<Output = Option<usize>> + Send + 'a>>;
type TcpForwardFuture<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

async fn send_on_live_tcp_socket_with_sender<T, S, C>(
    tcp_socks: &[Arc<T>],
    session_state: &ClientSessionState,
    buf: &mut [u8],
    payload: &[u8],
    sender: S,
    closer: C,
) -> bool
where
    T: ClientSocketLiveness,
    S: for<'a> Fn(&'a Arc<T>, &'a mut [u8], &'a [u8]) -> TcpSendFuture<'a>,
    C: Fn(&Arc<T>) -> usize,
{
    while let Some(index) = find_next_live_tcp_socket_index(tcp_socks, session_state) {
        let tcp_sock = &tcp_socks[index];
        if sender(tcp_sock, buf, payload).await.is_some() {
            return true;
        }

        if closer(tcp_sock) == 0 {
            return false;
        }
    }

    false
}

async fn send_on_live_tcp_socket(
    tcp_socks: &[Arc<ClientTcpSocket>],
    session_state: &ClientSessionState,
    buf: &mut [u8],
    payload: &[u8],
) -> bool {
    send_on_live_tcp_socket_with_sender(
        tcp_socks,
        session_state,
        buf,
        payload,
        |tcp_sock, buf, payload| Box::pin(async move { tcp_sock.socket.send(buf, payload).await }),
        |tcp_sock| {
            close_tcp_socket(
                tcp_sock,
                session_state,
                "send failure while forwarding UDP payload",
            )
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_tcp_connect_loop<S, H, F, R, U, C>(
    connect: &TcpConnect,
    tcp_sock: &S,
    buf: &mut [u8],
    send_handshake: H,
    send_first_packet: F,
    recv_tcp: R,
    forward_udp: U,
    udp_count: usize,
    close_socket: C,
) where
    S: fmt::Display + Sync,
    H: for<'a> Fn(&'a S, &'a mut [u8], &'a [u8]) -> TcpSendFuture<'a>,
    F: for<'a> Fn(&'a S, &'a mut [u8], &'a [u8]) -> TcpSendFuture<'a>,
    R: for<'a> Fn(&'a S, &'a mut [u8]) -> TcpRecvFuture<'a>,
    U: for<'a> Fn(&'a S, usize, &'a [u8]) -> TcpForwardFuture<'a>,
    C: Fn(&S, &str) -> usize,
{
    if let Some(ref packet) = *connect.handshake_packet {
        if send_handshake(tcp_sock, buf, packet).await.is_none() {
            error!("Failed to send handshake packet to remote, closing sub-connection.");
            if close_socket(tcp_sock, "handshake packet send failure") == 0 {
                connect.cancellation.cancel();
            }
            return;
        }
        trace!("Sent handshake packet to: {}", tcp_sock);
    }

    let mut should_receive_handshake_packet = connect.handshake_packet.is_some();
    let mut udp_sock_index = 0usize;
    let mut close_reason = "peer closed the TCP sub-connection";
    let udp_rounds = udp_count.max(1);

    loop {
        tokio::select! {
            biased;
            _ = connect.cancellation.cancelled() => {
                debug!("Closing connection requested on {}, closing sub-connection", tcp_sock);
                break;
            }
            res = recv_tcp(tcp_sock, buf) => {
                match res {
                    Some(size) => {
                        if should_receive_handshake_packet {
                            should_receive_handshake_packet = false;
                            trace!("Received handshake packet to: {}", tcp_sock);
                            if let Some(ref packet) = connect.first_packet {
                                trace!("Sending first packet to: {}", tcp_sock);
                                if send_first_packet(tcp_sock, buf, packet).await.is_none() {
                                    close_reason = "failed to send first packet after handshake";
                                    break;
                                }
                            }
                            continue;
                        }

                        if let Some(ref enc) = *connect.encryption {
                            enc.decrypt(&mut buf[..size]);
                        }
                        udp_sock_index = (udp_sock_index + 1) % udp_rounds;
                        if let Err(err) = forward_udp(tcp_sock, udp_sock_index, &buf[..size]).await {
                            debug!(
                                "Unable to send UDP packet on {}: {err}, closing sub-connection",
                                tcp_sock
                            );
                            close_reason = "failed to forward TCP payload to UDP";
                            break;
                        }
                    }
                    None => {
                        close_reason = "recv returned EOF";
                        break;
                    }
                }
            }
        }
        _ = connect.packet_received_tx.send(());
    }

    if close_socket(tcp_sock, close_reason) == 0 {
        connect.cancellation.cancel();
    }
}

async fn main_async(matches: ArgMatches) -> io::Result<()> {
    let local_addr: Arc<SocketAddr> = Arc::new(
        matches
            .get_one::<String>("local")
            .unwrap()
            .parse()
            .expect("bad local address"),
    );

    let ipv4_only = matches.get_flag("ipv4_only");

    let remote_addr = tokio::net::lookup_host(matches.get_one::<String>("remote").unwrap())
        .await
        .expect("bad remote address or host")
        .find(|addr| !ipv4_only || addr.is_ipv4())
        .expect("unable to resolve remote host name");

    info!("Remote address is: {}", remote_addr);

    let tun_local: Ipv4Addr = matches
        .get_one::<String>("tun_local")
        .unwrap()
        .parse()
        .expect("bad local address for Tun interface");

    let tun_peer: Ipv4Addr = matches
        .get_one::<String>("tun_peer")
        .unwrap()
        .parse()
        .expect("bad peer address for Tun interface");

    let (tun_local6, tun_peer6) = if ipv4_only {
        (None, None)
    } else {
        (
            matches.get_one::<String>("tun_local6").map(|v| {
                v.parse::<Ipv6Addr>()
                    .expect("bad local address for Tun interface")
            }),
            matches.get_one::<String>("tun_peer6").map(|v| {
                v.parse::<Ipv6Addr>()
                    .expect("bad peer address for Tun interface")
            }),
        )
    };

    let tcp_socks_amount: usize = matches
        .get_one::<String>("tcp_connections")
        .unwrap()
        .parse()
        .expect("Unspecified number of TCP connections per each client");
    if tcp_socks_amount == 0 {
        panic!("TCP connections should be greater than or equal to 1");
    }

    let udp_socks_amount: usize = matches
        .get_one::<String>("udp_connections")
        .unwrap()
        .parse()
        .expect("Unspecified number of UDP connections per each client");
    if udp_socks_amount == 0 {
        panic!("UDP connections should be greater than or equal to 1");
    }

    let encryption = matches
        .get_one::<String>("encryption")
        .map(Encryption::from);
    debug!("Encryption in use: {:?}", encryption);
    let encryption = Arc::new(encryption);

    let handshake_packet: Arc<Option<Vec<u8>>> = Arc::new(
        matches
            .get_one::<String>("handshake_packet")
            .map(fs::read)
            .transpose()?,
    );

    let mut tun_config = tun::Configuration::default();
    tun_config
        .netmask("255.255.255.0")
        .address(tun_local)
        .destination(tun_peer)
        .up()
        .queues(
            matches
                .get_one::<String>("tun_queues")
                .unwrap()
                .parse()
                .unwrap(),
        );
    if let Some(name) = matches.get_one::<String>("tun") {
        if let Ok(fd) = name.parse::<i32>() {
            tun_config.raw_fd(fd);
        } else {
            tun_config.name(name);
        }
    }

    let tun = tun::create(&tun_config).unwrap();

    if let Some(tun_local6) = tun_local6 {
        #[cfg(any(
            target_os = "openbsd",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "dragonfly",
            target_os = "macos",
        ))]
        assign_ipv6_address(tun.name(), tun_local6);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        assign_ipv6_address(
            tun.name(),
            tun_local6,
            tun_peer6.expect("IPv6 peer address undefined"),
        );
    }

    let exit_fn: Box<dyn Fn() + 'static + Send> = if let Some(dev_name) =
        matches.get_one::<String>("auto_rule")
    {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                auto_rule(
                    dev_name,
                    ipv4_only,
                    remote_addr,
                )
            } else if
                #[cfg(target_os = "macos")] {
                auto_rule(
                    tun.name(),
                    dev_name,
                    tun_peer,
                    tun_peer6,
                )
            }
        }
    } else {
        info!(
            "Make sure ip forwarding is enabled, run the following commands or equivalent in your OS: \n\
            sysctl -w net.ipv4.ip_forward=1 \n\
            sysctl -w net.ipv6.conf.all.forwarding=1"
        );

        if ipv4_only {
            info!(
                "Make sure your firewall routes packets, replace the dev_name with \n\
                your active network interface (like eth0) and run the following commands for iptables \n\
                or equivalent in your OS: \n\
                iptables -t nat -I POSTROUTING -o dev_name -p tcp --dport {} -j MASQUERADE",
                remote_addr.port(),
            );
        } else {
            info!(
                "Make sure your firewall routes packets, replace the dev_name with \n\
                your active network interface (like eth0) and run the following commands for iptables \n\
                or equivalent in your OS: \n\
                iptables -t nat -I POSTROUTING -o dev_name -p tcp --dport {} -j MASQUERADE\n\
                ip6tables -t nat -I POSTROUTING -o dev_name -p tcp --dport {} -j MASQUERADE",
                remote_addr.port(),
                remote_addr.port(),
            );
        }

        Box::new(|| {})
    };

    ctrlc::set_handler(move || {
        exit_fn();
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    info!("Created TUN device {}", tun.name());

    let deadline = matches
        .get_one::<String>("deadline")
        .map(|f| f.parse::<u64>().unwrap());

    let stack = Arc::new(Stack::new(tun, tun_peer, tun_peer6, deadline));

    let local_addr = local_addr.clone();
    let mut buf_r = [0u8; MAX_PACKET_LEN];
    let udp_sock = new_udp_reuseport(*local_addr).unwrap();

    'main_loop: loop {
        let (size, addr) = udp_sock.recv_from(&mut buf_r).await.unwrap();

        info!("New UDP client from {}", addr);
        let stack = stack.clone();
        let local_addr = local_addr.clone();
        let handshake_packet = handshake_packet.clone();
        let encryption = encryption.clone();

        let udp_socks: Arc<Vec<_>> = {
            let mut socks = Vec::with_capacity(udp_socks_amount);
            for _ in 0..udp_socks_amount {
                let udp_sock = match new_udp_reuseport(*local_addr) {
                    Ok(udp_sock) => udp_sock,
                    Err(err) => {
                        error!("Craeting new udp socket error: {err}");
                        continue 'main_loop;
                    }
                };
                if let Err(err) = udp_sock.connect(addr).await {
                    error!("Unable to connect to {addr} over udp: {err}");
                    continue 'main_loop;
                }

                socks.push(Arc::new(udp_sock));
            }
            Arc::new(socks)
        };

        let cancellation = CancellationToken::new();
        let (packet_received_tx, _) = broadcast::channel(1);

        let tcp_socks: Arc<Vec<_>> = {
            let mut socks = Vec::with_capacity(tcp_socks_amount);
            let mut set = JoinSet::new();
            let mut first_connection = true;
            let mut first_port = 0u16;
            for i in 0..tcp_socks_amount {
                debug!("Creating tcp stream {i} to {remote_addr} for {addr}.");
                let stack = stack.clone();
                if first_connection {
                    let mut buf = [0u8; MAX_PACKET_LEN];
                    let res = stack.connect(&mut buf, remote_addr, 0).await;
                    let tcp_sock = if let Some((tcp_sock, port)) = res {
                        first_port = port;
                        Arc::new(ClientTcpSocket::new(tcp_sock))
                    } else {
                        error!("Unable to connect a tcp sock to remote {remote_addr} for {addr}");
                        continue 'main_loop;
                    };
                    socks.push(tcp_sock);
                    first_connection = false;
                    continue;
                }
                set.spawn(async move {
                    let mut buf = [0u8; MAX_PACKET_LEN];
                    let (tcp_sock, _) = stack
                        .connect(&mut buf, remote_addr, first_port as u32)
                        .await?;
                    Some(Arc::new(ClientTcpSocket::new(tcp_sock)))
                });
            }
            while let Some(tcp_sock) = set.join_next().await {
                let tcp_sock = match tcp_sock {
                    Ok(tcp_sock) => match tcp_sock {
                        Some(tcp_sock) => tcp_sock,
                        None => {
                            error!(
                                "Unable to connect a tcp sock to remote {remote_addr} for {addr}"
                            );
                            cancellation.cancel();
                            continue 'main_loop;
                        }
                    },
                    Err(err) => {
                        error!(
                                "Unable to join a tcp sock connection to remote {remote_addr} for {addr}: {err}"
                            );
                        cancellation.cancel();
                        continue 'main_loop;
                    }
                };
                socks.push(tcp_sock);
            }
            Arc::new(socks)
        };
        let session_state = Arc::new(ClientSessionState::new(tcp_socks.len()));

        for (index, tcp_sock) in tcp_socks.iter().enumerate() {
            let mut buf = [0u8; MAX_PACKET_LEN];
            let tcp_connect = TcpConnect {
                udp_socks: udp_socks.clone(),
                encryption: encryption.clone(),
                packet_received_tx: packet_received_tx.clone(),
                handshake_packet: handshake_packet.clone(),
                cancellation: cancellation.clone(),
                first_packet: if index == 0 {
                    Some(buf_r[..size].into())
                } else {
                    None
                },
                session_state: session_state.clone(),
            };
            let tcp_sock = tcp_sock.clone();
            tokio::spawn(async move {
                tcp_connect.handle(&mut buf, tcp_sock).await;
            });
        }

        for udp_sock in udp_socks.iter() {
            let udp_sock = udp_sock.clone();
            let mut packet_received_rx = packet_received_tx.subscribe();
            let packet_received_tx = packet_received_tx.clone();
            let cancellation = cancellation.clone();
            let encryption = encryption.clone();
            let tcp_socks = tcp_socks.clone();
            let session_state = session_state.clone();
            tokio::spawn(async move {
                let mut buf_udp = [0u8; MAX_PACKET_LEN];
                let mut buf = [0u8; MAX_PACKET_LEN];
                loop {
                    match wait_for_client_udp_activity(
                        &udp_sock,
                        &mut buf_udp,
                        &mut packet_received_rx,
                        &cancellation,
                        UDP_SOCK_READ_DEADLINE,
                    )
                    .await
                    {
                        ClientUdpActivity::Cancelled => {
                            debug!(
                                "Closing connection requested on {:?}, closing connection UDP",
                                udp_sock
                            );
                            break;
                        }
                        ClientUdpActivity::Received(size) => {
                            if let Some(ref enc) = *encryption {
                                enc.encrypt(&mut buf_udp[..size]);
                            }
                            if !send_on_live_tcp_socket(
                                &tcp_socks,
                                &session_state,
                                &mut buf,
                                &buf_udp[..size],
                            )
                            .await
                            {
                                debug!("No live TCP sub-connections remain on {:?}, closing connection", udp_sock);
                                cancellation.cancel();
                                break;
                            }
                        }
                        ClientUdpActivity::PacketReceived => {
                            continue;
                        }
                        ClientUdpActivity::IdleTimeout => {
                            debug!(
                                "No traffic seen in the last {:?} on {:?}, closing connection",
                                UDP_SOCK_READ_DEADLINE, udp_sock
                            );
                            break;
                        }
                        ClientUdpActivity::UdpError(e) => {
                            debug!(
                                "UDP connection closed on {:?}: {e}, closing connection",
                                udp_sock
                            );
                            break;
                        }
                    }
                    _ = packet_received_tx.send(());
                }
                cancellation.cancel();
                info!("Connention {:?} closed", udp_sock);
            });
        }
    }
}

#[derive(Clone)]
struct TcpConnect {
    udp_socks: Arc<Vec<Arc<UdpSocket>>>,
    encryption: Arc<Option<Encryption>>,
    packet_received_tx: broadcast::Sender<()>,
    handshake_packet: Arc<Option<Vec<u8>>>,
    cancellation: CancellationToken,
    first_packet: Option<Vec<u8>>,
    session_state: Arc<ClientSessionState>,
}

impl TcpConnect {
    async fn handle(&self, buf: &mut [u8], tcp_sock: Arc<ClientTcpSocket>) {
        let udp_socks = self.udp_socks.clone();
        let udp_count = udp_socks.len();
        let session_state = self.session_state.clone();

        run_tcp_connect_loop(
            self,
            &*tcp_sock,
            buf,
            |socket, buf, packet| Box::pin(async move { socket.socket.send(buf, packet).await }),
            |socket, buf, packet| Box::pin(async move { socket.socket.send(buf, packet).await }),
            |socket, buf| Box::pin(async move { socket.socket.recv(buf).await }),
            move |_, udp_index, payload| {
                let udp_socks = udp_socks.clone();
                Box::pin(async move {
                    udp_socks[udp_index]
                        .send(payload)
                        .await
                        .map(|_| ())
                        .map_err(|err| err.to_string())
                })
            },
            udp_count,
            move |socket, reason| close_tcp_socket(socket, &session_state, reason),
        )
        .await;
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::{
        close_tcp_socket_state, find_next_live_tcp_socket_index, run_tcp_connect_loop,
        send_on_live_tcp_socket_with_sender, wait_for_client_udp_activity, Arc, ClientSessionState,
        ClientSocketLiveness, ClientTcpSocketState, ClientUdpActivity, TcpConnect, MAX_PACKET_LEN,
    };
    use std::collections::VecDeque;
    use std::fmt;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::{Arc as StdArc, Mutex};
    use std::time::{Duration, Instant};
    use tokio::net::UdpSocket;
    use tokio::sync::broadcast;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn client_udp_wait_hits_idle_timeout_without_traffic() {
        let udp_sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let peer = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        udp_sock.connect(peer.local_addr().unwrap()).await.unwrap();

        let (packet_received_tx, _) = broadcast::channel(1);
        let mut packet_received_rx = packet_received_tx.subscribe();
        let cancellation = CancellationToken::new();
        let mut buf_udp = [0u8; 1];

        let start = Instant::now();
        let outcome = wait_for_client_udp_activity(
            &udp_sock,
            &mut buf_udp,
            &mut packet_received_rx,
            &cancellation,
            Duration::from_millis(25),
        )
        .await;
        let elapsed = start.elapsed();

        assert!(matches!(outcome, ClientUdpActivity::IdleTimeout));
        assert!(elapsed >= Duration::from_millis(25));
        assert!(elapsed < Duration::from_millis(250));
    }

    #[tokio::test]
    async fn client_udp_wait_returns_cancelled_before_timeout() {
        let udp_sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let peer = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        udp_sock.connect(peer.local_addr().unwrap()).await.unwrap();

        let (packet_received_tx, _) = broadcast::channel(1);
        let mut packet_received_rx = packet_received_tx.subscribe();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let mut buf_udp = [0u8; 1];

        let outcome = wait_for_client_udp_activity(
            &udp_sock,
            &mut buf_udp,
            &mut packet_received_rx,
            &cancellation,
            Duration::from_secs(1),
        )
        .await;

        assert!(matches!(outcome, ClientUdpActivity::Cancelled));
    }

    #[tokio::test]
    async fn client_udp_wait_returns_packet_received_signal() {
        let udp_sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let peer = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        udp_sock.connect(peer.local_addr().unwrap()).await.unwrap();

        let (packet_received_tx, _) = broadcast::channel(1);
        let mut packet_received_rx = packet_received_tx.subscribe();
        let cancellation = CancellationToken::new();
        let mut buf_udp = [0u8; 1];

        packet_received_tx.send(()).unwrap();
        let outcome = wait_for_client_udp_activity(
            &udp_sock,
            &mut buf_udp,
            &mut packet_received_rx,
            &cancellation,
            Duration::from_secs(1),
        )
        .await;

        assert!(matches!(outcome, ClientUdpActivity::PacketReceived));
    }

    #[tokio::test]
    async fn client_udp_wait_returns_received_data() {
        let udp_sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let peer = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        udp_sock.connect(peer.local_addr().unwrap()).await.unwrap();
        peer.connect(udp_sock.local_addr().unwrap()).await.unwrap();

        let (packet_received_tx, _) = broadcast::channel(1);
        let mut packet_received_rx = packet_received_tx.subscribe();
        let cancellation = CancellationToken::new();
        let mut buf_udp = [0u8; 8];

        peer.send(&[1, 2, 3]).await.unwrap();
        let outcome = wait_for_client_udp_activity(
            &udp_sock,
            &mut buf_udp,
            &mut packet_received_rx,
            &cancellation,
            Duration::from_secs(1),
        )
        .await;

        match outcome {
            ClientUdpActivity::Received(size) => {
                assert_eq!(size, 3);
                assert_eq!(&buf_udp[..size], &[1, 2, 3]);
            }
            _ => panic!("expected received UDP payload"),
        }
    }

    #[tokio::test]
    async fn client_udp_wait_prioritizes_cancellation_over_packet_signal() {
        let udp_sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let peer = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        udp_sock.connect(peer.local_addr().unwrap()).await.unwrap();

        let (packet_received_tx, _) = broadcast::channel(1);
        let mut packet_received_rx = packet_received_tx.subscribe();
        let cancellation = CancellationToken::new();
        let mut buf_udp = [0u8; 1];

        packet_received_tx.send(()).unwrap();
        cancellation.cancel();

        let outcome = wait_for_client_udp_activity(
            &udp_sock,
            &mut buf_udp,
            &mut packet_received_rx,
            &cancellation,
            Duration::from_secs(1),
        )
        .await;

        assert!(matches!(outcome, ClientUdpActivity::Cancelled));
    }

    #[test]
    fn close_tcp_socket_state_only_decrements_once() {
        let session_state = ClientSessionState::new(2);
        let tcp_sock_state = ClientTcpSocketState::new();

        assert_eq!(
            close_tcp_socket_state(&tcp_sock_state, &session_state),
            (1, true)
        );
        assert_eq!(
            close_tcp_socket_state(&tcp_sock_state, &session_state),
            (1, false)
        );
        assert_eq!(session_state.live_tcp_sockets(), 1);
    }

    #[test]
    fn find_next_live_tcp_socket_index_wraps_and_skips_dead_sockets() {
        let session_state = ClientSessionState::new(3);
        let tcp_socks = vec![
            ClientTcpSocketState::new(),
            ClientTcpSocketState::new(),
            ClientTcpSocketState::new(),
        ];

        assert_eq!(
            find_next_live_tcp_socket_index(&tcp_socks, &session_state),
            Some(0)
        );
        assert_eq!(
            find_next_live_tcp_socket_index(&tcp_socks, &session_state),
            Some(1)
        );

        close_tcp_socket_state(&tcp_socks[2], &session_state);
        assert_eq!(
            find_next_live_tcp_socket_index(&tcp_socks, &session_state),
            Some(0)
        );
        assert_eq!(
            find_next_live_tcp_socket_index(&tcp_socks, &session_state),
            Some(1)
        );
        assert_eq!(
            find_next_live_tcp_socket_index(&tcp_socks, &session_state),
            Some(0)
        );
    }

    #[test]
    fn find_next_live_tcp_socket_index_returns_none_when_all_closed() {
        let session_state = ClientSessionState::new(2);
        let tcp_socks = vec![ClientTcpSocketState::new(), ClientTcpSocketState::new()];

        close_tcp_socket_state(&tcp_socks[0], &session_state);
        close_tcp_socket_state(&tcp_socks[1], &session_state);

        assert_eq!(
            find_next_live_tcp_socket_index(&tcp_socks, &session_state),
            None
        );
        assert_eq!(session_state.live_tcp_sockets(), 0);
    }

    #[test]
    fn find_next_live_tcp_socket_index_wraps_after_many_reservations() {
        let session_state = ClientSessionState::new(3);
        let tcp_socks = vec![
            ClientTcpSocketState::new(),
            ClientTcpSocketState::new(),
            ClientTcpSocketState::new(),
        ];

        for _ in 0..32 {
            session_state.reserve_next_tcp_socket(tcp_socks.len());
        }

        assert_eq!(
            find_next_live_tcp_socket_index(&tcp_socks, &session_state),
            Some(2)
        );
        assert_eq!(
            find_next_live_tcp_socket_index(&tcp_socks, &session_state),
            Some(0)
        );
    }

    #[test]
    fn close_tcp_socket_state_does_not_underflow_live_count() {
        let session_state = ClientSessionState::new(0);
        let tcp_sock_state = ClientTcpSocketState::new();

        assert_eq!(
            close_tcp_socket_state(&tcp_sock_state, &session_state),
            (0, true)
        );
        assert_eq!(session_state.live_tcp_sockets(), 0);
        assert_eq!(
            close_tcp_socket_state(&tcp_sock_state, &session_state),
            (0, false)
        );
    }

    #[tokio::test]
    async fn send_on_live_succeeds_without_closing_when_first_socket_works() {
        let session_state = StdArc::new(ClientSessionState::new(2));
        let sockets: Vec<_> = vec![
            Arc::new(FakeTcpSocket::new(0, vec![Some(())])),
            Arc::new(FakeTcpSocket::new(1, vec![Some(())])),
        ];
        let mut buf = [0u8; MAX_PACKET_LEN];
        let session_state_handle = session_state.clone();

        let result = send_on_live_tcp_socket_with_sender(
            &sockets,
            &session_state,
            &mut buf,
            b"hello",
            |tcp_sock, _buf, _payload| Box::pin(async move { tcp_sock.next_send() }),
            move |tcp_sock| close_tcp_socket_state(&tcp_sock.state, &session_state_handle).0,
        )
        .await;

        assert!(result);
        assert!(sockets[0].state.is_alive());
        assert!(sockets[1].state.is_alive());
        assert_eq!(session_state.live_tcp_sockets(), 2);
    }

    struct FakeTcpSocket {
        id: usize,
        state: ClientTcpSocketState,
        send_results: Mutex<VecDeque<Option<()>>>,
    }

    impl FakeTcpSocket {
        fn new(id: usize, responses: Vec<Option<()>>) -> Self {
            Self {
                id,
                state: ClientTcpSocketState::new(),
                send_results: Mutex::new(VecDeque::from(responses)),
            }
        }

        fn next_send(&self) -> Option<()> {
            self.send_results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Some(()))
        }
    }

    impl ClientSocketLiveness for FakeTcpSocket {
        fn is_alive(&self) -> bool {
            self.state.is_alive()
        }
    }

    #[tokio::test]
    async fn send_on_live_moves_to_another_socket_after_failure() {
        let session_state = StdArc::new(ClientSessionState::new(2));
        let sockets: Vec<_> = vec![
            Arc::new(FakeTcpSocket::new(0, vec![None])),
            Arc::new(FakeTcpSocket::new(1, vec![Some(())])),
        ];
        let mut buf = [0u8; MAX_PACKET_LEN];
        let payload = b"failover test";

        let close_log = StdArc::new(Mutex::new(Vec::new()));
        let close_log_handle = close_log.clone();
        let session_state_handle = session_state.clone();

        let result = send_on_live_tcp_socket_with_sender(
            &sockets,
            &session_state,
            &mut buf,
            payload,
            |tcp_sock, _buf, _payload| Box::pin(async move { tcp_sock.next_send() }),
            move |tcp_sock| {
                let (remaining, newly_closed) =
                    close_tcp_socket_state(&tcp_sock.state, &session_state_handle);
                if newly_closed {
                    close_log_handle.lock().unwrap().push(tcp_sock.id);
                }
                remaining
            },
        )
        .await;

        assert!(result);
        assert_eq!(session_state.live_tcp_sockets(), 1);
        assert_eq!(&*close_log.lock().unwrap(), &[0]);
        assert!(!sockets[0].state.is_alive());
        assert!(sockets[1].state.is_alive());
    }

    #[tokio::test]
    async fn send_on_live_returns_false_when_every_socket_closes() {
        let session_state = StdArc::new(ClientSessionState::new(2));
        let sockets: Vec<_> = vec![
            Arc::new(FakeTcpSocket::new(0, vec![None])),
            Arc::new(FakeTcpSocket::new(1, vec![None])),
        ];
        let mut buf = [0u8; MAX_PACKET_LEN];
        let payload = b"no live sockets";
        let session_state_handle = session_state.clone();

        let result = send_on_live_tcp_socket_with_sender(
            &sockets,
            &session_state,
            &mut buf,
            payload,
            |tcp_sock, _buf, _payload| Box::pin(async move { tcp_sock.next_send() }),
            move |tcp_sock| close_tcp_socket_state(&tcp_sock.state, &session_state_handle).0,
        )
        .await;

        assert!(!result);
        assert_eq!(session_state.live_tcp_sockets(), 0);
        assert!(!sockets[0].state.is_alive());
        assert!(!sockets[1].state.is_alive());
    }

    struct FakeTcpLoopSocket {
        recv_results: Mutex<VecDeque<Option<usize>>>,
    }

    impl FakeTcpLoopSocket {
        fn new(results: Vec<Option<usize>>) -> Self {
            Self {
                recv_results: Mutex::new(VecDeque::from(results)),
            }
        }

        fn next_recv(&self) -> Option<usize> {
            self.recv_results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(None)
        }
    }

    impl fmt::Display for FakeTcpLoopSocket {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "fake-tcp-loop")
        }
    }

    #[tokio::test]
    async fn tcp_connect_cancelled_when_handshake_send_fails() {
        let session_state = Arc::new(ClientSessionState::new(1));
        let session_state_handle = session_state.clone();
        let cancellation = CancellationToken::new();
        let (packet_received_tx, _) = broadcast::channel(1);
        let tcp_connect = TcpConnect {
            udp_socks: Arc::new(Vec::new()),
            encryption: Arc::new(None),
            packet_received_tx,
            handshake_packet: Arc::new(Some(vec![0x1])),
            cancellation: cancellation.clone(),
            first_packet: None,
            session_state: session_state.clone(),
        };
        let fake_socket = FakeTcpLoopSocket::new(vec![]);
        let mut buf = [0u8; MAX_PACKET_LEN];

        run_tcp_connect_loop(
            &tcp_connect,
            &fake_socket,
            &mut buf,
            |_, _, _| Box::pin(async { None }),
            |_, _, _| Box::pin(async { Some(()) }),
            |_, _| Box::pin(async { Some(0) }),
            |_, _, _| Box::pin(async { Ok(()) }),
            1,
            move |_, _| session_state_handle.note_tcp_socket_closed(),
        )
        .await;

        assert!(tcp_connect.cancellation.is_cancelled());
        assert_eq!(session_state.live_tcp_sockets(), 0);
    }

    #[tokio::test]
    async fn tcp_connect_closes_when_first_packet_send_fails() {
        let session_state = Arc::new(ClientSessionState::new(1));
        let session_state_handle = session_state.clone();
        let cancellation = CancellationToken::new();
        let (packet_received_tx, _) = broadcast::channel(1);
        let tcp_connect = TcpConnect {
            udp_socks: Arc::new(Vec::new()),
            encryption: Arc::new(None),
            packet_received_tx,
            handshake_packet: Arc::new(Some(vec![0x2])),
            cancellation: cancellation.clone(),
            first_packet: Some(vec![0x3]),
            session_state: session_state.clone(),
        };
        let fake_socket = FakeTcpLoopSocket::new(vec![Some(1)]);
        let mut buf = [0u8; MAX_PACKET_LEN];

        run_tcp_connect_loop(
            &tcp_connect,
            &fake_socket,
            &mut buf,
            |_, _, _| Box::pin(async { Some(()) }),
            |_, _, _| Box::pin(async { None }),
            |socket, _| Box::pin(async move { socket.next_recv() }),
            |_, _, _| Box::pin(async { Ok(()) }),
            1,
            move |_, _| session_state_handle.note_tcp_socket_closed(),
        )
        .await;

        assert!(tcp_connect.cancellation.is_cancelled());
        assert_eq!(session_state.live_tcp_sockets(), 0);
    }

    #[tokio::test]
    async fn tcp_connect_cancels_when_forward_failure_closes_last_socket() {
        let session_state = Arc::new(ClientSessionState::new(1));
        let session_state_handle = session_state.clone();
        let cancellation = CancellationToken::new();
        let (packet_received_tx, _) = broadcast::channel(1);
        let tcp_connect = TcpConnect {
            udp_socks: Arc::new(Vec::new()),
            encryption: Arc::new(None),
            packet_received_tx,
            handshake_packet: Arc::new(None),
            cancellation: cancellation.clone(),
            first_packet: None,
            session_state: session_state.clone(),
        };
        let fake_socket = FakeTcpLoopSocket::new(vec![Some(1)]);
        let mut buf = [0u8; MAX_PACKET_LEN];

        run_tcp_connect_loop(
            &tcp_connect,
            &fake_socket,
            &mut buf,
            |_, _, _| Box::pin(async { Some(()) }),
            |_, _, _| Box::pin(async { Some(()) }),
            |socket, _| Box::pin(async move { socket.next_recv() }),
            |_, _, _| Box::pin(async { Err("udp send failed".to_string()) }),
            1,
            move |_, _| session_state_handle.note_tcp_socket_closed(),
        )
        .await;

        assert!(tcp_connect.cancellation.is_cancelled());
        assert_eq!(session_state.live_tcp_sockets(), 0);
    }
}

#[cfg(target_os = "linux")]
fn auto_rule(
    dev_name: &str,
    ipv4_only: bool,
    remote_addr: SocketAddr,
) -> Box<dyn Fn() + 'static + Send> {
    let ipv4_forward_value = std::process::Command::new("sysctl")
        .arg("net.ipv4.ip_forward")
        .output()
        .expect("sysctl net.ipv4.ip_forward could not be executed.");

    if !ipv4_forward_value.status.success() {
        panic!(
            "sysctl net.ipv4.ip_forward could not be executed successfully: {}.",
            ipv4_forward_value.status
        );
    }

    let status = std::process::Command::new("sysctl")
        .arg("-w")
        .arg("net.ipv4.ip_forward=1")
        .output()
        .expect("sysctl -w net.ipv4.ip_forward=1 could not be executed.")
        .status;

    if !status.success() {
        panic!("sysctl -w net.ipv4.ip_forward=1 could not be executed successfully: {status}.");
    }

    let ipv4_forward_value: String = String::from_utf8(ipv4_forward_value.stdout)
        .unwrap()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    // let ipv4_forward_value = OsString::from(ipv4_forward_value);
    let ipv6_forward_value: Option<String> = if !ipv4_only {
        let ipv6_forward_value = std::process::Command::new("sysctl")
            .arg("net.ipv6.conf.all.forwarding")
            .output()
            .expect("sysctl net.ipv6.conf.all.forwarding could not be executed.");

        if !ipv6_forward_value.status.success() {
            panic!(
                "sysctl net.ipv6.conf.all.forwarding could not be executed successfully: {}.",
                ipv6_forward_value.status
            );
        }

        let status = std::process::Command::new("sysctl")
            .arg("-w")
            .arg("net.ipv6.conf.all.forwarding=1")
            .output()
            .expect("sysctl -w net.ipv6.conf.all.forwarding=1 could not be executed.")
            .status;

        if !status.success() {
            panic!("sysctl -w net.ipv6.conf.all.forwarding=1 could not be executed successfully: {status}.");
        }

        Some(
            String::from_utf8(ipv6_forward_value.stdout)
                .unwrap()
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect(),
        )
    } else {
        None
    };

    let iptables_add_rule = format!(
        "-t nat -I POSTROUTING -o {dev_name} -p tcp --dport {} -j MASQUERADE",
        remote_addr.port()
    );
    let ip6tables_add_rule = format!(
        "-t nat -I POSTROUTING -o {dev_name} -p tcp --dport {} -j MASQUERADE",
        remote_addr.port()
    );

    let iptables_del_rule = format!(
        "-t nat -D POSTROUTING -o {dev_name} -p tcp --dport {} -j MASQUERADE",
        remote_addr.port()
    );
    let ip6tables_del_rule = format!(
        "-t nat -D POSTROUTING -o {dev_name} -p tcp --dport {} -j MASQUERADE",
        remote_addr.port()
    );

    let status = std::process::Command::new("iptables")
        .args(iptables_add_rule.split(' '))
        .output()
        .expect("iptables could not be executed.")
        .status;

    if !status.success() {
        panic!("{iptables_add_rule} could not be executed successfully: {status}.");
    }

    if !ipv4_only {
        let status = std::process::Command::new("ip6tables")
            .args(ip6tables_add_rule.split(' '))
            .output()
            .expect("ip6tables could not be executed.")
            .status;

        if !status.success() {
            panic!("{ip6tables_add_rule} could not be executed successfully: {status}.");
        }
    }
    Box::new(move || {
        let status = std::process::Command::new("sysctl")
            .arg("-w")
            .arg(&ipv4_forward_value)
            .output()
            .unwrap_or_else(|err| {
                panic!(
                    "sysctl -w '{:?}' could not be executed: {err}.",
                    ipv4_forward_value
                )
            })
            .status;
        if !status.success() {
            panic!(
                "sysctl -w '{:?}' could not be executed successfully: {status}.",
                ipv4_forward_value
            );
        }

        if !ipv4_only {
            let status = std::process::Command::new("sysctl")
                .arg("-w")
                .arg(ipv6_forward_value.as_ref().unwrap())
                .output()
                .unwrap_or_else(|err| {
                    panic!(
                        "sysctl -w '{:?}' could not be executed: {err}.",
                        ipv6_forward_value
                    )
                })
                .status;
            if !status.success() {
                panic!(
                    "sysctl -w '{:?}' could not be executed successfully: {status}.",
                    ipv6_forward_value
                );
            }
        }

        let status = std::process::Command::new("iptables")
            .args(iptables_del_rule.split(' '))
            .output()
            .expect("iptables could not be executed.")
            .status;

        if !status.success() {
            panic!("{iptables_del_rule} could not be executed successfully: {status}.");
        }

        info!("Respective iptables rules removed.");

        if !ipv4_only {
            let status = std::process::Command::new("ip6tables")
                .args(ip6tables_del_rule.split(' '))
                .output()
                .expect("ip6tables could not be executed.")
                .status;

            if !status.success() {
                panic!("{ip6tables_del_rule} could not be executed successfully: {status}.");
            }

            info!("Respective ip6tables rules removed.");
        }
    })
}

#[cfg(target_os = "macos")]
fn auto_rule(
    dev_name: &str,
    int_name: &str,
    peer: Ipv4Addr,
    peer6: Option<Ipv6Addr>,
) -> Box<dyn Fn() + 'static + Send> {
    use std::process::Stdio;

    use tonel::utils::{add_routes, delete_routes};

    let ipv4_forward_value = std::process::Command::new("sysctl")
        .arg("net.inet.ip.forwarding")
        .output()
        .expect("sysctl net.inet.ip.forwarding could not be executed.");

    if !ipv4_forward_value.status.success() {
        panic!(
            "sysctl net.inet.ip.forwarding could not be executed successfully: {}.",
            ipv4_forward_value.status
        );
    }

    let status = std::process::Command::new("sysctl")
        .arg("net.inet.ip.forwarding=1")
        .output()
        .expect("sysctl net.inet.ip.forwarding=1 could not be executed.")
        .status;

    if !status.success() {
        panic!("sysctl net.inet.ip.forwarding=1 could not be executed successfully: {status}.");
    }

    let ipv4_forward_value: String = String::from_utf8(ipv4_forward_value.stdout)
        .unwrap()
        .replace(": ", "=")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    // let ipv4_forward_value = OsString::from(ipv4_forward_value);
    let ipv6_forward_value: Option<String> = if peer6.is_some() {
        let ipv6_forward_value = std::process::Command::new("sysctl")
            .arg("net.inet6.ip6.forwarding")
            .output()
            .expect("sysctl net.inet6.ip6.forwarding could not be executed.");

        if !ipv6_forward_value.status.success() {
            panic!(
                "sysctl net.inet6.ip6.forwarding could not be executed successfully: {}.",
                ipv6_forward_value.status
            );
        }

        let status = std::process::Command::new("sysctl")
            .arg("-w")
            .arg("net.inet6.ip6.forwarding=1")
            .output()
            .expect("sysctl -w net.inet6.ip6.forwarding=1 could not be executed.")
            .status;

        if !status.success() {
            panic!(
                "sysctl net.inet6.ip6.forwarding=1 could not be executed successfully: {status}."
            );
        }

        Some(
            String::from_utf8(ipv6_forward_value.stdout)
                .unwrap()
                .replace(": ", "=")
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect(),
        )
    } else {
        None
    };

    let mut pfctl = std::process::Command::new("pfctl")
        .arg("-e")
        .arg("-a")
        .arg("com.apple/tonel")
        .arg("-f")
        .arg("-")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::piped())
        .spawn()
        .expect("Failed to spawn pfctl process.");

    let mut nat_rules = format!("nat on {int_name} from {peer}/24 to any -> ({int_name})\n");
    if let Some(peer6) = peer6 {
        nat_rules += format!("nat on {int_name} from {peer6}/64 to any -> ({int_name})\n").as_str();
    }
    pfctl
        .stdin
        .take()
        .expect("Failed to open stdin for pfctl command.")
        .write_all(nat_rules.as_bytes())
        .expect("Failed to write pfctl rules");

    pfctl.wait().expect("Failed to add pfctl rules.");

    add_routes(dev_name, peer, peer6);

    Box::new(move || {
        let status = std::process::Command::new("sysctl")
            .arg(&ipv4_forward_value)
            .output()
            .unwrap_or_else(|err| {
                panic!(
                    "sysctl '{:?}' could not be executed: {err}.",
                    ipv4_forward_value
                )
            })
            .status;
        if !status.success() {
            panic!(
                "sysctl '{:?}' could not be executed successfully: {status}.",
                ipv4_forward_value
            );
        }

        let _ = std::process::Command::new("pfctl")
            .arg("-a")
            .arg("com.apple/tonel")
            .arg("-f")
            .arg("-")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .status();

        if peer6.is_some() {
            let status = std::process::Command::new("sysctl")
                .arg(ipv6_forward_value.as_ref().unwrap())
                .output()
                .unwrap_or_else(|err| {
                    panic!(
                        "sysctl '{:?}' could not be executed: {err}.",
                        ipv6_forward_value
                    )
                })
                .status;
            if !status.success() {
                panic!(
                    "sysctl '{:?}' could not be executed successfully: {status}.",
                    ipv6_forward_value
                );
            }

            delete_routes(peer, peer6);
        }
    })
}
