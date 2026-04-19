use cfg_if::cfg_if;
use clap::ArgMatches;
use clap::{crate_version, Arg, ArgAction, Command};
use log::{debug, error, info};
use std::collections::HashMap;
use std::fs;
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
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use tonel::tcp::packet::MAX_PACKET_LEN;
use tonel::tcp::Stack;
use tonel::utils::{assign_ipv6_address, new_udp_reuseport};
use tonel::Encryption;
use tun::Device;

fn parse_udp_connections(value: &str) -> Result<usize, &'static str> {
    let amount = value
        .parse::<usize>()
        .map_err(|_| "Unspecified number of UDP connections per each client")?;
    if amount == 0 {
        Err("UDP connections should be greater than or equal to 1")
    } else {
        Ok(amount)
    }
}

fn format_linux_nat_rule(
    dev_name: &str,
    local_port: u16,
    destination: &str,
    insert: bool,
) -> String {
    let action = if insert {
        "-t nat -I PREROUTING"
    } else {
        "-t nat -D PREROUTING"
    };
    format!(
        "{action} -p tcp -i {dev_name} --dport {local_port} -j DNAT --to-destination {destination}"
    )
}

#[cfg(any(test, target_os = "linux"))]
fn format_linux_forward_rule(
    input_if: &str,
    output_if: &str,
    insert: bool,
) -> String {
    let action = if insert { "-I FORWARD" } else { "-D FORWARD" };
    format!("{action} -i {input_if} -o {output_if} -j ACCEPT")
}

#[cfg(any(test, target_os = "linux"))]
const LINUX_TCP_MSS_CLAMP: usize = 1280;

#[cfg(any(test, target_os = "linux"))]
fn format_linux_mss_clamp_rule(input_if: &str, output_if: &str, insert: bool) -> String {
    let action = if insert {
        "-t mangle -I FORWARD"
    } else {
        "-t mangle -D FORWARD"
    };
    format!(
        "{action} -i {input_if} -o {output_if} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss {LINUX_TCP_MSS_CLAMP}"
    )
}

#[cfg(any(test, target_os = "linux"))]
fn build_netfilter_install_commands(manager: &str) -> Option<Vec<Vec<&'static str>>> {
    match manager {
        "apt-get" => Some(vec![
            vec!["apt-get", "update"],
            vec!["apt-get", "install", "-y", "iptables"],
        ]),
        "dnf" => Some(vec![vec!["dnf", "install", "-y", "iptables"]]),
        "yum" => Some(vec![vec!["yum", "install", "-y", "iptables"]]),
        "apk" => Some(vec![vec!["apk", "add", "--no-cache", "iptables"]]),
        "pacman" => Some(vec![vec![
            "pacman",
            "-Sy",
            "--noconfirm",
            "--needed",
            "iptables",
        ]]),
        "zypper" => Some(vec![vec![
            "zypper",
            "--non-interactive",
            "install",
            "iptables",
        ]]),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn command_exists(name: &str) -> bool {
    let path_iter = std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>());
    path_iter
        .chain(
            ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"]
                .iter()
                .map(std::path::PathBuf::from),
        )
        .any(|dir| dir.join(name).exists())
}

#[cfg(target_os = "linux")]
fn ensure_linux_netfilter_tools(ipv6: bool) {
    if command_exists("iptables") && (!ipv6 || command_exists("ip6tables")) {
        return;
    }

    info!("iptables tooling not found, attempting automatic installation.");
    let package_manager = ["apt-get", "dnf", "yum", "apk", "pacman", "zypper"]
        .into_iter()
        .find(|manager| command_exists(manager))
        .unwrap_or_else(|| {
            panic!(
                "iptables/ip6tables is not installed and no supported package manager was found."
            )
        });

    for command in build_netfilter_install_commands(package_manager).unwrap() {
        let status = std::process::Command::new(command[0])
            .args(&command[1..])
            .status()
            .unwrap_or_else(|err| {
                panic!(
                    "Unable to execute automatic netfilter install command {:?}: {err}.",
                    command
                )
            });
        if !status.success() {
            panic!(
                "Automatic netfilter install command {:?} failed with status {status}.",
                command
            );
        }
    }

    if !command_exists("iptables") || (ipv6 && !command_exists("ip6tables")) {
        panic!("iptables tooling is still unavailable after automatic installation.");
    }
}

#[cfg(any(test, target_os = "macos"))]
fn build_pfctl_nat_rules(
    int_name: &str,
    local_port: u16,
    peer: Ipv4Addr,
    peer6: Option<Ipv6Addr>,
) -> String {
    let mut rules =
        format!("rdr on {int_name} inet proto tcp from any to any port {local_port} -> {peer}\n");
    if let Some(peer6) = peer6 {
        rules.push_str(&format!(
            "rdr on {int_name} inet6 proto tcp from any to any port {local_port} -> {peer6}\n"
        ));
    }
    rules
}

struct ServerTcpSocket {
    addr: SocketAddr,
    socket: Arc<tonel::tcp::Socket>,
    alive: AtomicBool,
    has_payload_activity: AtomicBool,
}

impl ServerTcpSocket {
    fn new(socket: tonel::tcp::Socket) -> Self {
        let addr = socket.remote_addr();
        Self {
            addr,
            socket: Arc::new(socket),
            alive: AtomicBool::new(true),
            has_payload_activity: AtomicBool::new(false),
        }
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    fn mark_dead(&self) -> bool {
        self.alive.swap(false, Ordering::AcqRel)
    }

    fn note_payload_activity(&self) {
        self.has_payload_activity.store(true, Ordering::Release);
    }

    fn has_payload_activity(&self) -> bool {
        self.has_payload_activity.load(Ordering::Acquire)
    }
}

struct ServerFlowState {
    flow_key: SocketAddr,
    udp_socks: Arc<Vec<Arc<UdpSocket>>>,
    connections: Mutex<HashMap<SocketAddr, Arc<ServerTcpSocket>>>,
    next_udp_sock_index: AtomicUsize,
    next_tcp_socket_index: AtomicUsize,
    encryption: Arc<Option<Encryption>>,
    cancellation: CancellationToken,
}

impl ServerFlowState {
    fn new(
        flow_key: SocketAddr,
        udp_socks: Arc<Vec<Arc<UdpSocket>>>,
        encryption: Arc<Option<Encryption>>,
    ) -> Self {
        Self {
            flow_key,
            udp_socks,
            connections: Mutex::new(HashMap::new()),
            next_udp_sock_index: AtomicUsize::new(0),
            next_tcp_socket_index: AtomicUsize::new(0),
            encryption,
            cancellation: CancellationToken::new(),
        }
    }

    fn add_connection(&self, conn: Arc<ServerTcpSocket>) {
        if let Ok(mut connections) = self.connections.lock() {
            connections.insert(conn.addr, conn.clone());
        }
    }

    fn mark_connection_dead(&self, addr: SocketAddr, reason: &str) -> usize {
        let newly_closed = if let Ok(connections) = self.connections.lock() {
            connections
                .get(&addr)
                .map(|conn| conn.mark_dead())
                .unwrap_or(false)
        } else {
            false
        };

        if newly_closed {
            info!(
                "TCP sub-connection {} closed for flow {}: {}",
                addr, self.flow_key, reason
            );
        }

        let remaining = if let Ok(mut connections) = self.connections.lock() {
            connections.retain(|_, conn| conn.is_alive());
            connections.len()
        } else {
            0
        };

        if remaining == 0 {
            self.cancellation.cancel();
        }

        remaining
    }

    async fn forward_tcp_payload_to_udp(&self, addr: SocketAddr, payload: &[u8]) -> Result<(), String> {
        if let Ok(connections) = self.connections.lock() {
            if let Some(conn) = connections.get(&addr) {
                conn.note_payload_activity();
            }
        }
        let index = self.next_udp_sock_index.fetch_add(1, Ordering::Relaxed) % self.udp_socks.len();
        debug!(
            "Forwarding {} bytes from TCP flow {} on conn {} to UDP backend socket {}",
            payload.len(),
            self.flow_key,
            addr,
            index
        );
        self.udp_socks[index]
            .send(payload)
            .await
            .map(|_| ())
            .map_err(|err| err.to_string())
    }

    fn select_concurrent_connection(&self) -> Option<Arc<ServerTcpSocket>> {
        let connections = self.connections.lock().ok()?;
        let mut live: Vec<_> = connections
            .values()
            .filter(|conn| conn.is_alive() && conn.has_payload_activity())
            .cloned()
            .collect();
        if live.is_empty() {
            live = connections
                .values()
                .filter(|conn| conn.is_alive())
                .cloned()
                .collect();
        }
        drop(connections);
        if live.is_empty() {
            return None;
        }
        live.sort_by_key(|conn| conn.addr);
        let index = self
            .next_tcp_socket_index
            .fetch_add(1, Ordering::Relaxed)
            % live.len();
        Some(live[index].clone())
    }

    async fn forward_udp_payload_to_tcp(&self, payload: &[u8]) -> io::Result<()> {
        loop {
            let conn = self.select_concurrent_connection().ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotConnected, "no active tcp connection for flow")
            })?;
            let mut buf = [0u8; MAX_PACKET_LEN];
            let sent = if let Some(enc) = self.encryption.as_ref() {
                let mut encrypted = payload.to_vec();
                enc.encrypt(&mut encrypted);
                conn.socket.send(&mut buf, &encrypted).await.is_some()
            } else {
                conn.socket.send(&mut buf, payload).await.is_some()
            };
            if sent {
                debug!(
                    "Forwarded {} bytes from UDP backend for flow {} onto TCP conn {}",
                    payload.len(),
                    self.flow_key,
                    conn.addr
                );
                return Ok(());
            }

            if self.mark_connection_dead(conn.addr, "send failure while forwarding UDP payload")
                == 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "no live tcp connection remains for flow",
                ));
            }
        }
    }
}

async fn create_remote_udp_socks(
    remote_addr: SocketAddr,
    count: usize,
) -> io::Result<Arc<Vec<Arc<UdpSocket>>>> {
    let udp_sock = UdpSocket::bind(if remote_addr.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    })
    .await?;
    let local_addr = udp_sock.local_addr()?;
    drop(udp_sock);

    let mut socks = Vec::with_capacity(count.max(1));
    for _ in 0..count.max(1) {
        let udp_sock = new_udp_reuseport(local_addr)?;
        udp_sock.connect(remote_addr).await?;
        socks.push(Arc::new(udp_sock));
    }
    Ok(Arc::new(socks))
}

async fn run_server_udp_reader(
    flow: Arc<ServerFlowState>,
    udp_sock: Arc<UdpSocket>,
    flow_remove_tx: kanal::AsyncSender<SocketAddr>,
) {
    let mut buf_udp = [0u8; MAX_PACKET_LEN];
    loop {
        tokio::select! {
            biased;
            _ = flow.cancellation.cancelled() => break,
            res = udp_sock.recv(&mut buf_udp) => {
                let size = match res {
                    Ok(size) => size,
                    Err(err) => {
                        debug!("UDP connection error on {}: {err}", udp_sock.local_addr().unwrap());
                        flow.cancellation.cancel();
                        let _ = flow_remove_tx.send(flow.flow_key).await;
                        break;
                    }
                };
                if let Err(err) = flow.forward_udp_payload_to_tcp(&buf_udp[..size]).await {
                    debug!("Unable to send TCP packet for flow {}: {err}", flow.flow_key);
                    if flow.cancellation.is_cancelled() {
                        break;
                    }
                }
            }
        }
    }
}

async fn run_server_tcp_loop(
    flow: Arc<ServerFlowState>,
    tcp_sock: Arc<ServerTcpSocket>,
    handshake_packet: Arc<Option<Vec<u8>>>,
    flow_remove_tx: kanal::AsyncSender<SocketAddr>,
) {
    let mut buf_tcp = [0u8; MAX_PACKET_LEN];
    let mut should_receive_handshake_packet = handshake_packet.is_some();

    loop {
        tokio::select! {
            biased;
            _ = flow.cancellation.cancelled() => break,
            res = tcp_sock.socket.recv(&mut buf_tcp) => {
                match res {
                    Some(size) => {
                        if should_receive_handshake_packet {
                            should_receive_handshake_packet = false;
                            if let Some(ref p) = *handshake_packet {
                                let mut buf = [0u8; MAX_PACKET_LEN];
                                if tcp_sock.socket.send(&mut buf, p).await.is_none() {
                                    error!("Failed to send handshake packet to remote, closing connection.");
                                    break;
                                }
                                debug!("Sent handshake packet to: {}", tcp_sock.socket);
                            }
                            continue;
                        }
                        if let Some(ref enc) = *flow.encryption {
                            enc.decrypt(&mut buf_tcp[..size]);
                        }
                        if let Err(err) = flow.forward_tcp_payload_to_udp(tcp_sock.addr, &buf_tcp[..size]).await {
                            debug!("Unable to send UDP packet to remote destination for flow {}: {err}", flow.flow_key);
                            break;
                        }
                    },
                    None => break,
                }
            }
        }
    }

    if flow.mark_connection_dead(tcp_sock.addr, "recv returned EOF or forwarding failed") == 0 {
        let _ = flow_remove_tx.send(flow.flow_key).await;
    }
}

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
    let matches = Command::new("Tonel Server")
        .version(crate_version!())
        .author("Saber Haj Rabiee")
        .arg(
            Arg::new("local")
                .short('l')
                .long("local")
                .required(true)
                .value_name("PORT")
                .help("Sets the port where Tonel Server listens for incoming Tonel Client TCP connections")
        )
        .arg(
            Arg::new("remote")
                .short('r')
                .long("remote")
                .required(true)
                .value_name("IP or HOST NAME:PORT")
                .help("Sets the address or host name and port where Tonel Server forwards UDP packets to, \n\
                    IPv6 address need to be specified as: \"[IPv6]:PORT\"")
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
            )
        )
        .arg(
            Arg::new("tun_local")
                .long("tun-local")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface local address (O/S's end)")
                .default_value("192.168.201.1")
        )
        .arg(
            Arg::new("tun_peer")
                .long("tun-peer")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface destination (peer) address (Tonel Server's end). \n\
                       You will need to setup DNAT rules to this address in order for Tonel Server \n\
                       to accept TCP traffic from Tonel Client")
                .default_value("192.168.201.2")
        )
        .arg(
            Arg::new("ipv4_only")
                .long("ipv4-only")
                .short('4')
                .required(false)
                .help("Do not assign IPv6 addresses to Tun interface")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["tun_local6", "tun_peer6"]),
        )
        .arg(
            Arg::new("tun_local6")
                .long("tun-local6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 local address (O/S's end)")
                .default_value("fcc9::1")
        )
        .arg(
            Arg::new("tun_peer6")
                .long("tun-peer6")
                .required(false)
                .value_name("IP")
                .help("Sets the Tun interface IPv6 destination (peer) address (Tonel Client's end). \n\
                       You will need to setup SNAT/MASQUERADE rules on your Internet facing interface \n\
                       in order for Tonel Client to connect to Tonel Server")
                .default_value("fcc9::2")
        )
        .arg(
            Arg::new("handshake_packet")
                .long("handshake-packet")
                .required(false)
                .value_name("PATH")
                .help("Specify a file, which, after TCP handshake, its content will be sent as the \n\
                      first data packet to the client.\n\
                      Note: ensure this file's size does not exceed the MTU of the outgoing interface. \n\
                      The content is always sent out in a single packet and will not be further segmented")
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
                .required(false)
                .help("Log output path.")
        )
        .arg(
            Arg::new("log_level")
                .long("log-level")
                .required(false)
                .default_value("info")
                .help("Log output level. It could be one of the following:\n\
                    off, error, warn, info, debug, trace.")
        )
        .arg(
            Arg::new("deadline")
                .long("deadline")
                .required(false)
                .value_name("deadline")
                .help("An open connection will be closed focibly after provided seconds. Default is disabled.")
        )
        .get_matches();

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

async fn main_async(matches: ArgMatches) -> io::Result<()> {
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

    let local_port: u16 = matches
        .get_one::<String>("local")
        .unwrap()
        .parse()
        .expect("bad local port");

    let ipv4_only = matches.get_flag("ipv4_only");

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

    let remote_addr = tokio::net::lookup_host(matches.get_one::<String>("remote").unwrap())
        .await
        .expect("bad remote address or host")
        .next()
        .expect("unable to resolve remote host name");

    info!("Remote address is: {}", remote_addr);

    let udp_socks_amount =
        parse_udp_connections(matches.get_one::<String>("udp_connections").unwrap()).unwrap();

    let encryption = matches
        .get_one::<String>("encryption")
        .map(Encryption::from);
    debug!("Encryption in use: {:?}", encryption);
    let encryption = Arc::new(encryption);

    let handshake_packet: Option<Vec<u8>> = matches
        .get_one::<String>("handshake_packet")
        .map(fs::read)
        .transpose()?;
    let handshake_packet = Arc::new(handshake_packet);

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

    info!("Created TUN device {}", tun.name());

    let exit_fn: Box<dyn Fn() + 'static + Send> = if let Some(dev_name) =
        matches.get_one::<String>("auto_rule")
    {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                auto_rule(
                    tun.name(),
                    dev_name,
                    tun_peer,
                    tun_peer6,
                    local_port,
                )
            } else if
                #[cfg(target_os = "macos")] {
                auto_rule(
                    tun.name(),
                    dev_name,
                    tun_peer,
                    tun_peer6,
                    local_port,
                )
            }
        }
    } else {
        info!(
            "Make sure ip forwarding is enabled, run the following commands: \n\
            sysctl -w net.ipv4.ip_forward=1 \n\
            sysctl -w net.ipv6.conf.all.forwarding=1"
        );

        if ipv4_only {
            info!(
            "Make sure your firewall routes packets, replace the dev_name with \n\
            your active network interface (like eth0) and run the following commands for iptables: \n\
            iptables -t nat -I PREROUTING -p tcp -i dev_name --dport {} -j DNAT --to-destination {}",
            local_port,
            tun_peer,
        );
        } else {
            info!(
                "Make sure your firewall routes packets, replace the dev_name with \n\
                your active network interface (like eth0) and run the following commands for iptables: \n\
                iptables -t nat -I PREROUTING -p tcp -i dev_name --dport {} -j DNAT --to-destination {}\n\
                ip6tables -t nat -I PREROUTING -p tcp -i dev_name --dport {} -j DNAT --to-destination {}",
                local_port,
                tun_peer,
                local_port,
                tun_peer6.unwrap(),
            );
        }

        Box::new(|| {})
    };

    ctrlc::set_handler(move || {
        exit_fn();
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    let deadline = matches
        .get_one::<String>("deadline")
        .map(|f| f.parse::<u64>().unwrap());

    let mut stack = Stack::new(tun, tun_local, tun_local6, deadline);
    stack.listen(local_port);
    info!("Listening on {}", local_port);

    let mut flows: HashMap<SocketAddr, Arc<ServerFlowState>> = HashMap::new();
    let (flow_remove_tx, flow_remove_rx) = kanal::bounded_async::<SocketAddr>(128);

    loop {
        let (tcp_sock, first_port) = tokio::select! {
            biased;
            flow_key = flow_remove_rx.recv() => {
                match flow_key {
                    Ok(flow_key) => {
                        flows.remove(&flow_key);
                        continue;
                    }
                    Err(err) => {
                        error!("flow_remove_rx recv error: {err}");
                        continue;
                    }
                }
            },
            accepted = stack.accept() => accepted,
        };

        let flow_key = if first_port == 0 {
            tcp_sock.remote_addr()
        } else {
            SocketAddr::new(tcp_sock.remote_addr().ip(), first_port)
        };
        let flow = if let Some(flow) = flows.get(&flow_key) {
            flow.clone()
        } else {
            if first_port != 0 {
                error!("The request pool key {flow_key} does not exist.");
                continue;
            }

            let udp_socks = match create_remote_udp_socks(remote_addr, udp_socks_amount).await {
                Ok(udp_socks) => udp_socks,
                Err(err) => {
                    error!("Unable to create udp socket pool for flow {flow_key}: {err}");
                    continue;
                }
            };
            let flow = Arc::new(ServerFlowState::new(
                flow_key,
                udp_socks.clone(),
                encryption.clone(),
            ));
            for udp_sock in udp_socks.iter() {
                let flow = flow.clone();
                let udp_sock = udp_sock.clone();
                let flow_remove_tx = flow_remove_tx.clone();
                tokio::spawn(async move {
                    run_server_udp_reader(flow, udp_sock, flow_remove_tx).await;
                });
            }
            flows.insert(flow_key, flow.clone());
            flow
        };

        let tcp_sock = Arc::new(ServerTcpSocket::new(tcp_sock));
        info!(
            "New connection {} joined flow {}",
            tcp_sock.socket, flow_key
        );
        flow.add_connection(tcp_sock.clone());

        let flow_remove_tx = flow_remove_tx.clone();
        let handshake_packet = handshake_packet.clone();
        tokio::spawn(async move {
            run_server_tcp_loop(flow, tcp_sock, handshake_packet, flow_remove_tx).await;
        });
    }
}
#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    #[test]
    fn parse_udp_connections_accepts_positive_values() {
        assert_eq!(parse_udp_connections("3").unwrap(), 3);
    }

    #[test]
    fn parse_udp_connections_rejects_zero_and_errors() {
        assert_eq!(
            parse_udp_connections("0").unwrap_err(),
            "UDP connections should be greater than or equal to 1"
        );
    }

    #[test]
    fn parse_udp_connections_reports_parse_errors() {
        assert_eq!(
            parse_udp_connections("abc").unwrap_err(),
            "Unspecified number of UDP connections per each client"
        );
    }

    #[test]
    fn format_linux_nat_rule_switches_action_and_destination() {
        let insert_rule = format_linux_nat_rule("eth0", 2222, "192.168.0.1", true);
        let delete_rule = format_linux_nat_rule("eth0", 2222, "192.168.0.1", false);
        assert!(insert_rule.contains("-I PREROUTING"));
        assert!(delete_rule.contains("-D PREROUTING"));
        assert!(insert_rule.contains("DNAT --to-destination 192.168.0.1"));
    }

    #[test]
    fn format_linux_forward_rule_switches_direction_and_action() {
        let insert_rule = format_linux_forward_rule("eth0", "tun0", true);
        let delete_rule = format_linux_forward_rule("eth0", "tun0", false);
        assert!(insert_rule.contains("-I FORWARD"));
        assert!(delete_rule.contains("-D FORWARD"));
        assert!(insert_rule.contains("-i eth0"));
        assert!(insert_rule.contains("-o tun0"));
    }

    #[test]
    fn format_linux_mss_clamp_rule_switches_direction_action_and_value() {
        let insert_rule = format_linux_mss_clamp_rule("eth0", "tun0", true);
        let delete_rule = format_linux_mss_clamp_rule("eth0", "tun0", false);
        assert!(insert_rule.contains("-t mangle -I FORWARD"));
        assert!(delete_rule.contains("-t mangle -D FORWARD"));
        assert!(insert_rule.contains("--tcp-flags SYN,RST SYN"));
        assert!(insert_rule.contains("--set-mss 1280"));
        assert!(insert_rule.contains("-i eth0"));
        assert!(insert_rule.contains("-o tun0"));
    }

    #[test]
    fn build_netfilter_install_commands_supports_known_package_managers() {
        assert_eq!(
            build_netfilter_install_commands("apt-get").unwrap(),
            vec![
                vec!["apt-get", "update"],
                vec!["apt-get", "install", "-y", "iptables"]
            ]
        );
        assert_eq!(
            build_netfilter_install_commands("apk").unwrap(),
            vec![vec!["apk", "add", "--no-cache", "iptables"]]
        );
        assert!(build_netfilter_install_commands("unknown").is_none());
    }

    #[test]
    fn build_pfctl_nat_rules_includes_ipv6_when_requested() {
        let rules = build_pfctl_nat_rules(
            "en1",
            2222,
            Ipv4Addr::new(10, 0, 0, 1),
            Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        );
        assert!(rules.contains("inet proto tcp"));
        assert!(rules.contains("inet6 proto tcp"));
    }
}

#[cfg(target_os = "linux")]
fn auto_rule(
    tun_name: &str,
    dev_name: &str,
    peer: Ipv4Addr,
    peer6: Option<Ipv6Addr>,
    local_port: u16,
) -> Box<dyn Fn() + 'static + Send> {
    ensure_linux_netfilter_tools(peer6.is_some());

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
    let ipv6_forward_value: Option<String> = if peer6.is_some() {
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

    let iptables_add_rule = format_linux_nat_rule(dev_name, local_port, &peer.to_string(), true);
    let iptables_del_rule = format_linux_nat_rule(dev_name, local_port, &peer.to_string(), false);
    let iptables_add_forward_in_rule = format_linux_forward_rule(dev_name, tun_name, true);
    let iptables_add_forward_out_rule = format_linux_forward_rule(tun_name, dev_name, true);
    let iptables_del_forward_in_rule = format_linux_forward_rule(dev_name, tun_name, false);
    let iptables_del_forward_out_rule = format_linux_forward_rule(tun_name, dev_name, false);
    let iptables_add_mss_in_rule = format_linux_mss_clamp_rule(dev_name, tun_name, true);
    let iptables_add_mss_out_rule = format_linux_mss_clamp_rule(tun_name, dev_name, true);
    let iptables_del_mss_in_rule = format_linux_mss_clamp_rule(dev_name, tun_name, false);
    let iptables_del_mss_out_rule = format_linux_mss_clamp_rule(tun_name, dev_name, false);
    let ip6_peer_string = peer6.as_ref().map(|peer6| peer6.to_string());
    let ip6tables_add_rule = ip6_peer_string
        .as_deref()
        .map(|destination| format_linux_nat_rule(dev_name, local_port, destination, true));
    let ip6tables_del_rule = ip6_peer_string
        .as_deref()
        .map(|destination| format_linux_nat_rule(dev_name, local_port, destination, false));
    let ip6tables_add_forward_in_rule = format_linux_forward_rule(dev_name, tun_name, true);
    let ip6tables_add_forward_out_rule = format_linux_forward_rule(tun_name, dev_name, true);
    let ip6tables_del_forward_in_rule = format_linux_forward_rule(dev_name, tun_name, false);
    let ip6tables_del_forward_out_rule = format_linux_forward_rule(tun_name, dev_name, false);
    let ip6tables_add_mss_in_rule = format_linux_mss_clamp_rule(dev_name, tun_name, true);
    let ip6tables_add_mss_out_rule = format_linux_mss_clamp_rule(tun_name, dev_name, true);
    let ip6tables_del_mss_in_rule = format_linux_mss_clamp_rule(dev_name, tun_name, false);
    let ip6tables_del_mss_out_rule = format_linux_mss_clamp_rule(tun_name, dev_name, false);

    for rule in [
        iptables_add_rule.as_str(),
        iptables_add_forward_in_rule.as_str(),
        iptables_add_forward_out_rule.as_str(),
        iptables_add_mss_in_rule.as_str(),
        iptables_add_mss_out_rule.as_str(),
    ] {
        let status = std::process::Command::new("iptables")
            .args(rule.split(' '))
            .output()
            .expect("iptables could not be executed.")
            .status;

        if !status.success() {
            panic!("{rule} could not be executed successfully: {status}.");
        }
    }

    if let Some(rule) = &ip6tables_add_rule {
        for ip6rule in [
            rule.as_str(),
            ip6tables_add_forward_in_rule.as_str(),
            ip6tables_add_forward_out_rule.as_str(),
            ip6tables_add_mss_in_rule.as_str(),
            ip6tables_add_mss_out_rule.as_str(),
        ] {
            let status = std::process::Command::new("ip6tables")
                .args(ip6rule.split(' '))
                .output()
                .expect("ip6tables could not be executed.")
                .status;

            if !status.success() {
                panic!("{ip6rule} could not be executed successfully: {status}.");
            }
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

        if peer6.is_some() {
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

        for rule in [
            iptables_del_rule.as_str(),
            iptables_del_forward_in_rule.as_str(),
            iptables_del_forward_out_rule.as_str(),
            iptables_del_mss_in_rule.as_str(),
            iptables_del_mss_out_rule.as_str(),
        ] {
            let status = std::process::Command::new("iptables")
                .args(rule.split(' '))
                .output()
                .expect("iptables could not be executed.")
                .status;

            if !status.success() {
                panic!("{rule} could not be executed successfully: {status}.");
            }
        }

        info!("Respective iptables rules removed.");

        if let Some(rule) = ip6tables_del_rule.as_ref() {
            for ip6rule in [
                rule.as_str(),
                ip6tables_del_forward_in_rule.as_str(),
                ip6tables_del_forward_out_rule.as_str(),
                ip6tables_del_mss_in_rule.as_str(),
                ip6tables_del_mss_out_rule.as_str(),
            ] {
                let status = std::process::Command::new("ip6tables")
                    .args(ip6rule.split(' '))
                    .output()
                    .expect("ip6tables could not be executed.")
                    .status;

                if !status.success() {
                    panic!("{ip6rule} could not be executed successfully: {status}.");
                }
            }
        }

        if peer6.is_some() {
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
    local_port: u16,
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

    let nat_rules = build_pfctl_nat_rules(int_name, local_port, peer, peer6);
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
