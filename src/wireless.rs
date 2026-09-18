use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV6};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use idevice::remote_pairing::{
    PAIRABLE_HOST_SERVICE_TYPE, PairableHost, PairableHostInfo, PeerDevice,
    RemotePairingClient, RpPairingFile, RpPairingSocket, connect_tls_psk_tunnel_native,
};
use idevice::tcp::adapter::Adapter;
use idevice::tcp::handle::AdapterHandle;
use idevice::{IdeviceService, RsdService};
use mdns_sd::{ResolvedService, ScopedIp, ServiceDaemon, ServiceEvent, ServiceInfo};
use tokio::net::TcpListener;
use tokio::time::{timeout, Instant};

const MODEL: &str = "Mac17,7";
const REMOTE_PAIRING_SERVICE: &str = "_remotepairing._tcp.local.";
const BROWSE_TIMEOUT: Duration = Duration::from_secs(6);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);

#[derive(Debug, Clone)]
pub struct WirelessDeviceInfo {
    pub udid: String,
    pub name: String,
    pub product_type: String,
    pub ios_version: String,
    pub build_version: String,
}

impl std::fmt::Display for WirelessDeviceInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({}, iOS {} [{}]) • Wi-Fi",
            self.name, self.product_type, self.ios_version, self.build_version
        )
    }
}

fn state_dir() -> PathBuf {
    let root = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let dir = root.join("AirCard");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn pairing_path() -> PathBuf {
    state_dir().join("wireless-pairing.plist")
}

fn host_identity_path() -> PathBuf {
    state_dir().join("wireless-host.plist")
}

fn device_info_path() -> PathBuf {
    state_dir().join("wireless-device.plist")
}

fn stable_host_name() -> String {
    if let Ok(bytes) = std::fs::read(&host_identity_path()) {
        if let Ok(value) = plist::Value::from_reader(std::io::Cursor::new(bytes)) {
            if let Some(name) = value
                .as_dictionary()
                .and_then(|d| d.get("name"))
                .and_then(|v| v.as_string())
            {
                return name.to_string();
            }
        }
    }
    format!("AirCard-{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
}

fn load_host_info() -> PairableHostInfo {
    let name = stable_host_name();
    let mut info = PairableHostInfo::generate(&name, MODEL);

    if let Ok(bytes) = std::fs::read(host_identity_path()) {
        if let Ok(value) = plist::Value::from_reader(std::io::Cursor::new(bytes)) {
            if let Some(data) = value
                .as_dictionary()
                .and_then(|d| d.get("alt_irk"))
                .and_then(|v| v.as_data())
            {
                info.alt_irk = data.to_vec();
            }
        }
    }

    let mut dict = plist::Dictionary::new();
    dict.insert("name".into(), plist::Value::String(name));
    dict.insert("model".into(), plist::Value::String(MODEL.into()));
    dict.insert("alt_irk".into(), plist::Value::Data(info.alt_irk.clone()));
    if let Ok(bytes) = plist::to_bytes_xml(&plist::Value::Dictionary(dict)) {
        let _ = std::fs::write(host_identity_path(), bytes);
    }

    info
}

fn load_pairing_file() -> Result<RpPairingFile> {
    let path = pairing_path();
    if !path.is_file() {
        bail!("No saved iOS 27 wireless pairing exists yet. Tap 'Pair Wi-Fi' first.");
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to create pairing-file runtime")?;
    let file = runtime
        .block_on(RpPairingFile::read_from_file(&path))
        .context("Failed to read saved wireless pairing file")?;
    Ok(file)
}

fn save_pairing_file(file: &RpPairingFile) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to create pairing-file runtime")?;
    runtime
        .block_on(file.write_to_file(pairing_path()))
        .context("Failed to save iOS 27 wireless pairing file")
}

fn save_device_info(info: &WirelessDeviceInfo) -> Result<()> {
    let mut d = plist::Dictionary::new();
    d.insert("udid".into(), plist::Value::String(info.udid.clone()));
    d.insert("name".into(), plist::Value::String(info.name.clone()));
    d.insert("product_type".into(), plist::Value::String(info.product_type.clone()));
    d.insert("ios_version".into(), plist::Value::String(info.ios_version.clone()));
    d.insert("build_version".into(), plist::Value::String(info.build_version.clone()));
    std::fs::write(device_info_path(), plist::to_bytes_xml(&plist::Value::Dictionary(d))?)
        .context("Failed to save wireless device metadata")?;
    Ok(())
}

pub fn load_saved_device_info() -> Option<WirelessDeviceInfo> {
    let bytes = std::fs::read(device_info_path()).ok()?;
    let value = plist::Value::from_reader(std::io::Cursor::new(bytes)).ok()?;
    let d = value.as_dictionary()?;
    Some(WirelessDeviceInfo {
        udid: d.get("udid")?.as_string()?.to_string(),
        name: d.get("name")?.as_string()?.to_string(),
        product_type: d.get("product_type")?.as_string()?.to_string(),
        ios_version: d.get("ios_version")?.as_string()?.to_string(),
        build_version: d.get("build_version")?.as_string()?.to_string(),
    })
}

pub fn has_saved_pairing() -> bool {
    pairing_path().is_file()
}

struct Advertisement {
    daemon: ServiceDaemon,
    fullname: String,
}

impl Advertisement {
    fn start(info: &PairableHostInfo, pairing_file: &RpPairingFile, port: u16) -> Result<Self> {
        let identifier = pairing_file.identifier.clone();
        let txt_records = info.mdns_txt_records(&identifier);
        let properties: Vec<(&str, &str)> = txt_records
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();

        let daemon = ServiceDaemon::new().context("failed to start mDNS daemon")?;
        daemon
            .set_service_name_len_max(30)
            .context("failed to configure mDNS service name length")?;

        let instance = format!("AirCard-{}", &identifier[..8.min(identifier.len())]);
        let host = format!("aircard-{}.local.", &identifier[..8.min(identifier.len())]);
        let service = ServiceInfo::new(
            PAIRABLE_HOST_SERVICE_TYPE,
            &instance,
            &host,
            "",
            port,
            &properties[..],
        )
        .context("failed to create iOS 27 wireless-pairing mDNS service")?
        .enable_addr_auto();

        let fullname = service.get_fullname().to_string();
        daemon
            .register(service)
            .context("failed to advertise AirCard wireless pairing service")?;

        Ok(Self { daemon, fullname })
    }
}

impl Drop for Advertisement {
    fn drop(&mut self) {
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}

/// Perform iOS/iPadOS 27 Remote Pairing and persist the resulting device pairing.
pub fn pair_over_wifi<L, P>(mut log: L, mut pin: P) -> Result<(String, String)>
where
    L: FnMut(String) + Send + 'static,
    P: FnMut(String) + Send + 'static,
{
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create wireless pairing runtime")?;

    runtime.block_on(async move {
        let host_info = load_host_info();
        let host_name = host_info.name.clone();
        let mut pairing_file = RpPairingFile::generate(&host_name);

        let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
            .await
            .context("failed to open wireless pairing listener")?;
        let port = listener.local_addr()?.port();
        let _advertisement = Advertisement::start(&host_info, &pairing_file, port)?;

        log(format!(
            "Advertising iOS 27 wireless pairing as '{}' on TCP port {}...",
            host_name, port
        ));
        log("On iPhone: Developer Mode → Paired Devices → choose AirCard.".to_string());

        let (stream, address) = listener
            .accept()
            .await
            .context("failed to accept iOS wireless pairing connection")?;
        log(format!("iPhone connected from {}", address));

        let mut host = PairableHost::new(
            RpPairingSocket::new_device(stream),
            host_info,
        );
        let peer = host
            .accept(&mut pairing_file, |code| {
                pin(code);
                async {}
            })
            .await
            .context("iOS Remote Pairing handshake failed")?;

        save_pairing_file(&pairing_file)?;
        let info = WirelessDeviceInfo {
            udid: peer.remotepairing_udid.clone(),
            name: peer.name.clone(),
            product_type: "iPhone".into(),
            ios_version: "27.x".into(),
            build_version: "Remote Pairing".into(),
        };
        let _ = save_device_info(&info);

        log(format!(
            "Wireless pairing completed for {} ({})",
            peer.name, peer.remotepairing_udid
        ));
        log("Pairing record saved. AirCard can reconnect over Wi-Fi without repeating the PIN.".to_string());

        Ok((peer.remotepairing_udid, peer.name))
    })
}

#[derive(Clone)]
pub struct WirelessLink {
    handle: AdapterHandle,
    rsd: idevice::rsd::RsdHandshake,
    _tunnel_control: Arc<tokio::sync::Mutex<RemotePairingClient<RpPairingSocket<tokio::net::TcpStream>>>>,
}

impl std::fmt::Debug for WirelessLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WirelessLink").field("rsd", &self.rsd).finish()
    }
}

impl WirelessLink {
    pub async fn service<T>(&mut self) -> Result<T, idevice::IdeviceError>
    where
        T: IdeviceService + RsdService,
    {
        self.rsd
            .connect::<T>(&mut self.handle)
            .await
            .map_err(Into::into)
    }

    pub async fn connect_rsd_service(
        &mut self,
        name: &str,
    ) -> Result<Box<dyn idevice::ReadWrite>, idevice::IdeviceError> {
        let port = self
            .rsd
            .services
            .get(name)
            .ok_or(idevice::IdeviceError::ServiceNotFound)?
            .port;
        self.handle.connect_to_service_port(port).await
    }
}

#[derive(Clone, Debug)]
struct Addresses(SocketAddr);

impl Addresses {
    async fn connect(&self) -> Result<tokio::net::TcpStream, idevice::IdeviceError> {
        self.connect_to(self.0.port()).await
    }

    async fn connect_to(&self, port: u16) -> Result<tokio::net::TcpStream, idevice::IdeviceError> {
        let mut addr = self.0.clone();
        addr.set_port(port);
        match timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => Err(idevice::IdeviceError::Socket(e)),
            Err(_) => Err(idevice::IdeviceError::Socket(std::io::ErrorKind::TimedOut.into())),
        }
    }
}

fn address(service: &ResolvedService) -> Option<Addresses> {
    let port = service.port;
    service.addresses.iter().next().map(|ip| {
        Addresses(match ip {
            ScopedIp::V6(v6) => SocketAddr::V6(SocketAddrV6::new(
                *v6.addr(),
                port,
                0,
                v6.scope_id().index,
            )),
            ip => SocketAddr::new(ip.to_ip_addr(), port),
        })
    })
}

async fn find_remote_pairing(alt_irk: &[u8]) -> Option<Addresses> {
    let daemon = ServiceDaemon::new().ok()?;
    let receiver = daemon.browse(REMOTE_PAIRING_SERVICE).ok()?;
    let deadline = Instant::now() + BROWSE_TIMEOUT;

    let found = loop {
        match timeout_at(deadline, receiver.recv_async()).await {
            Ok(Ok(ServiceEvent::ServiceResolved(service))) => {
                let identifier = service.get_property_val_str("identifier")?;
                let auth_tag = service.get_property_val_str("authTag")?;
                if PeerDevice::validate_auth_tag(alt_irk, identifier, auth_tag) {
                    break address(&service);
                }
            }
            Ok(Ok(_)) => {}
            Ok(Err(_)) | Err(_) => break None,
        }
    };

    let _ = daemon.shutdown();
    found
}

pub async fn open_link() -> Result<WirelessLink> {
    let mut pairing_file = load_pairing_file()?;
    let alt_irk = pairing_file
        .alt_irk
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Saved pairing has no alt_irk. Pair the iPhone again."))?
        .to_vec();

    let addresses = find_remote_pairing(&alt_irk)
        .await
        .ok_or_else(|| anyhow::anyhow!("Paired iPhone was not found on the local Wi-Fi network"))?;

    let host_name = stable_host_name();
    let mut control = RemotePairingClient::new(
        RpPairingSocket::new(addresses.connect().await?),
        &host_name,
    );

    control.attempt_pair_verify().await?;
    control.validate_pairing(&pairing_file).await?;

    let tunnel_port = control.create_tcp_listener().await?;
    let tunnel = connect_tls_psk_tunnel_native(
        addresses.connect_to(tunnel_port).await?,
        control.encryption_key(),
    )
    .await?;

    let client_ip: IpAddr = tunnel.info.client_address.parse()?;
    let server_ip: IpAddr = tunnel.info.server_address.parse()?;
    let mtu = tunnel.info.mtu as usize;
    let rsd_port = tunnel.info.server_rsd_port;

    let mut adapter = Adapter::new(Box::new(tunnel.into_inner()), client_ip, server_ip);
    adapter.set_mss(mtu.saturating_sub(60));

    let handle = adapter.to_async_handle();
    let rsd = idevice::rsd::RsdHandshake::new(handle.connect(rsd_port).await?).await?;

    Ok(WirelessLink {
        handle,
        rsd,
        _tunnel_control: Arc::new(tokio::sync::Mutex::new(control)),
    })
}

/// Connect and query the remote lockdown service for real device metadata.
pub fn probe_device() -> Result<Option<WirelessDeviceInfo>> {
    if !has_saved_pairing() {
        return Ok(None);
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create wireless probe runtime")?;

    runtime.block_on(async {
        let mut link = open_link().await?;
        let mut lockdown = link
            .service::<idevice::lockdown::LockdownClient>()
            .await?;

        let name = lockdown
            .get_value(Some("DeviceName"), None)
            .await?
            .as_string()
            .unwrap_or("iPhone")
            .to_string();
        let product_type = lockdown
            .get_value(Some("ProductType"), None)
            .await?
            .as_string()
            .unwrap_or("iPhone")
            .to_string();
        let ios_version = lockdown
            .get_value(Some("ProductVersion"), None)
            .await?
            .as_string()
            .unwrap_or("Unknown")
            .to_string();
        let build_version = lockdown
            .get_value(Some("BuildVersion"), None)
            .await?
            .as_string()
            .unwrap_or("Unknown")
            .to_string();
        let udid = lockdown
            .get_value(Some("UniqueDeviceID"), None)
            .await?
            .as_string()
            .unwrap_or_default()
            .to_string();

        let info = WirelessDeviceInfo {
            udid,
            name,
            product_type,
            ios_version,
            build_version,
        };
        let _ = save_device_info(&info);
        Ok(Some(info))
    })
}

/// Scan syslog through the iOS 27 RSD service instead of usbmuxd/MobileDevice.
pub fn scan_syslog_for_cards_wireless<F, L>(
    stop_flag: Arc<std::sync::atomic::AtomicBool>,
    mut on_card_found: F,
    mut log: L,
) -> Result<()>
where
    F: FnMut(String, String) + Send + 'static,
    L: FnMut(String) + Send + 'static,
{
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create wireless syslog runtime")?;

    runtime.block_on(async move {
        use idevice::services::syslog_relay::SyslogRelayClient;
        use crate::scanner::{add_or_update_card, extract_card_hash_from_line, extract_card_name_from_line};

        log("Opening iOS 27 RSD tunnel for syslog...".into());
        let mut link = open_link().await.context("Failed to open wireless RSD tunnel")?;
        let mut syslog = link
            .service::<SyslogRelayClient>()
            .await
            .context("Failed to open com.apple.syslog_relay.shim.remote")?;

        log("Wireless syslog relay established. Listening for Wallet & PassKit events...".into());

        while !stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
            match timeout(Duration::from_millis(750), syslog.next()).await {
                Ok(Ok(line)) => {
                    if let Some(hash) = extract_card_hash_from_line(&line) {
                        let name = extract_card_name_from_line(&line).unwrap_or_default();
                        add_or_update_card(&hash, &name);
                        on_card_found(hash, name);
                    }
                }
                Ok(Err(e)) => return Err(anyhow::anyhow!("Wireless syslog ended: {e}")),
                Err(_) => {}
            }
        }

        log("Wireless syslog scan stopped.".into());
        Ok(())
    })
}

async fn timeout_at(deadline: Instant, fut: impl std::future::Future<Output = Result<ServiceEvent, mdns_sd::RecvError>>) -> Result<Result<ServiceEvent, mdns_sd::RecvError>, tokio::time::error::Elapsed> {
    timeout(deadline.saturating_duration_since(Instant::now()), fut).await
}
