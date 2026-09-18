use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV6};
use std::path::PathBuf;
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
use idevice::provider::RsdProvider;
use mdns_sd::{ResolvedService, ScopedIp, ServiceDaemon, ServiceEvent, ServiceInfo};
use tokio::net::TcpListener;
use tokio::time::timeout;

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
                if data.len() == 16 {
                    info.alt_irk.copy_from_slice(data);
                }
            }
        }
    }

    let mut dict = plist::Dictionary::new();
    dict.insert("name".into(), plist::Value::String(name));
    dict.insert("model".into(), plist::Value::String(MODEL.into()));
    dict.insert("alt_irk".into(), plist::Value::Data(info.alt_irk.to_vec()));
    let mut bytes = Vec::new();
    if plist::Value::Dictionary(dict).to_writer_xml(&mut bytes).is_ok() {
        let _ = std::fs::write(host_identity_path(), bytes);
    }

    info
}

async fn load_pairing_file() -> Result<RpPairingFile> {
    let path = pairing_path();
    if !path.is_file() {
        bail!("No saved iOS 27 wireless pairing exists yet. Tap 'Pair Wi-Fi' first.");
    }
    RpPairingFile::read_from_file(&path)
        .await
        .context("Failed to read saved wireless pairing file")
}

async fn save_pairing_file(file: &RpPairingFile) -> Result<()> {
    file.write_to_file(pairing_path())
        .await
        .context("Failed to save iOS 27 wireless pairing file")
}

fn save_device_info(info: &WirelessDeviceInfo) -> Result<()> {
    let mut d = plist::Dictionary::new();
    d.insert("udid".into(), plist::Value::String(info.udid.clone()));
    d.insert("name".into(), plist::Value::String(info.name.clone()));
    d.insert("product_type".into(), plist::Value::String(info.product_type.clone()));
    d.insert("ios_version".into(), plist::Value::String(info.ios_version.clone()));
    d.insert("build_version".into(), plist::Value::String(info.build_version.clone()));
    let mut bytes = Vec::new();
    plist::Value::Dictionary(d).to_writer_xml(&mut bytes)?;
    std::fs::write(device_info_path(), bytes)
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

        let instance = identifier.clone();
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
        log("Remote Pairing handshake started. Waiting for the iPhone to finish pair-setup...".to_string());
        let peer = timeout(
            Duration::from_secs(120),
            host.accept(&mut pairing_file, |code| {
                pin(code);
                async {}
            }),
        )
        .await
        .context("Timed out after 120 seconds waiting for the iPhone to finish Remote Pairing")?
        .context("iOS Remote Pairing handshake failed")?;
        log("iPhone completed the Remote Pairing handshake.".to_string());

        save_pairing_file(&pairing_file).await?;
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
    let deadline = tokio::time::Instant::now() + BROWSE_TIMEOUT;

    let found = loop {
        match tokio::time::timeout_at(deadline, receiver.recv_async()).await {
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
    let mut pairing_file = load_pairing_file().await?;
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
    control.validate_pairing(&mut pairing_file).await?;

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

    let mut handle = adapter.to_async_handle();
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
        let mut link = open_link().await.map_err(|e| anyhow::anyhow!(e.to_string()))?;
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



async fn send_plist_frame(
    stream: &mut Box<dyn idevice::ReadWrite>,
    value: plist::Value,
) -> Result<()> {
    use tokio::io::{AsyncWriteExt, BufWriter};

    let mut body = Vec::new();
    value.to_writer_xml(&mut body)?;
    let len = u32::try_from(body.len()).context("plist frame is too large")?;
    let mut writer = BufWriter::new(stream);
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_plist_frame(stream: &mut Box<dyn idevice::ReadWrite>) -> Result<plist::Value> {
    use tokio::io::AsyncReadExt;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 64 * 1024 * 1024 {
        bail!("invalid plist frame length: {len}");
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    Ok(plist::from_bytes(&body)?)
}

async fn rsd_service_stream(
    link: &mut WirelessLink,
    names: &[&str],
) -> Result<Box<dyn idevice::ReadWrite>> {
    for name in names {
        if link.rsd.services.contains_key(*name) {
            let mut stream = link.connect_rsd_service(name).await?;
            send_plist_frame(
                &mut stream,
                { let mut checkin = plist::Dictionary::new();
                checkin.insert("Label".into(), plist::Value::String("aircard".into()));
                checkin.insert("ProtocolVersion".into(), plist::Value::String("2".into()));
                checkin.insert("Request".into(), plist::Value::String("RSDCheckin".into()));
                plist::Value::Dictionary(checkin) },
            )
            .await?;
            let _ = read_plist_frame(&mut stream).await?;
            let _ = read_plist_frame(&mut stream).await?;
            return Ok(stream);
        }
    }
    bail!("None of the requested RSD services are advertised: {names:?}")
}

/// Send an Apple StreamingZip archive through the iOS 27 RSD service.
pub fn stage_streaming_zip_wireless(
    source_subdir: &str,
    archive: &[u8],
) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create wireless streaming-zip runtime")?;

    runtime.block_on(async {
        use tokio::io::AsyncWriteExt;

        let mut link = open_link().await.map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let mut stream = rsd_service_stream(
            &mut link,
            &[
                "com.apple.streaming_zip_conduit.shim.remote",
                "com.apple.streaming_zip_conduit",
            ],
        )
        .await
        .context("streaming_zip_conduit is not available over the wireless RSD tunnel")?;

        let mut request = plist::Dictionary::new();
        request.insert("MediaSubdir".into(), plist::Value::String(source_subdir.to_string()));
        let request = plist::Value::Dictionary(request);
        send_plist_frame(&mut stream, request).await?;

        let mut sent = 0usize;
        while sent < archive.len() {
            let end = (sent + 64 * 1024).min(archive.len());
            stream.write_all(&archive[sent..end]).await?;
            sent = end;
        }
        stream.flush().await?;

        let _response = read_plist_frame(&mut stream)
            .await
            .context("StreamingZip did not return a response")?;
        Ok::<(), anyhow::Error>(())
    })
}

/// Minimal clean-room AirTraffic legacy message client over the RSD shim.
pub fn sync_assets_via_airtraffic_wireless<L>(
    assets: &[(&str, &str)],
    mut log: L,
) -> Result<()>
where
    L: FnMut(&str),
{
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create wireless AirTraffic runtime")?;

    runtime.block_on(async {
        let mut link = open_link().await.map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let mut stream = rsd_service_stream(
            &mut link,
            &["com.apple.atc2.shim.remote", "com.apple.atc.shim.remote"],
        )
        .await
        .context("AirTraffic ATC RSD shim is not available")?;

        fn dict(entries: Vec<(&str, plist::Value)>) -> plist::Value {
            let mut d = plist::Dictionary::new();
            for (k, v) in entries {
                d.insert(k.to_string(), v);
            }
            plist::Value::Dictionary(d)
        }

        let message_name = |value: &plist::Value| {
            value
                .as_dictionary()
                .and_then(|d| d.get("Command").or_else(|| d.get("MessageName")).or_else(|| d.get("Name")))
                .and_then(|v| v.as_string())
                .unwrap_or("")
                .to_string()
        };

        // Apple's ATHostConnection creates the legacy AirTraffic session and
        // the device sends its initial messages (including SyncAllowed) first.
        // Do not send a synthetic Capabilities command here.
        log("Starting AirTraffic legacy handshake...");
        log("Waiting for SyncAllowed from iPhone...");
        let mut sync_allowed = false;
        for _ in 0..30 {
            let msg = read_plist_frame(&mut stream).await?;
            let name = message_name(&msg);
            log(&format!("AirTraffic received: {}", if name.is_empty() { "<unnamed message>" } else { &name }));
            if name == "SyncAllowed" { sync_allowed = true; break; }
            if name == "SyncFailed" { bail!("AirTraffic returned SyncFailed before sync started"); }
        }
        if !sync_allowed { bail!("AirTraffic: SyncAllowed was not received"); }

        let library_id = uuid::Uuid::new_v4().to_string();
        let host_info = dict(vec![
            ("Type", plist::Value::String("iTunes".into())),
            ("Version", plist::Value::String("13.7.0.161".into())),
            ("MacOSVersion", plist::Value::String("Windows NT 10.0".into())),
            ("SyncHostName", plist::Value::String("aircard".into())),
            ("LibraryID", plist::Value::String(library_id)),
            ("SyncedDataclasses", plist::Value::Array(vec![plist::Value::String("Book".into())])),
            ("SyncedAssetTypes", plist::Value::Array(vec![plist::Value::String("Book".into())])),
            ("Wakeable", plist::Value::Boolean(false)),
        ]);

        let host_params = dict(vec![
            ("HostInfo", host_info.clone()),
        ]);
        send_plist_frame(&mut stream, dict(vec![
            ("Command", plist::Value::String("HostInfo".into())),
            ("Params", host_params),
            ("Session", plist::Value::Integer(0.into())),
        ])).await?;

        let params = dict(vec![
            ("DataclassAnchors", dict(vec![])),
            ("Dataclasses", plist::Value::Array(vec![plist::Value::String("Book".into())])),
            ("HostInfo", host_info),
        ]);
        // Match Apple's AirTrafficHost timing: give the device a short
        // interval after HostInfo before issuing the sync request.
        log("HostInfo sent. Waiting 200 ms before RequestingSync...");
        tokio::time::sleep(Duration::from_millis(200)).await;

        send_plist_frame(&mut stream, dict(vec![
            ("Command", plist::Value::String("RequestingSync".into())),
            ("Params", params),
            ("Session", plist::Value::Integer(1.into())),
        ])).await?;

        log("RequestingSync sent. Waiting for ReadyForSync...");
        let mut ready = false;
        for _ in 0..30 {
            let msg = read_plist_frame(&mut stream).await?;
            let name = message_name(&msg);
            log(&format!("AirTraffic received: {}", if name.is_empty() { "<unnamed message>" } else { &name }));
            if name == "ReadyForSync" { ready = true; break; }
            if name == "SyncFailed" { bail!("AirTraffic returned SyncFailed while preparing sync"); }
        }
        if !ready { bail!("AirTraffic: ReadyForSync was not received"); }

        let sync_types = dict(vec![("Book", plist::Value::Integer(1.into()))]);
        send_plist_frame(&mut stream, dict(vec![
            ("Command", plist::Value::String("MetadataSyncFinished".into())),
            ("Params", dict(vec![
                ("SyncTypes", sync_types),
                ("DataclassAnchors", dict(vec![])),
            ])),
            ("Session", plist::Value::Integer(1.into())),
        ])).await?;

        log("Waiting for AssetManifest...");
        let manifest = loop {
            let msg = read_plist_frame(&mut stream).await?;
            let name = message_name(&msg);
            if name == "AssetManifest" {
                let p = msg.as_dictionary().and_then(|d| d.get("Params")).and_then(|v| v.as_dictionary());
                break p.and_then(|d| d.get("AssetManifest").or_else(|| d.get("Manifest"))).cloned();
            }
            if name == "SyncFailed" || name == "SyncFinished" {
                bail!("AirTraffic terminated before AssetManifest: {name}");
            }
        };

        let manifest = manifest.context("AssetManifest message did not contain a manifest")?;
        let available: Vec<String> = manifest
            .as_dictionary()
            .and_then(|d| d.get("Book"))
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_dictionary())
            .filter(|d| d.get("IsDownload").and_then(|v| v.as_boolean()).unwrap_or(false))
            .filter_map(|d| d.get("AssetID").and_then(|v| v.as_string()).map(str::to_owned))
            .collect();

        for (ident, dest) in assets {
            if !available.is_empty() && !available.iter().any(|x| x == ident) {
                bail!("AirTraffic manifest does not advertise asset {ident}");
            }
            send_plist_frame(&mut stream, dict(vec![
                ("Command", plist::Value::String("AssetCompleted".into())),
                ("Params", dict(vec![
                    ("AssetID", plist::Value::String((*ident).into())),
                    ("Dataclass", plist::Value::String("Book".into())),
                    ("Destination", plist::Value::String((*dest).into())),
                ])),
                ("Session", plist::Value::Integer(1.into())),
            ])).await?;
            tokio::time::sleep(Duration::from_millis(900)).await;
        }
        Ok::<(), anyhow::Error>(())
    })
}

pub fn wireless_write_file(path: &str, data: &[u8]) -> Result<()> {
    let path = path.to_string();
    let data = data.to_vec();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create wireless AFC runtime")?;

    runtime.block_on(async move {
        use idevice::services::afc::opcode::AfcFopenMode;
        use idevice::services::afc::AfcClient;

        let mut link = open_link().await.map_err(|e| idevice::IdeviceError::UnexpectedResponse(e.to_string()))?;
        let mut afc = link.service::<AfcClient>().await?;
        let mut fd = afc.open(&path, AfcFopenMode::WrOnly).await?;
        fd.write_entire(&data).await?;
        fd.close().await?;
        Ok::<(), idevice::IdeviceError>(())
    })?;
    Ok(())
}

pub fn wireless_read_file(path: &str) -> Result<Option<Vec<u8>>> {
    let path = path.to_string();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create wireless AFC runtime")?;

    runtime.block_on(async move {
        use idevice::services::afc::opcode::AfcFopenMode;
        use idevice::services::afc::AfcClient;

        let mut link = open_link().await.map_err(|e| idevice::IdeviceError::UnexpectedResponse(e.to_string()))?;
        let mut afc = link.service::<AfcClient>().await?;
        if afc.get_file_info(&path).await.is_err() {
            return Ok::<Option<Vec<u8>>, idevice::IdeviceError>(None);
        }
        let mut fd = afc.open(&path, AfcFopenMode::RdOnly).await?;
        let data = fd.read_entire().await?;
        fd.close().await?;
        Ok(Some(data))
    }).map_err(Into::into)
}

pub fn wireless_remove(path: &str, recursive: bool) -> Result<()> {
    let path = path.to_string();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create wireless AFC runtime")?;

    runtime.block_on(async move {
        use idevice::services::afc::AfcClient;

        let mut link = open_link().await.map_err(|e| idevice::IdeviceError::UnexpectedResponse(e.to_string()))?;
        let mut afc = link.service::<AfcClient>().await?;
        if recursive {
            let _ = afc.remove_all(&path).await;
        } else {
            let _ = afc.remove(&path).await;
        }
        Ok::<(), idevice::IdeviceError>(())
    })?;
    Ok(())
}
