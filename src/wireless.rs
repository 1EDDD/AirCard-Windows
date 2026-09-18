use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use idevice::remote_pairing::{
    PAIRABLE_HOST_SERVICE_TYPE, PairableHost, PairableHostInfo, RpPairingFile, RpPairingSocket,
};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use tokio::net::TcpListener;

const MODEL: &str = "Mac17,7";

fn host_label() -> String {
    format!("aircard-{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
}

struct Advertisement {
    daemon: ServiceDaemon,
    fullname: String,
}

impl Advertisement {
    fn start(info: &PairableHostInfo, pairing_file: &RpPairingFile, port: u16) -> Result<Self> {
        let identifier = pairing_file.identifier.clone();
        let txt_records = info.mdns_txt_records(&identifier);
        let properties: Vec<_> = txt_records
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
            &properties,
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

/// Advertise AirCard as a pairable computer for iOS/iPadOS 27+.
/// The pairing record is kept in memory for this AirCard process.
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
        let host_name = host_label();
        let host_info = PairableHostInfo::generate(&host_name, MODEL);
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

        let mut host = PairableHost::new(RpPairingSocket::new_device(stream), host_info);
        let peer = host
            .accept(&mut pairing_file, |code| {
                pin(code.clone());
                async move { code }
            })
            .await
            .context("iOS Remote Pairing handshake failed")?;

        log(format!(
            "Wireless pairing completed for {} ({})",
            peer.name, peer.remotepairing_udid
        ));

        Ok((peer.remotepairing_udid, peer.name))
    })
}
