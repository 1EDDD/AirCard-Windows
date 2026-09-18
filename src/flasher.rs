use std::thread::sleep;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::afc::AfcClient;
use crate::airlift::{
    LINK_PREFIX, RECOVERED_PREFIX, SOURCE_PREFIX, build_books_plist,
    build_streaming_zip_archive, restore_books, snapshot_books,
    stage_streaming_zip,
};
use crate::airtraffic::sync_assets_via_airtraffic;
use crate::device::ActiveDeviceSession;
use crate::wireless::{stage_streaming_zip_wireless, sync_assets_via_airtraffic_wireless, wireless_read_file, wireless_remove, wireless_write_file};

pub const TARGET_WALLET_ASSETS: &[&str] = &[
    "cardBackgroundCombined@3x.png",
    "cardBackgroundCombined@2x.png",
];

pub const CACHE_FILES: &[&str] = &[
    "FrontFace",
    "PlaceHolder",
    "Preview",
];

#[link(name = "bcrypt")]
unsafe extern "system" {
    fn BCryptGenRandom(
        hAlgorithm: *mut std::ffi::c_void,
        pbBuffer: *mut u8,
        cbBuffer: u32,
        dwFlags: u32,
    ) -> i32;
}

pub fn generate_token() -> String {
    let mut bytes = [0u8; 10];
    unsafe {
        let _ = BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            2, // BCRYPT_USE_SYSTEM_PREFERRED_RNG
        );
    }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn write_system_file<L>(
    udid: &str,
    target_dir: &str,
    leaf_name: &str,
    payload: &[u8],
    mut log: L,
) -> Result<()>
where
    L: FnMut(&str),
{
    let token = generate_token();
    let source = format!("{}{}", SOURCE_PREFIX, token);
    let link_dest = format!("{}{}", LINK_PREFIX, token);
    let recovered = format!("{}{}", RECOVERED_PREFIX, token);

    let link_ident = format!("../../{}/p0/p1/p2/link", source);
    let payload_ident = format!("../../{}/payload", source);
    let target_dest = format!("{}/{}", link_dest, leaf_name);

    let books_identifiers = vec![link_ident.clone(), payload_ident.clone()];
    let assets_to_sync = [
        (link_ident.as_str(), link_dest.as_str()),
        (payload_ident.as_str(), target_dest.as_str()),
    ];

    log(&format!("Connecting AFC for {}...", leaf_name));
    let session = ActiveDeviceSession::open(Some(udid))
        .context("Failed to open device session for writing")?;
    let afc = AfcClient::new(&session).context("Failed to open AFC connection")?;

    let snapshot = snapshot_books(&afc).context("Failed to snapshot Books state before staging")?;

    let archive_data = build_streaming_zip_archive(target_dir, payload)
        .context("Failed to build streaming zip archive")?;

    let books_plist = build_books_plist(&books_identifiers)
        .context("Failed to build Books.plist")?;

    let write_res = (|| -> Result<()> {
        log(&format!("Staging payload archive ({} bytes) via MobileInstallation...", archive_data.len()));
        stage_streaming_zip(&session, &source, &archive_data)
            .context("Failed to stage streaming zip conduit")?;

        let link_obj = format!("{}/p0/p1/p2/link", source);
        let payload_obj = format!("{}/payload", source);
        if !afc.exists(&source) || !afc.exists(&link_obj) || !afc.exists(&payload_obj) {
            bail!("StreamingZip completed but staging link/payload object missing on AFC");
        }

        afc.make_directory_recursive("Books/Sync")?;
        afc.write_file("Books/Sync/Books.plist", &books_plist)?;
        if !afc.exists("Books/Sync/Books.plist") {
            bail!("Failed to stage Books/Sync/Books.plist");
        }

        log(&format!("Synchronizing {} with AirTraffic host daemon...", leaf_name));
        sync_assets_via_airtraffic(udid, &assets_to_sync, &mut log)
            .context("AirTraffic sync failed")?;

        Ok(())
    })();

    let _ = afc.remove_path(&link_dest);
    let _ = afc.remove_path(&recovered);
    let _ = afc.remove_tree(&source);
    sleep(Duration::from_millis(800));

    let restore_res = restore_books(&afc, &snapshot);

    write_res?;
    restore_res.context("Failed to restore Books state during cleanup")?;
    log(&format!("Successfully written: {}", leaf_name));

    Ok(())
}

#[allow(dead_code)]
pub fn write_system_files_batch<L>(
    udid: &str,
    target_dir: &str,
    items: &[(&str, &[u8])],
    mut log: L,
) -> Result<()>
where
    L: FnMut(&str),
{
    for (leaf, payload) in items {
        write_system_file(udid, target_dir, leaf, payload, &mut log)?;
    }
    Ok(())
}

pub fn flash_wallet_skin<F, L>(
    udid: &str,
    card_hash: &str,
    skin_png: &[u8],
    mut progress: F,
    mut log: L,
) -> Result<()>
where
    F: FnMut(usize, usize, &str),
    L: FnMut(&str),
{
    let pkpass_dir = format!("/var/mobile/Library/Passes/Cards/{}.pkpass", card_hash);

    log(&format!("Target Card Hash: {}", card_hash));
    log(&format!("Skin payload size: {} bytes PNG", skin_png.len()));

    let total_steps = TARGET_WALLET_ASSETS.len() + 2 * CACHE_FILES.len();
    let mut step = 0;

    for asset in TARGET_WALLET_ASSETS {
        step += 1;
        progress(step, total_steps, &format!("Writing {}...", asset));
        log(&format!("[{}/{}] Writing primary asset {}...", step, total_steps, asset));
        write_system_file(udid, &pkpass_dir, asset, skin_png, &mut log)
            .context(format!("Failed to write card asset {}", asset))?;
    }

    for ext in [".cache", ".pkcache"] {
        let cache_dir = format!("/var/mobile/Library/Passes/Cards/{}{}", card_hash, ext);
        for leaf in CACHE_FILES {
            step += 1;
            progress(step, total_steps, &format!("Clearing {}/{}...", ext, leaf));
            log(&format!("[{}/{}] Invaliding cache: {}/{}...", step, total_steps, ext, leaf));
            let _ = write_system_file(udid, &cache_dir, leaf, b"corrupted", &mut log);
        }
    }

    progress(total_steps, total_steps, "Card skin updated successfully!");
    log("Card skin write finished! Close and reopen Wallet on iPhone to view.");
    Ok(())
}

pub fn flash_passcode_theme<F, L>(
    udid: &str,
    items: &[(String, String, Vec<u8>)],
    mut progress: F,
    mut log: L,
) -> Result<()>
where
    F: FnMut(usize, usize, &str),
    L: FnMut(&str),
{
    let total = items.len();
    log(&format!("Flashing passcode theme ({} button assets)...", total));
    for (idx, (target_dir, leaf, payload)) in items.iter().enumerate() {
        progress(
            idx + 1,
            total,
            &format!("Writing {}...", leaf),
        );
        log(&format!("[{}/{}] Writing button asset {} to {}...", idx + 1, total, leaf, target_dir));
        write_system_file(udid, target_dir, leaf, payload, &mut log)
            .context(format!("Failed to write passcode button {}", leaf))?;
    }

    log("Passcode theme successfully written! Lock iPhone to see new keypad.");
    Ok(())
}


/// Flash the Wallet skin using only the iOS 27 Remote Pairing/RSD transport.
/// This mirrors the existing USB staging flow: StreamingZip creates the staged
/// link/payload objects, AFC updates Books/Sync/Books.plist, and the ATC RSD
/// shim completes the Book asset sync.
pub fn flash_wallet_skin_wireless<F, L>(
    card_hash: &str,
    skin_png: &[u8],
    mut progress: F,
    mut log: L,
) -> Result<()>
where
    F: FnMut(usize, usize, &str),
    L: FnMut(&str),
{
    let pkpass_dir = format!("/var/mobile/Library/Passes/Cards/{}.pkpass", card_hash);
    log(&format!("Wireless target Card Hash: {}", card_hash));
    log(&format!("Wireless skin payload size: {} bytes PNG", skin_png.len()));

    let original_books = wireless_read_file("Books/Sync/Books.plist")?;
    let total_steps = TARGET_WALLET_ASSETS.len() + 2 * CACHE_FILES.len();
    let mut step = 0;

    let result = (|| -> Result<()> {
        for asset in TARGET_WALLET_ASSETS {
            step += 1;
            progress(step, total_steps, &format!("Writing {} over Wi-Fi...", asset));

            let token = generate_token();
            let source = format!("{}{}", SOURCE_PREFIX, token);
            let link_dest = format!("{}{}", LINK_PREFIX, token);
            let recovered = format!("{}{}", RECOVERED_PREFIX, token);
            let link_ident = format!("../../{}/p0/p1/p2/link", source);
            let payload_ident = format!("../../{}/payload", source);
            let target_dest = format!("{}/{}", link_dest, asset);
            let assets_to_sync = [
                (link_ident.as_str(), link_dest.as_str()),
                (payload_ident.as_str(), target_dest.as_str()),
            ];

            let books_plist = build_books_plist(
                &[link_ident.clone(), payload_ident.clone()]
            ).context("Failed to build wireless Books.plist")?;
            let archive = build_streaming_zip_archive(&pkpass_dir, skin_png)
                .context("Failed to build wireless StreamingZip archive")?;

            log(&format!(
                "[{}/{}] Staging {} bytes through StreamingZip RSD shim...",
                step,
                total_steps,
                archive.len()
            ));
            stage_streaming_zip_wireless(&source, &archive)
                .context("Wireless StreamingZip staging failed")?;

            wireless_write_file("Books/Sync/Books.plist", &books_plist)
                .context("Failed to write Books/Sync/Books.plist over Wi-Fi")?;

            log(&format!(
                "[{}/{}] Syncing {} through AirTraffic RSD shim...",
                step, total_steps, asset
            ));
            sync_assets_via_airtraffic_wireless(&assets_to_sync, &mut log)
                .context("Wireless AirTraffic sync failed")?;

            wireless_remove(&link_dest, true)?;
            wireless_remove(&recovered, true)?;
            wireless_remove(&source, true)?;
            std::thread::sleep(Duration::from_millis(400));
        }

        for ext in [".cache", ".pkcache"] {
            let cache_dir = format!("/var/mobile/Library/Passes/Cards/{}{}", card_hash, ext);
            for leaf in CACHE_FILES {
                step += 1;
                progress(step, total_steps, &format!("Clearing {}/{} over Wi-Fi...", ext, leaf));
                log(&format!(
                    "[{}/{}] Clearing cache {}/{}...",
                    step, total_steps, ext, leaf
                ));

                let token = generate_token();
                let source = format!("{}{}", SOURCE_PREFIX, token);
                let link_dest = format!("{}{}", LINK_PREFIX, token);
                let recovered = format!("{}{}", RECOVERED_PREFIX, token);
                let link_ident = format!("../../{}/p0/p1/p2/link", source);
                let payload_ident = format!("../../{}/payload", source);
                let target_dest = format!("{}/{}", link_dest, leaf);
                let assets_to_sync = [
                    (link_ident.as_str(), link_dest.as_str()),
                    (payload_ident.as_str(), target_dest.as_str()),
                ];
                let books_plist = build_books_plist(&[link_ident, payload_ident])?;
                let archive = build_streaming_zip_archive(&cache_dir, b"corrupted")?;

                stage_streaming_zip_wireless(&source, &archive)?;
                wireless_write_file("Books/Sync/Books.plist", &books_plist)?;
                sync_assets_via_airtraffic_wireless(&assets_to_sync, &mut log)?;

                wireless_remove(&link_dest, true)?;
                wireless_remove(&recovered, true)?;
                wireless_remove(&source, true)?;
            }
        }

        Ok(())
    })();

    match original_books {
        Some(bytes) => {
            let _ = wireless_write_file("Books/Sync/Books.plist", &bytes);
        }
        None => {
            let _ = wireless_remove("Books/Sync/Books.plist", false);
        }
    }

    if let Err(e) = &result {
        log(&format!("Wireless Wallet flash failed: {e:#}"));
    }

    result?;
    progress(total_steps, total_steps, "Card skin updated successfully over Wi-Fi!");
    log("Wireless Wallet skin write finished! Close and reopen Wallet on iPhone.");
    Ok(())
}
