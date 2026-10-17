//! Kojalytics license check. The app opens its documents only on a computer where the Kojalytics
//! Launcher has activated a license key (Settings › License): the launcher saves a certificate,
//! signed by Kojalytics, for this machine; the app checks the signature and the machine offline.
//! Until then it shows a lock screen instead, and checks again every few seconds.
//!
//! Shared verbatim by WordKoja, GridKoja and DeckKoja (`apps/<app>/src/license.rs`).

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// Kojalytics' certificate-signing public key (Ed25519, raw); the launcher's `license::PUBLIC_KEY`.
const PUBLIC_KEY: [u8; 32] = [
    0x7a, 0x55, 0x81, 0x5a, 0xb1, 0xae, 0xda, 0xdc, 0xd7, 0x34, 0x0d, 0xcd, 0x52, 0xf4, 0x3a, 0x6c, 0xf9, 0x8d, 0x74, 0xcb, 0x7f, 0x7f,
    0x64, 0xab, 0x0b, 0x1b, 0x16, 0x22, 0x00, 0xc2, 0xdc, 0x14,
];
const SHOP_URL: &str = "https://www.kojalytics.com/koja-apps";
const LAUNCHER_BUNDLE_ID: &str = "com.kojalytics.artcraft-launcher";
const RECHECK: Duration = Duration::from_secs(3);

struct State {
    licensed: bool,
    reason: String,
    checked: Option<Instant>,
}

static STATE: Mutex<State> = Mutex::new(State { licensed: false, reason: String::new(), checked: None });

/// `true` when the app may show its documents; otherwise draws the lock screen into `ui`.
pub fn gate(ui: &mut egui::Ui) -> bool {
    let mut state = STATE.lock().unwrap_or_else(PoisonError::into_inner);
    if !state.licensed && state.checked.is_none_or(|t| t.elapsed() >= RECHECK) {
        match check() {
            Ok(()) => state.licensed = true,
            Err(e) => state.reason = e,
        }
        state.checked = Some(Instant::now());
    }
    if state.licensed {
        return true;
    }
    let reason = state.reason.clone();
    drop(state);
    lock_screen(ui, &reason);
    ui.ctx().request_repaint_after(RECHECK);
    false
}

fn lock_screen(ui: &mut egui::Ui, reason: &str) {
    let rect = ui.max_rect();
    ui.painter().rect_filled(rect, 0.0, egui::Color32::from_rgb(0x0c, 0x0c, 0x12));
    ui.scope_builder(egui::UiBuilder::new().max_rect(rect), |ui| {
        ui.vertical_centered(|ui| {
            ui.add_space((rect.height() / 2.0 - 140.0).max(24.0));
            ui.label(egui::RichText::new("🔒").size(40.0));
            ui.add_space(12.0);
            ui.label(egui::RichText::new("Lizenz erforderlich").size(28.0).strong().color(egui::Color32::WHITE));
            ui.add_space(8.0);
            ui.label(egui::RichText::new(reason).color(egui::Color32::from_rgb(0xa5, 0xb4, 0xfc)));
            ui.add_space(14.0);
            ui.label(
                egui::RichText::new(
                    "Aktiviere deinen Kojalytics-Lizenzschlüssel im Kojalytics Launcher unter Einstellungen › Lizenz.\nDiese App entsperrt sich danach automatisch.",
                )
                .color(egui::Color32::from_rgb(0xb4, 0xb4, 0xc4)),
            );
            ui.add_space(22.0);
            let accent = egui::Color32::from_rgb(0x63, 0x66, 0xf1);
            let open = egui::Button::new(egui::RichText::new("Kojalytics Launcher öffnen").color(egui::Color32::WHITE).size(15.0)).fill(accent);
            if ui.add_sized([260.0, 36.0], open).clicked() {
                open_launcher(ui.ctx());
            }
            ui.add_space(8.0);
            if ui.add_sized([260.0, 32.0], egui::Button::new("Lizenz kaufen · kojalytics.com")).clicked() {
                ui.ctx().open_url(egui::OpenUrl::new_tab(SHOP_URL));
            }
        });
    });
}

fn open_launcher(ctx: &egui::Context) {
    #[cfg(target_os = "macos")]
    if std::process::Command::new("/usr/bin/open").args(["-b", LAUNCHER_BUNDLE_ID]).status().is_ok_and(|s| s.success()) {
        return;
    }
    let _ = LAUNCHER_BUNDLE_ID;
    // No launcher installed (or not on macOS): the shop page has the download.
    ctx.open_url(egui::OpenUrl::new_tab(SHOP_URL));
}

fn check() -> Result<(), String> {
    let device = device_hash().ok_or("Die Geräte-ID dieses Computers ist nicht lesbar.")?;
    let path = certificate_path().ok_or("Der Ordner des Kojalytics Launchers wurde nicht gefunden.")?;
    let cert = std::fs::read_to_string(path).map_err(|_| "Auf diesem Computer ist noch keine Lizenz aktiviert.".to_string())?;
    verify(&cert, &device, &PUBLIC_KEY)
}

/// Where the Kojalytics Launcher keeps the certificate (its `Paths::data` / `license.txt`).
fn certificate_path() -> Option<std::path::PathBuf> {
    let home = || std::env::var_os("HOME").map(std::path::PathBuf::from);
    let data = if cfg!(target_os = "macos") {
        home()?.join("Library/Application Support/Kojalytics Launcher")
    } else if cfg!(target_os = "windows") {
        std::path::PathBuf::from(std::env::var_os("LOCALAPPDATA")?).join("Kojalytics Launcher")
    } else {
        std::env::var_os("XDG_DATA_HOME").map(std::path::PathBuf::from).or_else(|| Some(home()?.join(".local/share")))?.join("artcraft-launcher")
    };
    Some(data.join("license.txt"))
}

/// SHA-256 of the machine id, as the launcher computes it.
fn device_hash() -> Option<String> {
    let id = machine_id()?;
    Some(Sha256::digest(format!("kojalytics-device:{id}").as_bytes()).iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(target_os = "macos")]
fn machine_id() -> Option<String> {
    let out = std::process::Command::new("/usr/sbin/ioreg").args(["-rd1", "-c", "IOPlatformExpertDevice"]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find(|l| l.contains("\"IOPlatformUUID\""))?;
    let id = line.rsplit('"').nth(1)?.trim().to_string();
    (!id.is_empty()).then_some(id)
}

#[cfg(target_os = "windows")]
fn machine_id() -> Option<String> {
    let out = std::process::Command::new("reg").args(["query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let id = text.lines().find(|l| l.contains("MachineGuid"))?.split_whitespace().last()?.to_string();
    (!id.is_empty()).then_some(id)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn machine_id() -> Option<String> {
    ["/etc/machine-id", "/var/lib/dbus/machine-id", "/etc/hostid"]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
}

fn verify(certificate: &str, device: &str, public_key: &[u8; 32]) -> Result<(), String> {
    let invalid = || "Die gespeicherte Lizenz ist ungültig. Bitte aktiviere sie im Kojalytics Launcher neu.".to_string();
    let (payload, signature) = certificate.trim().split_once('.').ok_or_else(invalid)?;
    let signature = URL_SAFE_NO_PAD.decode(signature).map_err(|_| invalid())?;
    let signature = Signature::from_slice(&signature).map_err(|_| invalid())?;
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| invalid())?;
    key.verify_strict(payload.as_bytes(), &signature).map_err(|_| invalid())?;
    let json: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).map_err(|_| invalid())?).map_err(|_| invalid())?;
    if json["device"].as_str() != Some(device) {
        return Err("Die Lizenz wurde auf einem anderen Computer aktiviert.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn certificate(signer: &SigningKey, device: &str) -> String {
        let payload = URL_SAFE_NO_PAD.encode(format!(r#"{{"v":1,"license":"abc","hint":"STVWX","device":"{device}","issued":1792000000}}"#));
        format!("{payload}.{}", URL_SAFE_NO_PAD.encode(signer.sign(payload.as_bytes()).to_bytes()))
    }

    #[test]
    fn accepts_only_a_kojalytics_certificate_for_this_device() {
        let signer = SigningKey::from_bytes(&[7; 32]);
        let public = signer.verifying_key().to_bytes();
        assert!(verify(&certificate(&signer, "dev1"), "dev1", &public).is_ok());
        assert!(verify(&certificate(&signer, "dev1"), "dev2", &public).is_err());
        assert!(verify(&certificate(&SigningKey::from_bytes(&[8; 32]), "dev1"), "dev1", &public).is_err());
        assert!(verify("garbage", "dev1", &public).is_err());
    }

    #[test]
    #[ignore = "needs a license activated by the Kojalytics Launcher on this machine"]
    fn this_machine_is_licensed() {
        assert_eq!(check(), Ok(()));
    }

    #[test]
    fn the_built_in_key_and_this_machine_are_usable() {
        assert!(VerifyingKey::from_bytes(&PUBLIC_KEY).is_ok());
        assert_eq!(device_hash().map(|h| h.len()), Some(64));
        assert!(certificate_path().is_some_and(|p| p.ends_with("license.txt")));
    }
}
