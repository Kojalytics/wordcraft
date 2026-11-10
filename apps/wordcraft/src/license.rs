//! Kojalytics license check. The app opens its documents only on a computer where the Kojalytics
//! Launcher has activated a license key (Settings › License): the launcher saves a certificate,
//! signed by Kojalytics, for this machine; the app checks the signature and the machine offline.
//! Until then it shows a lock screen instead, and checks again every few seconds.
//!
//! Shared verbatim by WordKoja, GridKoja and DeckKoja (`apps/<app>/src/license.rs`).

use std::sync::{Mutex, OnceLock, PoisonError};
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
const SHOP_URL: &str = "https://www.kojalytics.com/software#preise";
const TRIAL_ENDED: &str = "Dein kostenloser 3-Tage-Test ist abgelaufen.";
const LAUNCHER_BUNDLE_ID: &str = "com.kojalytics.artcraft-launcher";
const RECHECK: Duration = Duration::from_secs(3);

struct State {
    licensed: bool,
    /// When a free trial ends (Unix seconds); `None` for a license.
    until: Option<u64>,
    reason: String,
    checked: Option<Instant>,
}

static STATE: Mutex<State> = Mutex::new(State { licensed: false, until: None, reason: String::new(), checked: None });

/// `true` when the app may show its documents; otherwise draws the lock screen into `ui`.
pub fn gate(ui: &mut egui::Ui) -> bool {
    let mut state = STATE.lock().unwrap_or_else(PoisonError::into_inner);
    // A trial ends while the app is open, too.
    if state.licensed && state.until.is_some_and(|until| unix_now() >= until) {
        state.licensed = false;
        state.checked = None;
    }
    if !state.licensed && state.checked.is_none_or(|t| t.elapsed() >= RECHECK) {
        match check() {
            Ok(until) => {
                state.licensed = true;
                state.until = until;
            }
            Err(e) => state.reason = e,
        }
        state.checked = Some(Instant::now());
    }
    if state.licensed {
        if state.until.is_some() {
            ui.ctx().request_repaint_after(Duration::from_secs(60));
        }
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
            let ended = reason == TRIAL_ENDED;
            let title = if ended { "Test abgelaufen" } else { "Lizenz erforderlich" };
            ui.label(egui::RichText::new(title).size(28.0).strong().color(egui::Color32::WHITE));
            ui.add_space(8.0);
            ui.label(egui::RichText::new(reason).color(egui::Color32::from_rgb(0xa5, 0xb4, 0xfc)));
            ui.add_space(14.0);
            ui.label(
                egui::RichText::new(if ended {
                    "Kaufe eine Lizenz auf kojalytics.com und aktiviere sie im Kojalytics Launcher unter Einstellungen › Lizenz.\nDiese App entsperrt sich danach automatisch."
                } else {
                    "Starte im Kojalytics Launcher unter Einstellungen › Lizenz den kostenlosen 3-Tage-Test\noder aktiviere deinen Lizenzschlüssel. Diese App entsperrt sich danach automatisch."
                })
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
    #[cfg(target_os = "windows")]
    if let Some(exe) = launcher_exe() {
        if std::process::Command::new(exe).spawn().is_ok() {
            return;
        }
    }
    let _ = LAUNCHER_BUNDLE_ID;
    // No launcher installed (or on Linux): the shop page has the download.
    ctx.open_url(egui::OpenUrl::new_tab(SHOP_URL));
}

/// The Kojalytics Launcher's exe on Windows: in the folder its installer recorded, or its default.
#[cfg(target_os = "windows")]
fn launcher_exe() -> Option<std::path::PathBuf> {
    let recorded = reg_value(r"HKCU\Software\Kojalytics\Kojalytics Launcher", "InstallDir").map(std::path::PathBuf::from);
    let default = std::env::var_os("LOCALAPPDATA").map(|d| std::path::PathBuf::from(d).join("Programs").join("Kojalytics Launcher"));
    [recorded, default].into_iter().flatten().map(|d| d.join("artcraft-launcher.exe")).find(|p| p.is_file())
}

/// One registry value, read with reg.exe (`    Name    REG_SZ    value`).
#[cfg(target_os = "windows")]
fn reg_value(key: &str, name: &str) -> Option<String> {
    use std::os::windows::process::CommandExt;
    // reg.exe is a console program: without CREATE_NO_WINDOW a console window flashes up.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new("reg").args(["query", key, "/v", name]).creation_flags(CREATE_NO_WINDOW).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find(|l| l.trim_start().starts_with(name))?;
    let value = line.split_once("REG_")?.1.split_once(char::is_whitespace)?.1.trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// `Ok(None)` with a license, `Ok(Some(end))` during a free trial, otherwise why not.
fn check() -> Result<Option<u64>, String> {
    let device = device_hash().ok_or("Die Geräte-ID dieses Computers ist nicht lesbar.")?;
    let path = certificate_path().ok_or("Der Ordner des Kojalytics Launchers wurde nicht gefunden.")?;
    let license = std::fs::read_to_string(&path).ok().map(|cert| verify(&cert, &device, &PUBLIC_KEY));
    if let Some(Ok(())) = license {
        return Ok(None);
    }
    // The launcher saves a free trial's certificate next to the license.
    if let Ok(cert) = std::fs::read_to_string(path.with_file_name("trial.txt")) {
        return verify_trial(&cert, &device, &PUBLIC_KEY, unix_now()).map(Some);
    }
    match license {
        Some(Err(e)) => Err(e),
        _ => Err("Auf diesem Computer ist noch keine Lizenz aktiviert.".into()),
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
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

/// SHA-256 of the machine id, as the launcher computes it. Read once: the lock screen checks again
/// every few seconds.
fn device_hash() -> Option<String> {
    static DEVICE: OnceLock<Option<String>> = OnceLock::new();
    DEVICE
        .get_or_init(|| {
            let id = machine_id()?;
            Some(Sha256::digest(format!("kojalytics-device:{id}").as_bytes()).iter().map(|b| format!("{b:02x}")).collect())
        })
        .clone()
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
    reg_value(r"HKLM\SOFTWARE\Microsoft\Cryptography", "MachineGuid")
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn machine_id() -> Option<String> {
    ["/etc/machine-id", "/var/lib/dbus/machine-id", "/etc/hostid"]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
}

fn verify(certificate: &str, device: &str, public_key: &[u8; 32]) -> Result<(), String> {
    let json = signed_json(certificate, public_key).ok_or("Die gespeicherte Lizenz ist ungültig. Bitte aktiviere sie im Kojalytics Launcher neu.")?;
    if json["device"].as_str() != Some(device) {
        return Err("Die Lizenz wurde auf einem anderen Computer aktiviert.".into());
    }
    Ok(())
}

/// A free trial's certificate: the end of the trial while it runs. Trial certificates name the
/// machine `trial_device`, so [`verify`] (and apps from before trials) never accept one as a license.
fn verify_trial(certificate: &str, device: &str, public_key: &[u8; 32], now: u64) -> Result<u64, String> {
    let invalid = "Der gespeicherte Test ist ungültig. Bitte starte ihn im Kojalytics Launcher neu.";
    let json = signed_json(certificate, public_key).ok_or(invalid)?;
    if json["trial_device"].as_str() != Some(device) {
        return Err("Der Test wurde auf einem anderen Computer gestartet.".into());
    }
    let (Some(starts), Some(expires)) = (json["starts"].as_u64(), json["expires"].as_u64()) else { return Err(invalid.into()) };
    // A clock set back by more than a day before the trial began doesn't stretch it.
    if now + 86_400 < starts {
        return Err("Datum und Uhrzeit dieses Computers stimmen nicht. Bitte stelle sie richtig ein.".into());
    }
    if now >= expires {
        return Err(TRIAL_ENDED.into());
    }
    Ok(expires)
}

/// The JSON payload of a certificate signed by Kojalytics (`payload.signature`, both base64url).
fn signed_json(certificate: &str, public_key: &[u8; 32]) -> Option<serde_json::Value> {
    let (payload, signature) = certificate.trim().split_once('.')?;
    let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(signature).ok()?).ok()?;
    VerifyingKey::from_bytes(public_key).ok()?.verify_strict(payload.as_bytes(), &signature).ok()?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()
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

    fn signed(signer: &SigningKey, json: &str) -> String {
        let payload = URL_SAFE_NO_PAD.encode(json);
        format!("{payload}.{}", URL_SAFE_NO_PAD.encode(signer.sign(payload.as_bytes()).to_bytes()))
    }

    #[test]
    fn a_trial_unlocks_this_device_until_it_ends_and_never_passes_as_a_license() {
        let signer = SigningKey::from_bytes(&[7; 32]);
        let public = signer.verifying_key().to_bytes();
        let trial = signed(&signer, r#"{"v":1,"trial":true,"trial_device":"dev1","starts":1000000,"expires":1259200,"issued":1000000}"#);
        assert_eq!(verify_trial(&trial, "dev1", &public, 1000100), Ok(1259200));
        assert_eq!(verify_trial(&trial, "dev1", &public, 1259200), Err(TRIAL_ENDED.to_string()));
        assert!(verify_trial(&trial, "dev2", &public, 1000100).is_err());
        assert!(verify_trial(&trial, "dev1", &public, 1000000 - 2 * 86_400).is_err());
        assert!(verify_trial(&signed(&SigningKey::from_bytes(&[8; 32]), r#"{"trial_device":"dev1","starts":1,"expires":9999999999}"#), "dev1", &public, 2).is_err());
        assert!(verify(&trial, "dev1", &public).is_err());
        assert!(verify_trial(&certificate(&signer, "dev1"), "dev1", &public, 1000100).is_err());
    }

    #[test]
    #[ignore = "needs a license activated by the Kojalytics Launcher on this machine"]
    fn this_machine_is_licensed() {
        assert_eq!(check(), Ok(None));
    }

    #[test]
    fn the_built_in_key_and_this_machine_are_usable() {
        assert!(VerifyingKey::from_bytes(&PUBLIC_KEY).is_ok());
        assert_eq!(device_hash().map(|h| h.len()), Some(64));
        assert!(certificate_path().is_some_and(|p| p.ends_with("license.txt")));
    }
}
