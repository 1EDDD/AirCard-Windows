#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod afc;
mod airlift;
mod airtraffic;
mod app;
mod apple;
mod device;
mod flasher;
mod image_skin;
mod passthm;
mod scanner;
mod wireless;

fn startup_log(message: &str) {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let _ = std::fs::write(dir.join("aircard-startup.log"), format!("{message}\n"));
        }
    }
}

fn main() -> eframe::Result<()> {
    std::panic::set_hook(Box::new(|info| {
        startup_log(&format!("AirCard startup panic: {info}"));
    }));
    startup_log("AirCard starting...");

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([960.0, 620.0])
            .with_min_inner_size([850.0, 560.0])
            .with_title("AirCard v1.2.1"),
        ..Default::default()
    };

    let result = eframe::run_native(
        "AirCard v1.2.1",
        options,
        Box::new(|cc| Ok(Box::new(app::AirCardApp::new(cc)))),
    );

    startup_log(&format!("AirCard exited: {result:?}"));
    result
}
