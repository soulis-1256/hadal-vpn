#[cfg(all(not(test), any(dev, not(hadal_missing_dist))))]
fn main() {
    // Work around WebKitGTK Wayland partial-tile/DMA-BUF compositing bugs unless overridden
    if std::env::var_os("WEBKIT_DISABLE_COMPOSITING_MODE").is_none() {
        std::env::set_var("WEBKIT_DISABLE_COMPOSITING_MODE", "1");
    }
    if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
        std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
    }
    hadal_gui_lib::run_with_context(tauri::generate_context!());
}

#[cfg(not(all(not(test), any(dev, not(hadal_missing_dist)))))]
fn main() {
    #[cfg(not(test))]
    {
        eprintln!(
            "hadal-gui built without ../dist; run `bun run build` in crates/hadal-gui first"
        );
        std::process::exit(1);
    }
}
