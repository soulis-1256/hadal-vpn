fn main() {
    println!("cargo:rustc-check-cfg=cfg(hadal_missing_dist)");
    let dist_dir = std::path::Path::new("../dist");
    println!("cargo:rerun-if-changed={}", dist_dir.display());
    if !dist_dir.exists() {
        println!("cargo:rustc-cfg=hadal_missing_dist");
    }
    tauri_build::build()
}
