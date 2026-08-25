uniffi::setup_scaffolding!();

/// Scaffold probe; replaced by the real API.
#[uniffi::export]
pub fn bhwi_ffi_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
