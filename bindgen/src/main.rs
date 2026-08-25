//! Thin wrapper around uniffi's own bindgen CLI, so the generator version always
//! matches the `uniffi` version the scaffolding was compiled with.
fn main() {
    uniffi::uniffi_bindgen_main()
}
