{
  description = "bhwi-ffi: UniFFI bindings for BHWI";

  inputs = {
    # Same nixpkgs rev motd uses: androidenv there is known-good on this setup.
    nixpkgs.url = "github:NixOS/nixpkgs/767b0d3ec98a143ad9ed7dfc0d5553510ac27133";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ rust-overlay.overlays.default ];
        pkgs = import nixpkgs {
          inherit system overlays;
          config = {
            allowUnfree = true;
            android_sdk.accept_license = true;
          };
        };
        rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        ndkVersion = "28.2.13676358";
        androidComposition = pkgs.androidenv.composeAndroidPackages {
          platformVersions = [ "35" ];
          buildToolsVersions = [ "35.0.0" ];
          platformToolsVersion = "35.0.2";
          includeNDK = true;
          ndkVersions = [ ndkVersion ];
          includeEmulator = false;
          includeSystemImages = false;
        };
        androidSdk = androidComposition.androidsdk;
        sdkRoot = "${androidSdk}/libexec/android-sdk";
        # Opt-in emulator closure for the x86_64 instrumentation test loop.
        emulatorComposition = pkgs.androidenv.composeAndroidPackages {
          platformVersions = [ "34" ];
          buildToolsVersions = [ ];
          platformToolsVersion = "35.0.2";
          includeEmulator = true;
          includeSystemImages = true;
          systemImageTypes = [ "default" ];
          abiVersions = [ "x86_64" ];
        };
        emulatorSdk = emulatorComposition.androidsdk;
        emulatorSdkRoot = "${emulatorSdk}/libexec/android-sdk";
      in {
        devShells.default = pkgs.mkShell {
          packages = [
            rust
            pkgs.rust-analyzer
            pkgs.cargo-ndk
            pkgs.jdk21
            androidSdk
            # tools/check.sh inspects the AAR.
            pkgs.unzip
          ];
          JAVA_HOME = pkgs.jdk21.home;
          ANDROID_HOME = sdkRoot;
          ANDROID_SDK_ROOT = sdkRoot;
          ANDROID_NDK_HOME = "${sdkRoot}/ndk/${ndkVersion}";
          ANDROID_NDK_ROOT = "${sdkRoot}/ndk/${ndkVersion}";
          # AGP's downloaded aapt2 is dynamically linked and won't run on NixOS.
          GRADLE_OPTS = "-Dorg.gradle.project.android.aapt2FromMavenOverride=${sdkRoot}/build-tools/35.0.0/aapt2 -Dorg.gradle.workers.max=2";
        };
        devShells.emulator = pkgs.mkShell {
          packages = [ pkgs.jdk21 emulatorSdk ];
          JAVA_HOME = pkgs.jdk21.home;
          ANDROID_HOME = emulatorSdkRoot;
          ANDROID_SDK_ROOT = emulatorSdkRoot;
          LANG = "C.UTF-8";
          LC_ALL = "C.UTF-8";
        };
      });
}
