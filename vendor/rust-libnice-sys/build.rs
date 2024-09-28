extern crate bindgen;
extern crate pkg_config;

use std::env;
use std::path::PathBuf;

fn main() {
    let libnice = pkg_config::Config::new()
        .atleast_version("0.1.0")
        .probe("nice")
        .expect("Failed to find (lib)nice using pkg-config!");

    let bindings = bindgen::Builder::default()
        .header_contents(
            "wrapper.h",
            "#include <nice/agent.h>
             #include <nice/interfaces.h>

             #include <stun/stunagent.h>
             #include <stun/stunmessage.h>
             #include <stun/constants.h>
             #include <stun/usages/bind.h>
             #include <stun/usages/ice.h>
             #include <stun/usages/turn.h>
             #include <stun/usages/timer.h>

             #include <nice/pseudotcp.h>",
        )
        // ICE Library
        .allowlist_function("nice_.+")
        .allowlist_type("NICE.+")
        .allowlist_type("_?Nice.+")
        .allowlist_type("_?TurnServer")
        // STUN Library
        .allowlist_function("stun_.+")
        .allowlist_type("STUN.+")
        .allowlist_type("TURN.+")
        .allowlist_type("_?[Ss]tun.+")
        // contains `va_list` type argument which seems like it might not be handled properly
        .opaque_type("StunDebugHandler")
        // Pseudo TCP Socket implementation
        .allowlist_function("pseudo_tcp_.+")
        .allowlist_type("_?PseudoTcp.+")
        // Disable recursive allowlisting, we're using libc, glib-sys, etc.
        .allowlist_recursively(false)
        .clang_args(
            libnice
                .include_paths
                .iter()
                .map(|path| format!("-I{}", path.to_string_lossy())),
        )
        .generate()
        .expect("Unable to generate bindings");
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
