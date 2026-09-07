fn main() {
    println!("cargo:rerun-if-env-changed=OXIDE_SE_BOARD");
    println!("cargo:rerun-if-env-changed=OXIDE_SE_DEFAULT_SECURITY_DOMAIN");
    println!("cargo:rerun-if-env-changed=OXIDE_SE_SCP03_PROFILE");
    println!("cargo:rerun-if-env-changed=OXIDE_SE_SCP11_PROFILES");
    println!("cargo:rerun-if-env-changed=OXIDE_SE_SECURE_CHANNEL_MODE");
    println!("cargo:rerun-if-env-changed=OXIDE_SE_ROOT_SECURITY_DOMAIN_AID");
    println!("cargo:rerun-if-env-changed=OXIDE_SE_TRACE");
    println!("cargo:rustc-check-cfg=cfg(oxide_se_board_raspi_pico2)");
    println!("cargo:rustc-check-cfg=cfg(oxide_se_board_mps2_an385)");
    println!("cargo:rustc-check-cfg=cfg(oxide_se_board_olimex_stm32_h405)");
    println!("cargo:rustc-check-cfg=cfg(oxide_se_board_b_l475e_iot01a)");
    println!("cargo:rustc-check-cfg=cfg(oxide_se_board_raspi_pico)");
    println!("cargo:rustc-check-cfg=cfg(oxide_se_target_has_stack_limits)");
    for profile in ["armv6m", "armv7m", "armv8m"] {
        println!("cargo:rustc-check-cfg=cfg(oxide_se_target_{profile})");
    }
    println!("cargo:rustc-check-cfg=cfg(oxide_se_trace_semihosting)");
    println!("cargo:rustc-check-cfg=cfg(oxide_se_trace_jtag)");
    println!("cargo:rustc-check-cfg=cfg(oxide_se_scp03_profile_s16)");
    println!("cargo:rustc-check-cfg=cfg(oxide_se_scp11_profile_a)");
    println!("cargo:rustc-check-cfg=cfg(oxide_se_scp11_profile_b)");
    println!("cargo:rustc-check-cfg=cfg(oxide_se_scp11_profile_c)");

    let board = std::env::var("OXIDE_SE_BOARD").unwrap_or_else(|_| "mps2-an385".to_owned());
    let profile = match board.as_str() {
        "raspi-pico1" => "armv6m",
        "raspi-pico2" => "armv8m",
        _ => "armv7m",
    };
    println!("cargo:rustc-cfg=oxide_se_target_{profile}");
    match board.as_str() {
        "olimex-stm32-h405" => println!("cargo:rustc-cfg=oxide_se_board_olimex_stm32_h405"),
        "b-l475e-iot01a" => println!("cargo:rustc-cfg=oxide_se_board_b_l475e_iot01a"),
        "raspi-pico1" => println!("cargo:rustc-cfg=oxide_se_board_raspi_pico"),
        "raspi-pico2" => {
            println!("cargo:rustc-cfg=oxide_se_board_raspi_pico2");
            println!("cargo:rustc-cfg=oxide_se_target_has_stack_limits");
        }
        _ => println!("cargo:rustc-cfg=oxide_se_board_mps2_an385"),
    }

    match std::env::var("OXIDE_SE_TRACE").as_deref() {
        Ok("none") | Err(_) => {}
        Ok("semihosting") => println!("cargo:rustc-cfg=oxide_se_trace_semihosting"),
        Ok("jtag") if board == "raspi-pico1" => println!("cargo:rustc-cfg=oxide_se_trace_jtag"),
        Ok("jtag") => panic!("OXIDE_SE_TRACE=jtag is only supported on raspi-pico1 for now"),
        Ok(value) => {
            panic!("unsupported OXIDE_SE_TRACE={value}; expected none, semihosting, or jtag")
        }
    }

    if matches!(
        std::env::var("OXIDE_SE_SCP03_PROFILE").as_deref(),
        Ok("S16")
    ) {
        println!("cargo:rustc-cfg=oxide_se_scp03_profile_s16");
    }

    match std::env::var("OXIDE_SE_DEFAULT_SECURITY_DOMAIN").as_deref() {
        Ok("NullSecurityDomain" | "KernelSecurityDomain" | "RustletSecurityDomainProxy")
        | Err(_) => {}
        Ok(value) => panic!(
            "unsupported OXIDE_SE_DEFAULT_SECURITY_DOMAIN={value}; expected NullSecurityDomain, KernelSecurityDomain, or RustletSecurityDomainProxy"
        ),
    }

    match std::env::var("OXIDE_SE_SCP03_PROFILE").as_deref() {
        Ok("S8" | "S16") | Err(_) => {}
        Ok(value) => panic!("unsupported OXIDE_SE_SCP03_PROFILE={value}; expected S8 or S16"),
    }

    let scp11_profiles = std::env::var("OXIDE_SE_SCP11_PROFILES").unwrap_or_else(|_| "C".into());
    for profile in scp11_profiles
        .split(',')
        .filter(|profile| !profile.is_empty())
    {
        match profile {
            "A" => println!("cargo:rustc-cfg=oxide_se_scp11_profile_a"),
            "B" => println!("cargo:rustc-cfg=oxide_se_scp11_profile_b"),
            "C" => println!("cargo:rustc-cfg=oxide_se_scp11_profile_c"),
            value => panic!(
                "unsupported OXIDE_SE_SCP11_PROFILES entry {value}; expected comma-separated A, B, C"
            ),
        }
    }

    match std::env::var("OXIDE_SE_SECURE_CHANNEL_MODE").as_deref() {
        Ok(
            "None"
            | "Identity"
            | "Scp03Only"
            | "Scp11Only"
            | "Scp03AndScp11"
            | "Scp11cOnly"
            | "Scp03AndScp11c",
        )
        | Err(_) => {}
        Ok(value) => panic!(
            "unsupported OXIDE_SE_SECURE_CHANNEL_MODE={value}; expected None, Identity, Scp03Only, Scp11Only, Scp03AndScp11, or legacy Scp11cOnly/Scp03AndScp11c"
        ),
    }
}
