//! gp scenario operations and assertions, shared by individual tests and campaigns.
use super::*;

/// End a porting probe on the kernel authority, never on an application AID.
/// SELECT followed by a clear read also proves liveness after replay/session
/// error handling. The full scenarios keep their application sequence intact.
fn finish_kernel_scp_probe(
    client: &mut ApduClient,
    log_prefix: &str,
    total: usize,
) -> Result<usize, Box<dyn Error>> {
    eprintln!("{log_prefix}: kernel-only scope, reselect root SD and verify liveness");
    expect_status(
        client.exchange(&CommandBuilder::select(root_security_domain_aid()))?,
        (0x90, 0x00),
        "kernel SCP root SELECT",
    )?;
    expect_response(
        client.exchange(&CommandBuilder::gp_get_data(0x9f70, 4))?,
        &[0x9f, 0x70, 0x01, 0x07],
        (0x90, 0x00),
        "kernel SCP liveness after session",
    )?;
    Ok(total + 2)
}

/// Runs the aggregate kernel Security Domain regression campaign.
///
/// This is intentionally a coarse smoke of the three kernel-owned management
/// policies: clear-channel development mode (`NullSecurityDomain`), SCP03 over
/// `KernelSecurityDomain`, and SCP11a/SCP11b/SCP11c over
/// `KernelSecurityDomain`. It is useful as a quick cross-policy gate; detailed
/// protocol coverage lives in the dedicated `test gp_noscp`, `test gp_scp03`,
/// `test gp_scp11a`, `test gp_scp11b`, and `test gp_scp11c` commands.
pub(crate) fn run_security_domain_test_for_board(
    ctx: &TestContext,
    image_format: LayoutImageFormat,
    board: &str,
) -> Result<TestReport, Box<dyn Error>> {
    let null_total = run_noscp_test_for_board(ctx, image_format, board)?.total;
    let scp03_total = run_scp03_test_for_board(
        ctx,
        image_format,
        board,
        HostScp03Selection::Single(HostScp03Profile::S8),
    )?
    .total;
    let scp11a_total = run_with_build_config(ctx, "configs/config_scp11a_test.toml", |ctx| {
        run_scp11a_test_for_board(ctx, image_format, board)
    })?
    .total;
    let scp11b_total = run_with_build_config(ctx, "configs/config_scp11b_test.toml", |ctx| {
        run_scp11b_test_for_board(ctx, image_format, board)
    })?
    .total;
    let scp11c_total = run_with_build_config(ctx, "configs/config_scp11c_test.toml", |ctx| {
        run_scp11c_test_for_board(ctx, image_format, board)
    })?
    .total;
    let scp11ac_discovery_total =
        run_with_build_config(ctx, "configs/config_scp11ac_test.toml", |ctx| {
            run_kernel_discovery_profile_test(
                ctx,
                image_format,
                board,
                rustlet_runtime::gp::SecurityDomainCapabilities {
                    scp03_s8: false,
                    scp03_s16: false,
                    scp11a: true,
                    scp11b: false,
                    scp11c: true,
                },
                "security-domain-scp11ac-discovery",
            )
        })?;
    Ok(TestReport::passed(
        null_total
            + scp03_total
            + scp11a_total
            + scp11b_total
            + scp11c_total
            + scp11ac_discovery_total,
    ))
}

pub(crate) fn run_kernel_discovery_profile_test(
    ctx: &TestContext,
    image_format: LayoutImageFormat,
    board: &str,
    capabilities: rustlet_runtime::gp::SecurityDomainCapabilities,
    log_prefix: &str,
) -> Result<usize, Box<dyn Error>> {
    let board = board_spec(board)?;

    testing::target::run_apdu(
        ctx,
        board,
        image_format,
        log_prefix,
        APDU_RESPONSE_TIMEOUT,
        |client| validate_gp_discovery(client, log_prefix, capabilities),
    )
}

/// Validates the declarative supplementary Security Domain manifest path.
///
/// The image contains one restricted Issuer `NullSecurityDomain` below the
/// technical root. The test proves that both the Issuer SD and its contained Rustlet instance were
/// installed during bootstrap, that the child cannot escape to the root
/// authority, and that its contained package and preinstalled instance are
/// usable without any runtime `INSTALL`.
pub(crate) fn run_predeployment_test_for_board(
    ctx: &TestContext,
    image_format: LayoutImageFormat,
    board: &str,
) -> Result<TestReport, Box<dyn Error>> {
    let board = board_spec(board)?;
    let test_result = testing::target::run_apdu(
        ctx,
        board,
        image_format,
        "predeployment",
        APDU_RESPONSE_TIMEOUT,
        |client| {
            let log_prefix = "predeployment";

            eprintln!("{log_prefix}: GET STATUS returns the declared Issuer Security Domain");
            expect_get_status_record(
                &client.exchange(&CommandBuilder::gp_get_status(0x80, false, &[]))?,
                predeployed_child_security_domain_instance_aid(),
                true,
                "predeployment Issuer Security Domain",
            )?;

            eprintln!("{log_prefix}: select Issuer Security Domain");
            expect_status(
                client.exchange(&CommandBuilder::select(
                    predeployed_child_security_domain_instance_aid(),
                ))?,
                (0x90, 0x00),
                "predeployment Issuer Security Domain",
            )?;

            eprintln!("{log_prefix}: child cannot select the root security domain");
            expect_status(
                client.exchange(&CommandBuilder::select(kernel_security_domain_package_aid()))?,
                (0x6A, 0x82),
                "predeployment child cannot escape to root",
            )?;

            eprintln!("{log_prefix}: select child-owned preinstalled minimal instance");
            expect_status(
                client.exchange(&CommandBuilder::select(
                    crate_rustlet_minimal_valid_test_instance_c_aid(),
                ))?,
                (0x90, 0x00),
                "predeployment child-owned minimal instance",
            )?;
            let minimal_total = run_minimal_valid_post_select_apdus(client, log_prefix, false)?;

            Ok(4 + minimal_total)
        },
    );
    test_result.map(TestReport::passed)
}

/// Runs clear-channel registry APDUs without opening a secure channel.
///
/// This isolates the polymorphic registry from SCP03/SCP11 framing: DATA, KEY
/// and INSTANCE objects are created, queried where applicable, replaced, and
/// deleted through ordinary APDUs under the development `NullSecurityDomain`.
pub(crate) fn run_registry_test_for_board(
    ctx: &TestContext,
    image_format: LayoutImageFormat,
    board: &str,
) -> Result<TestReport, Box<dyn Error>> {
    let board = board_spec(board)?;
    let test_result = testing::target::run_apdu(
        ctx,
        board,
        image_format,
        "run_registry_test_for_board",
        APDU_RESPONSE_TIMEOUT,
        |client| {
            let log_prefix = "registry";
            run_clear_registry_access_apdus(client, log_prefix)
        },
    );
    test_result.map(TestReport::passed)
}

/// Runs every GP-focused regression that is meaningful for one board/backend.
///
/// This deliberately stays separate from `test rustlet_all`: Rustlet tests
/// prove application ABI behavior, while this campaign chains management,
/// secure-channel, registry, predeployment, and dynamic LOAD paths. Persistent
/// flash replay uses either QEMU Pico1's backing file or physical OpenOCD flash.
pub(crate) fn run_gp_all_test_for_board(
    ctx: &TestContext,
    image_format: LayoutImageFormat,
    board: &str,
) -> Result<TestReport, Box<dyn Error>> {
    let board_spec = board_spec(board)?;
    let mut total = 0usize;

    eprintln!("gp-all: no-SCP management");
    total += run_with_build_config(ctx, "configs/config_noscp_test.toml", |ctx| {
        run_noscp_test_for_board(ctx, image_format, board)
    })?
    .total;

    eprintln!("gp-all: SCP03 S8/S16 management");
    total += run_with_build_config(ctx, "configs/config_scp03_test.toml", |ctx| {
        run_scp03_test_for_board(ctx, image_format, board, HostScp03Selection::All)
    })?
    .total;

    eprintln!("gp-all: SCP11a management");
    total += run_with_build_config(ctx, "configs/config_scp11a_test.toml", |ctx| {
        run_scp11a_test_for_board(ctx, image_format, board)
    })?
    .total;

    eprintln!("gp-all: SCP11b management");
    total += run_with_build_config(ctx, "configs/config_scp11b_test.toml", |ctx| {
        run_scp11b_test_for_board(ctx, image_format, board)
    })?
    .total;

    eprintln!("gp-all: SCP11c management");
    total += run_with_build_config(ctx, "configs/config_scp11c_test.toml", |ctx| {
        run_scp11c_test_for_board(ctx, image_format, board)
    })?
    .total;

    eprintln!("gp-all: predeployment manifest");
    total += run_with_build_config(ctx, "configs/config_predeployment_test.toml", |ctx| {
        run_predeployment_test_for_board(ctx, image_format, board)
    })?
    .total;

    eprintln!("gp-all: clear registry access");
    total += run_with_build_config(ctx, "configs/config_gp_registry_test.toml", |ctx| {
        run_registry_test_for_board(ctx, image_format, board)
    })?
    .total;

    eprintln!("gp-all: Rustlet Security Domain over SCP03");
    total += run_with_build_config(
        ctx,
        "configs/config_rustlet_security_domain_scp03_test.toml",
        |ctx| run_rustlet_security_domain_test_for_board(ctx, image_format, board),
    )?
    .total;

    eprintln!("gp-all: delegated SCP03 with no kernel SCP profile");
    total += run_with_build_config(
        ctx,
        "configs/config_rustlet_security_domain_delegated_scp03_test.toml",
        |ctx| run_rustlet_security_domain_test_for_board(ctx, image_format, board),
    )?
    .total;

    eprintln!("gp-all: Rustlet Security Domain over SCP11a");
    total += run_with_build_config(
        ctx,
        "configs/config_rustlet_security_domain_scp11a_test.toml",
        |ctx| run_rustlet_security_domain_scp11a_test_for_board(ctx, image_format, board),
    )?
    .total;

    eprintln!("gp-all: Rustlet Security Domain over SCP11b");
    total += run_with_build_config(
        ctx,
        "configs/config_rustlet_security_domain_scp11b_test.toml",
        |ctx| run_rustlet_security_domain_scp11b_test_for_board(ctx, image_format, board),
    )?
    .total;

    eprintln!("gp-all: Rustlet Security Domain over SCP11c");
    total += run_with_build_config(
        ctx,
        "configs/config_rustlet_security_domain_scp11c_test.toml",
        |ctx| run_rustlet_security_domain_scp11c_test_for_board(ctx, image_format, board),
    )?
    .total;

    if image_format != LayoutImageFormat::Elf {
        eprintln!("gp-all: skip dynamic LOAD and persistence for non-ELF kernel image");
        return Ok(TestReport::passed(total));
    }

    if ctx.openocd().is_some() || board_spec.env_name == "raspi-pico1" {
        eprintln!("gp-all: SCP03 dynamic INSTALL [for load] / LOAD");
        total += run_with_build_config(ctx, "configs/config_scp03_test.toml", |ctx| {
            run_scp03_install_load_test_for_board(ctx, board)
        })?
        .total;

        eprintln!("gp-all: SCP11a dynamic INSTALL [for load] / LOAD");
        total += run_with_build_config(ctx, "configs/config_scp11a_test.toml", |ctx| {
            run_kernel_security_domain_scp11_load_persistence_test_for_board(ctx, board)
        })?;

        eprintln!("gp-all: persistent registry replay");
        total += run_with_build_config(ctx, "configs/config_gp_persistence_test.toml", |ctx| {
            run_persistence_test_for_board(ctx, board)
        })?
        .total;
    } else {
        eprintln!(
            "gp-all: skip dynamic LOAD and persistent registry replay on {} (requires raspi-pico1 flash-file)",
            board_spec.env_name
        );
    }

    Ok(TestReport::passed(total))
}

/// Validates clear-channel GP management under `NullSecurityDomain`.
///
/// Checks lifecycle and capability discovery, GET STATUS, and rejection of
/// INITIALIZE UPDATE by a domain that offers no secure channel. Installation
/// and Rustlet execution are covered separately by the Rustlet scenarios.
pub(crate) fn run_noscp_test_for_board(
    ctx: &TestContext,
    image_format: LayoutImageFormat,
    board: &str,
) -> Result<TestReport, Box<dyn Error>> {
    Ok(TestReport::passed(run_security_domain_profile_test(
        ctx,
        image_format,
        board,
        "NullSecurityDomain",
        HostScp03Profile::S8,
        "security-domain-null",
    )?))
}

/// Runs one or both SCP03 GlobalPlatform regression profiles.
///
/// `HostScp03Selection::Single` validates one MAC-size profile (`S8` or `S16`);
/// `All` runs both profiles sequentially. The command line deliberately
/// requires an explicit selection so routine debugging does not rebuild and run
/// both profiles by accident.
pub(crate) fn run_scp03_test_for_board(
    ctx: &TestContext,
    image_format: LayoutImageFormat,
    board: &str,
    scp03_selection: HostScp03Selection,
) -> Result<TestReport, Box<dyn Error>> {
    let total = match scp03_selection {
        HostScp03Selection::Single(profile) => {
            run_single_scp03_test_for_board(ctx, image_format, board, profile)?
        }
        HostScp03Selection::All => {
            run_single_scp03_test_for_board(ctx, image_format, board, HostScp03Profile::S8)?
                + run_single_scp03_test_for_board(ctx, image_format, board, HostScp03Profile::S16)?
        }
    };
    Ok(TestReport::passed(total))
}

pub(crate) fn run_single_scp03_test_for_board(
    ctx: &TestContext,
    image_format: LayoutImageFormat,
    board: &str,
    scp03_profile: HostScp03Profile,
) -> Result<usize, Box<dyn Error>> {
    run_security_domain_profile_test(
        ctx,
        image_format,
        board,
        "KernelSecurityDomain",
        scp03_profile,
        &format!("security-domain-kernel-{}", scp03_profile.log_suffix()),
    )
}

/// Runs the SCP11c GlobalPlatform regression against the kernel authority.
///
/// The scenario covers PSO/authentication sequencing, protected management
/// commands, key rotation interactions with SCP03 material, and replay/stale
/// rejection behavior reachable through the QEMU APDU transport.
pub(crate) fn run_scp11c_test_for_board(
    ctx: &TestContext,
    image_format: LayoutImageFormat,
    board: &str,
) -> Result<TestReport, Box<dyn Error>> {
    let board = board_spec(board)?;
    let test_result = testing::target::run_apdu(
        ctx,
        board,
        image_format,
        "security-domain-scp11c",
        APDU_RESPONSE_TIMEOUT,
        |client| {
            let log_prefix = "security-domain-scp11c";

            eprintln!("{log_prefix}: GET DATA lifecycle");
            expect_response(
                client.exchange(&CommandBuilder::gp_get_data(0x9f70, 0x04))?,
                &[0x9f, 0x70, 0x01, 0x07],
                (0x90, 0x00),
                "scp11c kernel GET DATA lifecycle",
            )?;
            let discovery_total = validate_gp_discovery(
                client,
                log_prefix,
                rustlet_runtime::gp::SecurityDomainCapabilities {
                    scp03_s8: false,
                    scp03_s16: false,
                    scp11a: false,
                    scp11b: false,
                    scp11c: true,
                },
            )?;

            let host_static_secret_bytes = [
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E,
                0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
                0x4D, 0x4E, 0x4F, 0x50,
            ];
            let host_ephemeral_secret_bytes = [
                0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
                0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
                0x3D, 0x3E, 0x3F, 0x41,
            ];
            let host_static_secret = SecretKey::from_slice(&host_static_secret_bytes)
                .map_err(|_| "scp11c: invalid host static private key")?;
            let host_static_public = host_static_secret.public_key().to_encoded_point(false);
            let host_secret = SecretKey::from_slice(&host_ephemeral_secret_bytes)
                .map_err(|_| "scp11c: invalid host ephemeral private key")?;
            let host_public = host_secret.public_key().to_encoded_point(false);
            let host_certificate = build_dev_oce_certificate(host_static_public.as_bytes())?;

            eprintln!("{log_prefix}: SCP11a MUTUAL AUTHENTICATE is rejected on SCP11c path");
            expect_status(
                client.exchange(&CommandBuilder::scp11a_mutual_authenticate(
                    0x00,
                    0x01,
                    host_public.as_bytes(),
                ))?,
                (0x6D, 0x00),
                "scp11c path rejects mismatched scp11a mutual authenticate",
            )?;

            eprintln!("{log_prefix}: SCP11c MUTUAL AUTHENTICATE rejected before PSO");
            expect_status(
                client.exchange(&CommandBuilder::scp11c_mutual_authenticate(
                    0x00,
                    0x01,
                    host_public.as_bytes(),
                ))?,
                (0x69, 0x85),
                "scp11c mutual authenticate before perform security operation",
            )?;

            eprintln!("{log_prefix}: SCP11c PERFORM SECURITY OPERATION");
            expect_status(
                client.exchange(&CommandBuilder::scp11c_perform_security_operation(
                    0x00,
                    0x00,
                    &host_certificate,
                ))?,
                (0x90, 0x00),
                "scp11c perform security operation",
            )?;

            eprintln!("{log_prefix}: SCP11c PERFORM SECURITY OPERATION again");
            expect_status(
                client.exchange(&CommandBuilder::scp11c_perform_security_operation(
                    0x00,
                    0x00,
                    &host_certificate,
                ))?,
                (0x90, 0x00),
                "scp11c perform security operation repeated",
            )?;

            eprintln!(
            "{log_prefix}: SCP11c protected GET DATA rejected after PSO and before authentication"
        );
            expect_status(
                client.exchange(&OwnedT0Command {
                    cla: 0x84,
                    ins: 0xCA,
                    p1: 0x9f,
                    p2: 0x70,
                    lc: 0,
                    le: 41,
                    data: Vec::new(),
                })?,
                (0x69, 0x85),
                "scp11c protected GET DATA before mutual authenticate",
            )?;

            eprintln!(
                "{log_prefix}: SCP11c PERFORM SECURITY OPERATION rejects malformed certificate"
            );
            let mut malformed_certificate = host_certificate.clone();
            let last = malformed_certificate
                .last_mut()
                .ok_or("scp11c malformed certificate: empty certificate")?;
            *last ^= 0x01;
            expect_status(
                client.exchange(&CommandBuilder::scp11c_perform_security_operation(
                    0x00,
                    0x00,
                    &malformed_certificate,
                ))?,
                (0x66, 0x00),
                "scp11c perform security operation malformed certificate",
            )?;

            eprintln!("{log_prefix}: SCP11c MUTUAL AUTHENTICATE rejects malformed TLV");
            expect_status(
                client.exchange(&CommandBuilder::scp11c_mutual_authenticate_raw(
                    0x00,
                    0x01,
                    host_public.as_bytes(),
                ))?,
                (0x6A, 0x80),
                "scp11c mutual authenticate malformed tlv",
            )?;

            for qualifier in [
                SCP11_KEY_USAGE_MACS,
                SCP11C_KEY_USAGE_COMMAND_ONLY,
                SCP11C_KEY_USAGE_COMMAND_ENC_RESPONSE_MAC,
            ] {
                eprintln!(
                    r#"{log_prefix}: SCP11c MUTUAL AUTHENTICATE rejects profiled-out key usage "{qualifier:02X}""#
                );
                expect_status(
                    client.exchange(&CommandBuilder::scp11_mutual_authenticate_with_usage(
                        0x00,
                        0x01,
                        SCP11C_IDENTIFIER_PARAM,
                        qualifier,
                        host_public.as_bytes(),
                    ))?,
                    (0x6A, 0x80),
                    "scp11c profiled-out key usage",
                )?;
            }

            eprintln!("{log_prefix}: SCP11c MUTUAL AUTHENTICATE rejects unsupported key type");
            let mut wrong_type_crt = Vec::new();
            append_scp11c_crt_identifier(&mut wrong_type_crt);
            wrong_type_crt.extend_from_slice(&tlv(&[0x95], &[SCP11C_KEY_USAGE_FULL]));
            wrong_type_crt.extend_from_slice(&tlv(&[0x80], &[0x89]));
            wrong_type_crt.extend_from_slice(&tlv(&[0x81], &[SCP11C_KEY_LENGTH_AES_128]));
            wrong_type_crt.extend_from_slice(&tlv(&[0x84], OXIDE_SE_SCP11C_HOST_ID));
            wrong_type_crt.extend_from_slice(&tlv(&[0x5F, 0x49], host_public.as_bytes()));
            let wrong_type_request = tlv(&[0xA6], &wrong_type_crt);
            expect_status(
                client.exchange(&CommandBuilder::scp11c_mutual_authenticate_raw(
                    0x00,
                    0x01,
                    &wrong_type_request,
                ))?,
                (0x6A, 0x80),
                "scp11c mutual authenticate wrong key type",
            )?;

            eprintln!("{log_prefix}: SCP11c MUTUAL AUTHENTICATE rejects unsupported key length");
            let mut wrong_length_crt = Vec::new();
            append_scp11c_crt_identifier(&mut wrong_length_crt);
            wrong_length_crt.extend_from_slice(&tlv(&[0x95], &[SCP11C_KEY_USAGE_FULL]));
            wrong_length_crt.extend_from_slice(&tlv(&[0x80], &[SCP11C_KEY_TYPE_AES]));
            wrong_length_crt.extend_from_slice(&tlv(&[0x81], &[0x20]));
            wrong_length_crt.extend_from_slice(&tlv(&[0x84], OXIDE_SE_SCP11C_HOST_ID));
            wrong_length_crt.extend_from_slice(&tlv(&[0x5F, 0x49], host_public.as_bytes()));
            let wrong_length_request = tlv(&[0xA6], &wrong_length_crt);
            expect_status(
                client.exchange(&CommandBuilder::scp11c_mutual_authenticate_raw(
                    0x00,
                    0x01,
                    &wrong_length_request,
                ))?,
                (0x6A, 0x80),
                "scp11c mutual authenticate wrong key length",
            )?;

            eprintln!("{log_prefix}: SCP11c MUTUAL AUTHENTICATE rejects malformed 5F49");
            let mut malformed_public = host_public.as_bytes().to_vec();
            malformed_public.pop();
            let mut malformed_public_crt = Vec::new();
            append_scp11c_crt_identifier(&mut malformed_public_crt);
            malformed_public_crt.extend_from_slice(&tlv(&[0x95], &[SCP11C_KEY_USAGE_FULL]));
            malformed_public_crt.extend_from_slice(&tlv(&[0x80], &[SCP11C_KEY_TYPE_AES]));
            malformed_public_crt.extend_from_slice(&tlv(&[0x81], &[SCP11C_KEY_LENGTH_AES_128]));
            malformed_public_crt.extend_from_slice(&tlv(&[0x84], OXIDE_SE_SCP11C_HOST_ID));
            malformed_public_crt.extend_from_slice(&tlv(&[0x5F, 0x49], &malformed_public));
            let malformed_public_request = tlv(&[0xA6], &malformed_public_crt);
            expect_status(
                client.exchange(&CommandBuilder::scp11c_mutual_authenticate_raw(
                    0x00,
                    0x01,
                    &malformed_public_request,
                ))?,
                (0x6A, 0x80),
                "scp11c mutual authenticate malformed public key",
            )?;

            eprintln!("{log_prefix}: SCP11c MUTUAL AUTHENTICATE rejects duplicate 95");
            let mut duplicate_type_crt = Vec::new();
            append_scp11c_crt_identifier(&mut duplicate_type_crt);
            duplicate_type_crt.extend_from_slice(&tlv(&[0x95], &[SCP11C_KEY_USAGE_FULL]));
            duplicate_type_crt.extend_from_slice(&tlv(&[0x80], &[SCP11C_KEY_TYPE_AES]));
            duplicate_type_crt.extend_from_slice(&tlv(&[0x80], &[SCP11C_KEY_TYPE_AES]));
            duplicate_type_crt.extend_from_slice(&tlv(&[0x81], &[SCP11C_KEY_LENGTH_AES_128]));
            duplicate_type_crt.extend_from_slice(&tlv(&[0x84], OXIDE_SE_SCP11C_HOST_ID));
            duplicate_type_crt.extend_from_slice(&tlv(&[0x5F, 0x49], host_public.as_bytes()));
            let duplicate_type_request = tlv(&[0xA6], &duplicate_type_crt);
            expect_status(
                client.exchange(&CommandBuilder::scp11c_mutual_authenticate_raw(
                    0x00,
                    0x01,
                    &duplicate_type_request,
                ))?,
                (0x6A, 0x80),
                "scp11c mutual authenticate duplicate key type",
            )?;

            eprintln!("{log_prefix}: SCP11c MUTUAL AUTHENTICATE rejects duplicate 80");
            let mut duplicate_length_crt = Vec::new();
            append_scp11c_crt_identifier(&mut duplicate_length_crt);
            duplicate_length_crt.extend_from_slice(&tlv(&[0x95], &[SCP11C_KEY_USAGE_FULL]));
            duplicate_length_crt.extend_from_slice(&tlv(&[0x80], &[SCP11C_KEY_TYPE_AES]));
            duplicate_length_crt.extend_from_slice(&tlv(&[0x81], &[SCP11C_KEY_LENGTH_AES_128]));
            duplicate_length_crt.extend_from_slice(&tlv(&[0x81], &[SCP11C_KEY_LENGTH_AES_128]));
            duplicate_length_crt.extend_from_slice(&tlv(&[0x84], OXIDE_SE_SCP11C_HOST_ID));
            duplicate_length_crt.extend_from_slice(&tlv(&[0x5F, 0x49], host_public.as_bytes()));
            let duplicate_length_request = tlv(&[0xA6], &duplicate_length_crt);
            expect_status(
                client.exchange(&CommandBuilder::scp11c_mutual_authenticate_raw(
                    0x00,
                    0x01,
                    &duplicate_length_request,
                ))?,
                (0x6A, 0x80),
                "scp11c mutual authenticate duplicate key length",
            )?;

            eprintln!("{log_prefix}: SCP11c MUTUAL AUTHENTICATE rejects duplicate 81");
            let mut duplicate_host_id_crt = Vec::new();
            append_scp11c_crt_identifier(&mut duplicate_host_id_crt);
            duplicate_host_id_crt.extend_from_slice(&tlv(&[0x95], &[SCP11C_KEY_USAGE_FULL]));
            duplicate_host_id_crt.extend_from_slice(&tlv(&[0x80], &[SCP11C_KEY_TYPE_AES]));
            duplicate_host_id_crt.extend_from_slice(&tlv(&[0x81], &[SCP11C_KEY_LENGTH_AES_128]));
            duplicate_host_id_crt.extend_from_slice(&tlv(&[0x84], OXIDE_SE_SCP11C_HOST_ID));
            duplicate_host_id_crt.extend_from_slice(&tlv(&[0x84], OXIDE_SE_SCP11C_HOST_ID));
            duplicate_host_id_crt.extend_from_slice(&tlv(&[0x5F, 0x49], host_public.as_bytes()));
            let duplicate_host_id_request = tlv(&[0xA6], &duplicate_host_id_crt);
            expect_status(
                client.exchange(&CommandBuilder::scp11c_mutual_authenticate_raw(
                    0x00,
                    0x01,
                    &duplicate_host_id_request,
                ))?,
                (0x6A, 0x80),
                "scp11c mutual authenticate duplicate host id",
            )?;

            eprintln!("{log_prefix}: SCP11c MUTUAL AUTHENTICATE rejects duplicate 5F49");
            let mut duplicate_public_key_crt = Vec::new();
            append_scp11c_crt_identifier(&mut duplicate_public_key_crt);
            duplicate_public_key_crt.extend_from_slice(&tlv(&[0x95], &[SCP11C_KEY_USAGE_FULL]));
            duplicate_public_key_crt.extend_from_slice(&tlv(&[0x80], &[SCP11C_KEY_TYPE_AES]));
            duplicate_public_key_crt.extend_from_slice(&tlv(&[0x81], &[SCP11C_KEY_LENGTH_AES_128]));
            duplicate_public_key_crt.extend_from_slice(&tlv(&[0x84], OXIDE_SE_SCP11C_HOST_ID));
            duplicate_public_key_crt.extend_from_slice(&tlv(&[0x5F, 0x49], host_public.as_bytes()));
            duplicate_public_key_crt.extend_from_slice(&tlv(&[0x5F, 0x49], host_public.as_bytes()));
            let duplicate_public_key_request = tlv(&[0xA6], &duplicate_public_key_crt);
            expect_status(
                client.exchange(&CommandBuilder::scp11c_mutual_authenticate_raw(
                    0x00,
                    0x01,
                    &duplicate_public_key_request,
                ))?,
                (0x6A, 0x80),
                "scp11c mutual authenticate duplicate public key",
            )?;

            eprintln!("{log_prefix}: SCP11c MUTUAL AUTHENTICATE rejects malformed 95 length");
            let mut malformed_type_length_crt = Vec::new();
            append_scp11c_crt_identifier(&mut malformed_type_length_crt);
            malformed_type_length_crt.extend_from_slice(&tlv(&[0x95], &[SCP11C_KEY_USAGE_FULL]));
            malformed_type_length_crt
                .extend_from_slice(&tlv(&[0x80], &[SCP11C_KEY_TYPE_AES, 0x00]));
            malformed_type_length_crt
                .extend_from_slice(&tlv(&[0x81], &[SCP11C_KEY_LENGTH_AES_128]));
            malformed_type_length_crt.extend_from_slice(&tlv(&[0x84], OXIDE_SE_SCP11C_HOST_ID));
            malformed_type_length_crt
                .extend_from_slice(&tlv(&[0x5F, 0x49], host_public.as_bytes()));
            let malformed_type_length_request = tlv(&[0xA6], &malformed_type_length_crt);
            expect_status(
                client.exchange(&CommandBuilder::scp11c_mutual_authenticate_raw(
                    0x00,
                    0x01,
                    &malformed_type_length_request,
                ))?,
                (0x6A, 0x80),
                "scp11c mutual authenticate malformed key type length",
            )?;

            eprintln!("{log_prefix}: SCP11c MUTUAL AUTHENTICATE rejects malformed 80 length");
            let mut malformed_length_length_crt = Vec::new();
            append_scp11c_crt_identifier(&mut malformed_length_length_crt);
            malformed_length_length_crt.extend_from_slice(&tlv(&[0x95], &[SCP11C_KEY_USAGE_FULL]));
            malformed_length_length_crt.extend_from_slice(&tlv(&[0x80], &[SCP11C_KEY_TYPE_AES]));
            malformed_length_length_crt
                .extend_from_slice(&tlv(&[0x81], &[SCP11C_KEY_LENGTH_AES_128, 0x00]));
            malformed_length_length_crt.extend_from_slice(&tlv(&[0x84], OXIDE_SE_SCP11C_HOST_ID));
            malformed_length_length_crt
                .extend_from_slice(&tlv(&[0x5F, 0x49], host_public.as_bytes()));
            let malformed_length_length_request = tlv(&[0xA6], &malformed_length_length_crt);
            expect_status(
                client.exchange(&CommandBuilder::scp11c_mutual_authenticate_raw(
                    0x00,
                    0x01,
                    &malformed_length_length_request,
                ))?,
                (0x6A, 0x80),
                "scp11c mutual authenticate malformed key length length",
            )?;

            eprintln!("{log_prefix}: SCP11c MUTUAL AUTHENTICATE");
            let response = client.exchange(&CommandBuilder::scp11c_mutual_authenticate(
                0x00,
                0x01,
                host_public.as_bytes(),
            ))?;
            let response = expect_scp11c_mutual_authenticate_response(
                &response,
                "scp11c mutual authenticate",
            )?;
            let expected_keys = derive_host_scp11c_session_keys(
                &host_static_secret,
                &host_secret,
                response.public_key,
                "scp11c mutual authenticate",
            )?;
            if !expected_keys.all_distinct() {
                return Err(
                    "scp11c mutual authenticate: derived session keys should remain distinct"
                        .into(),
                );
            }
            let expected_receipt = host_scp11c_mutual_authenticate_receipt(
                &expected_keys,
                &CommandBuilder::scp11c_mutual_authenticate(0x00, 0x01, host_public.as_bytes())
                    .data,
                response.public_key,
                "scp11c mutual authenticate",
            )?;
            if response.receipt != expected_receipt {
                return Err("scp11c mutual authenticate: receipt mismatch".into());
            }
            let card_static_secret = SecretKey::from_slice(&SCP11_DEV_CARD_STATIC_PRIVATE_KEY)
                .map_err(|_| "scp11c: invalid card static private key")?;
            let card_static_public = card_static_secret.public_key().to_encoded_point(false);
            if response.public_key != card_static_public.as_bytes() {
                return Err("scp11c mutual authenticate: expected static card public key".into());
            }

            eprintln!("{log_prefix}: SCP11c stale receipt aborts the active session");
            let mut stale_receipt_chain = [0u8; 16];
            let stale_receipt_get_data = CommandBuilder::protected_gp_get_data(
                0x9f70,
                &expected_keys.s_mac,
                &mut stale_receipt_chain,
                16,
                41,
            )?;
            expect_status(
                client.exchange(&stale_receipt_get_data)?,
                (0x69, 0x82),
                "scp11c protected GET DATA stale receipt",
            )?;

            eprintln!("{log_prefix}: SCP11c MUTUAL AUTHENTICATE again");
            let second_host_secret_bytes = [
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
                0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C,
                0x2D, 0x2E, 0x2F, 0x31,
            ];
            let second_host_secret = SecretKey::from_slice(&second_host_secret_bytes)
                .map_err(|_| "scp11c: invalid second host ephemeral private key")?;
            let second_host_public = second_host_secret.public_key().to_encoded_point(false);
            let second = client.exchange(&CommandBuilder::scp11c_mutual_authenticate(
                0x00,
                0x01,
                second_host_public.as_bytes(),
            ))?;
            let second = expect_scp11c_mutual_authenticate_response(
                &second,
                "scp11c mutual authenticate second",
            )?;
            let second_keys = derive_host_scp11c_session_keys(
                &host_static_secret,
                &second_host_secret,
                second.public_key,
                "scp11c mutual authenticate second",
            )?;
            if !second_keys.all_distinct() {
                return Err(
                "scp11c mutual authenticate second: derived session keys should remain distinct"
                    .into(),
            );
            }
            let second_receipt = host_scp11c_mutual_authenticate_receipt(
                &second_keys,
                &CommandBuilder::scp11c_mutual_authenticate(
                    0x00,
                    0x01,
                    second_host_public.as_bytes(),
                )
                .data,
                second.public_key,
                "scp11c mutual authenticate second",
            )?;
            if second.receipt != second_receipt {
                return Err("scp11c mutual authenticate second: receipt mismatch".into());
            }
            if second.public_key != response.public_key {
                return Err("scp11c mutual authenticate second: card static key changed".into());
            }
            if second_receipt == expected_receipt {
                return Err("scp11c mutual authenticate second: expected distinct receipt".into());
            }

            eprintln!("{log_prefix}: SCP11c protected GET DATA lifecycle with R-ENC/R-MAC");
            let mut command_mac_chain = second_receipt;
            let mut response_mac_chain = second_receipt;
            let mut command_enc_counter = 0u32;
            let mut response_enc_counter = 0u32;
            let protected_get_data_response = [0x9F, 0x70, 0x01, 0x07];
            let response_iv =
                host_scp11c_encryption_iv(&second_keys.s_enc, &mut response_enc_counter, 0x12)?;
            let encrypted_lifecycle = host_aes_cbc_encrypt(
                &second_keys.s_enc,
                &response_iv,
                &protected_get_data_response,
                HostCbcPadding::Iso9797M2,
            )?;
            let mut rmac_input = encrypted_lifecycle.clone();
            rmac_input.extend_from_slice(&[0x90, 0x00]);
            let protected_get_data_rmac = host_chained_truncated_aes_cmac(
                &second_keys.s_rmac,
                &mut response_mac_chain,
                &rmac_input,
                16,
            )?;
            let protected_get_data = CommandBuilder::protected_gp_get_data(
                0x9f70,
                &second_keys.s_mac,
                &mut command_mac_chain,
                16,
                41,
            )?;

            let protected_response = parse_protected_response(
                client.exchange(&protected_get_data)?,
                "scp11c protected GET DATA lifecycle",
            )?;
            if protected_response.encrypted_data != encrypted_lifecycle
                || protected_response.status != (0x90, 0x00)
                || protected_response.mac != protected_get_data_rmac
            {
                return Err(
                    "scp11c protected GET DATA lifecycle: protected response mismatch".into(),
                );
            }
            let decrypted_lifecycle = host_aes_cbc_decrypt(
                &second_keys.s_enc,
                &response_iv,
                &protected_response.encrypted_data,
                HostCbcPadding::Iso9797M2,
            )?;
            if decrypted_lifecycle != protected_get_data_response {
                return Err("scp11c encrypted GET DATA host decrypt mismatch".into());
            }

            eprintln!("{log_prefix}: SCP11c protected STORE DATA with C-ENC large payload");
            let large_store_data = vec![0xA5; protected_load_chunk_len(16)? - 4];
            let encrypted_store_data = scp11c_encrypt_command_data(
                CommandBuilder::gp_store_data_with_tag(0xDF11, &large_store_data),
                &second_keys,
                &mut command_mac_chain,
                &mut command_enc_counter,
            )?;
            let protected_store_rmac = host_chained_truncated_aes_cmac(
                &second_keys.s_rmac,
                &mut response_mac_chain,
                &[0x90, 0x00],
                16,
            )?;
            let protected_store_response = parse_protected_response(
                client.exchange(&encrypted_store_data)?,
                "scp11c encrypted STORE DATA",
            )?;
            if !protected_store_response.encrypted_data.is_empty()
                || protected_store_response.status != (0x90, 0x00)
                || protected_store_response.mac != protected_store_rmac
            {
                return Err("scp11c encrypted STORE DATA: protected response mismatch".into());
            }

            eprintln!("{log_prefix}: SCP11c protected PUT KEY is forbidden");
            let encrypted_put_key = scp11c_encrypt_command_data(
                CommandBuilder::gp_put_key(
                    0x02,
                    0x01,
                    &[
                        (&SCP03_ROTATED_ENC_KEY, 0x01),
                        (&SCP03_ROTATED_MAC_KEY, 0x02),
                    ],
                ),
                &second_keys,
                &mut command_mac_chain,
                &mut command_enc_counter,
            )?;
            let protected_put_key_rmac = host_chained_truncated_aes_cmac(
                &second_keys.s_rmac,
                &mut response_mac_chain,
                &[0x69, 0x85],
                16,
            )?;
            expect_protected_status(
                client.exchange(&encrypted_put_key)?,
                (0x69, 0x85),
                &protected_put_key_rmac,
                "scp11c encrypted PUT KEY forbidden",
            )?;

            eprintln!("{log_prefix}: SCP11c protected DELETE key is forbidden");
            let encrypted_delete_key = scp11c_encrypt_command_data(
                CommandBuilder::gp_delete_aid(&[b'K', b'E', b'Y', 0x00, 0x01, 0x01]),
                &second_keys,
                &mut command_mac_chain,
                &mut command_enc_counter,
            )?;
            let protected_delete_key_rmac = host_chained_truncated_aes_cmac(
                &second_keys.s_rmac,
                &mut response_mac_chain,
                &[0x69, 0x85],
                16,
            )?;
            expect_protected_status(
                client.exchange(&encrypted_delete_key)?,
                (0x69, 0x85),
                &protected_delete_key_rmac,
                "scp11c encrypted DELETE key forbidden",
            )?;

            eprintln!("{log_prefix}: SCP11c protected SET STATUS is forbidden");
            let encrypted_set_status = scp11c_encrypt_command_data(
                CommandBuilder::gp_set_status(
                    0x80,
                    0x80,
                    &[0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x01],
                ),
                &second_keys,
                &mut command_mac_chain,
                &mut command_enc_counter,
            )?;
            let protected_set_status_rmac = host_chained_truncated_aes_cmac(
                &second_keys.s_rmac,
                &mut response_mac_chain,
                &[0x69, 0x85],
                16,
            )?;
            expect_protected_status(
                client.exchange(&encrypted_set_status)?,
                (0x69, 0x85),
                &protected_set_status_rmac,
                "scp11c encrypted SET STATUS forbidden",
            )?;

            if !ctx.build.without_rustlets {
                eprintln!("{log_prefix}: SCP11c protected install minimal_valid_test");
                let encrypted_install = scp11c_encrypt_command_data(
                    CommandBuilder::install(crate_rustlet_minimal_valid_test_aid()),
                    &second_keys,
                    &mut command_mac_chain,
                    &mut command_enc_counter,
                )?;
                let protected_install_rmac = host_chained_truncated_aes_cmac(
                    &second_keys.s_rmac,
                    &mut response_mac_chain,
                    &[0x90, 0x00],
                    16,
                )?;
                expect_protected_status(
                    client.exchange(&encrypted_install)?,
                    (0x90, 0x00),
                    &protected_install_rmac,
                    "scp11c encrypted install minimal_valid_test",
                )?;
            }

            eprintln!("{log_prefix}: SCP11c protected GET DATA replay is rejected");
            expect_status(
                client.exchange(&protected_get_data)?,
                (0x69, 0x82),
                "scp11c protected GET DATA replay",
            )?;

            if ctx.build.without_rustlets {
                return finish_kernel_scp_probe(client, log_prefix, 32 + discovery_total);
            }

            eprintln!("{log_prefix}: select minimal_valid_test");
            expect_status(
                client.exchange(&CommandBuilder::select(
                    crate_rustlet_minimal_valid_test_aid(),
                ))?,
                (0x90, 0x00),
                "scp11c select minimal_valid_test",
            )?;
            let minimal_total = run_minimal_valid_post_select_apdus(client, log_prefix, true)?;

            Ok(34 + discovery_total + minimal_total)
        },
    );
    test_result.map(TestReport::passed)
}

pub(crate) fn run_scp11a_test_for_board(
    ctx: &TestContext,
    image_format: LayoutImageFormat,
    board: &str,
) -> Result<TestReport, Box<dyn Error>> {
    let board = board_spec(board)?;
    let test_result = testing::target::run_apdu(
        ctx,
        board,
        image_format,
        "security-domain-scp11a",
        APDU_RESPONSE_TIMEOUT,
        |client| {
            let log_prefix = "security-domain-scp11a";

            eprintln!("{log_prefix}: GET DATA lifecycle");
            expect_response(
                client.exchange(&CommandBuilder::gp_get_data(0x9f70, 0x04))?,
                &[0x9f, 0x70, 0x01, 0x07],
                (0x90, 0x00),
                "scp11a kernel GET DATA lifecycle",
            )?;
            let discovery_total = validate_gp_discovery(
                client,
                log_prefix,
                rustlet_runtime::gp::SecurityDomainCapabilities {
                    scp03_s8: false,
                    scp03_s16: false,
                    scp11a: true,
                    scp11b: false,
                    scp11c: false,
                },
            )?;

            let host_static_secret_bytes = [
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E,
                0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
                0x4D, 0x4E, 0x4F, 0x50,
            ];
            let host_ephemeral_secret_bytes = [
                0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
                0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
                0x3D, 0x3E, 0x3F, 0x41,
            ];
            let host_static_secret = SecretKey::from_slice(&host_static_secret_bytes)
                .map_err(|_| "scp11a: invalid host static private key")?;
            let host_ephemeral_secret = SecretKey::from_slice(&host_ephemeral_secret_bytes)
                .map_err(|_| "scp11a: invalid host ephemeral private key")?;
            let host_static_public = host_static_secret.public_key().to_encoded_point(false);
            let host_ephemeral_public = host_ephemeral_secret.public_key().to_encoded_point(false);
            let host_certificate = build_dev_oce_certificate(host_static_public.as_bytes())?;

            eprintln!("{log_prefix}: SCP11a MUTUAL AUTHENTICATE rejected before PSO");
            expect_status(
                client.exchange(&CommandBuilder::scp11a_mutual_authenticate(
                    0x00,
                    0x01,
                    host_ephemeral_public.as_bytes(),
                ))?,
                (0x69, 0x85),
                "scp11a mutual authenticate before perform security operation",
            )?;

            eprintln!("{log_prefix}: SCP11a PERFORM SECURITY OPERATION");
            let split = host_certificate.len() / 2;
            expect_status(
                client.exchange(&CommandBuilder::scp11c_perform_security_operation(
                    0x80,
                    0x00,
                    &host_certificate[..split],
                ))?,
                (0x90, 0x00),
                "scp11a perform security operation first command block",
            )?;
            expect_status(
                client.exchange(&CommandBuilder::scp11c_perform_security_operation(
                    0x00,
                    0x00,
                    &host_certificate[split..],
                ))?,
                (0x90, 0x00),
                "scp11a perform security operation final command block",
            )?;

            eprintln!("{log_prefix}: PSO certificate-chain selector is rejected");
            expect_status(
                client.exchange(&CommandBuilder::scp11c_perform_security_operation(
                    0x00,
                    0x80,
                    &host_certificate[..32],
                ))?,
                (0x6A, 0x86),
                "scp11a unsupported PSO certificate chain",
            )?;

            eprintln!("{log_prefix}: SCP11c MUTUAL AUTHENTICATE is rejected on SCP11a path");
            expect_status(
                client.exchange(&CommandBuilder::scp11c_mutual_authenticate(
                    0x00,
                    0x01,
                    host_ephemeral_public.as_bytes(),
                ))?,
                (0x6D, 0x00),
                "scp11a path rejects mismatched scp11c mutual authenticate",
            )?;

            eprintln!("{log_prefix}: SCP11a ECKA selector and tag 84 binding are enforced");
            expect_status(
                client.exchange(&CommandBuilder::scp11a_mutual_authenticate(
                    0x00,
                    0x02,
                    host_ephemeral_public.as_bytes(),
                ))?,
                (0x6A, 0x88),
                "scp11a wrong ECKA key identifier",
            )?;
            expect_status(
                client.exchange(&CommandBuilder::scp11_mutual_authenticate_with_host_tag(
                    0x00,
                    0x01,
                    SCP11A_IDENTIFIER_PARAM,
                    false,
                    host_ephemeral_public.as_bytes(),
                ))?,
                (0x6A, 0x80),
                "scp11a parameter requests missing host id",
            )?;
            expect_status(
                client.exchange(&CommandBuilder::scp11_mutual_authenticate_with_host_tag(
                    0x00,
                    0x01,
                    0x01,
                    true,
                    host_ephemeral_public.as_bytes(),
                ))?,
                (0x6A, 0x80),
                "scp11a host id forbidden when parameter omits identities",
            )?;

            eprintln!(r#"{log_prefix}: SCP11a rejects profiled-out key usage "34""#);
            expect_status(
                client.exchange(&CommandBuilder::scp11_mutual_authenticate_with_usage(
                    0x00,
                    0x01,
                    SCP11A_IDENTIFIER_PARAM,
                    SCP11_KEY_USAGE_MACS,
                    host_ephemeral_public.as_bytes(),
                ))?,
                (0x6A, 0x80),
                "scp11a profiled-out key usage 34",
            )?;

            eprintln!("{log_prefix}: BEGIN and END R-MAC SESSION are profiled out");
            expect_status(
                client.exchange(&CommandBuilder::gp_rmac_session(0x7A, 0x00, 0x00))?,
                (0x6D, 0x00),
                "scp11a BEGIN R-MAC SESSION profiled out",
            )?;
            expect_status(
                client.exchange(&CommandBuilder::gp_rmac_session(0x78, 0x00, 0x00))?,
                (0x6D, 0x00),
                "scp11a END R-MAC SESSION profiled out",
            )?;

            eprintln!("{log_prefix}: SCP11a MUTUAL AUTHENTICATE");
            let response = client.exchange(&CommandBuilder::scp11a_mutual_authenticate(
                0x00,
                0x01,
                host_ephemeral_public.as_bytes(),
            ))?;
            let response = expect_scp11c_mutual_authenticate_response(
                &response,
                "scp11a mutual authenticate",
            )?;
            let expected_keys = derive_host_scp11a_session_keys(
                &host_static_secret,
                &host_ephemeral_secret,
                response.public_key,
                "scp11a mutual authenticate",
            )?;
            if !expected_keys.all_distinct() {
                return Err(
                    "scp11a mutual authenticate: derived session keys should remain distinct"
                        .into(),
                );
            }
            let expected_receipt = host_scp11c_mutual_authenticate_receipt(
                &expected_keys,
                &CommandBuilder::scp11a_mutual_authenticate(
                    0x00,
                    0x01,
                    host_ephemeral_public.as_bytes(),
                )
                .data,
                response.public_key,
                "scp11a mutual authenticate",
            )?;
            if response.receipt != expected_receipt {
                return Err("scp11a mutual authenticate: receipt mismatch".into());
            }

            eprintln!("{log_prefix}: SCP11a protected GET DATA lifecycle with R-ENC/R-MAC");
            let mut command_mac_chain = expected_receipt;
            let mut response_mac_chain = expected_receipt;
            let mut response_enc_counter = 0u32;
            let protected_get_data_response = [0x9F, 0x70, 0x01, 0x07];
            let response_iv =
                host_scp11c_encryption_iv(&expected_keys.s_enc, &mut response_enc_counter, 0x12)?;
            let encrypted_lifecycle = host_aes_cbc_encrypt(
                &expected_keys.s_enc,
                &response_iv,
                &protected_get_data_response,
                HostCbcPadding::Iso9797M2,
            )?;
            let mut rmac_input = encrypted_lifecycle.clone();
            rmac_input.extend_from_slice(&[0x90, 0x00]);
            let protected_get_data_rmac = host_chained_truncated_aes_cmac(
                &expected_keys.s_rmac,
                &mut response_mac_chain,
                &rmac_input,
                16,
            )?;
            let protected_get_data = CommandBuilder::protected_gp_get_data(
                0x9f70,
                &expected_keys.s_mac,
                &mut command_mac_chain,
                16,
                41,
            )?;
            let protected_response = parse_protected_response(
                client.exchange(&protected_get_data)?,
                "scp11a protected GET DATA lifecycle",
            )?;
            if protected_response.encrypted_data != encrypted_lifecycle
                || protected_response.status != (0x90, 0x00)
                || protected_response.mac != protected_get_data_rmac
            {
                return Err(
                    "scp11a protected GET DATA lifecycle: protected response mismatch".into(),
                );
            }

            if !ctx.build.without_rustlets {
                eprintln!("{log_prefix}: SCP11a protected install minimal_valid_test");
                let mut command_enc_counter = 0u32;
                let encrypted_install = scp11c_encrypt_command_data(
                    CommandBuilder::install(crate_rustlet_minimal_valid_test_aid()),
                    &expected_keys,
                    &mut command_mac_chain,
                    &mut command_enc_counter,
                )?;
                let protected_install_rmac = host_chained_truncated_aes_cmac(
                    &expected_keys.s_rmac,
                    &mut response_mac_chain,
                    &[0x90, 0x00],
                    16,
                )?;
                expect_protected_status(
                    client.exchange(&encrypted_install)?,
                    (0x90, 0x00),
                    &protected_install_rmac,
                    "scp11a encrypted install minimal_valid_test",
                )?;
            }

            eprintln!("{log_prefix}: SCP11a protected GET DATA replay is rejected");
            expect_status(
                client.exchange(&protected_get_data)?,
                (0x69, 0x82),
                "scp11a protected GET DATA replay",
            )?;

            if ctx.build.without_rustlets {
                return finish_kernel_scp_probe(client, log_prefix, 9 + discovery_total);
            }

            eprintln!("{log_prefix}: select minimal_valid_test");
            expect_status(
                client.exchange(&CommandBuilder::select(
                    crate_rustlet_minimal_valid_test_aid(),
                ))?,
                (0x90, 0x00),
                "scp11a select minimal_valid_test",
            )?;
            let minimal_total = run_minimal_valid_post_select_apdus(client, log_prefix, true)?;

            Ok(11 + discovery_total + minimal_total)
        },
    );
    test_result.map(TestReport::passed)
}

pub(crate) fn run_scp11b_test_for_board(
    ctx: &TestContext,
    image_format: LayoutImageFormat,
    board: &str,
) -> Result<TestReport, Box<dyn Error>> {
    let board = board_spec(board)?;
    let test_result = testing::target::run_apdu(
        ctx,
        board,
        image_format,
        "security-domain-scp11b",
        APDU_RESPONSE_TIMEOUT,
        |client| {
            let log_prefix = "security-domain-scp11b";

            eprintln!("{log_prefix}: GET DATA lifecycle");
            expect_response(
                client.exchange(&CommandBuilder::gp_get_data(0x9f70, 0x04))?,
                &[0x9f, 0x70, 0x01, 0x07],
                (0x90, 0x00),
                "scp11b kernel GET DATA lifecycle",
            )?;
            let discovery_total = validate_gp_discovery(
                client,
                log_prefix,
                rustlet_runtime::gp::SecurityDomainCapabilities {
                    scp03_s8: false,
                    scp03_s16: false,
                    scp11a: false,
                    scp11b: true,
                    scp11c: false,
                },
            )?;

            let host_ephemeral_secret_bytes = [
                0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
                0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
                0x3D, 0x3E, 0x3F, 0x41,
            ];
            let host_ephemeral_secret = SecretKey::from_slice(&host_ephemeral_secret_bytes)
                .map_err(|_| "scp11b: invalid host ephemeral private key")?;
            let host_ephemeral_public = host_ephemeral_secret.public_key().to_encoded_point(false);

            eprintln!("{log_prefix}: SCP11b MUTUAL AUTHENTICATE INS is rejected");
            expect_status(
                client.exchange(&CommandBuilder::scp11a_mutual_authenticate(
                    0x00,
                    0x01,
                    host_ephemeral_public.as_bytes(),
                ))?,
                (0x6D, 0x00),
                "scp11b mutual authenticate ins rejected",
            )?;

            eprintln!(r#"{log_prefix}: SCP11b rejects profiled-out key usage "34""#);
            expect_status(
                client.exchange(&CommandBuilder::scp11b_internal_authenticate_with_usage(
                    0x00,
                    0x01,
                    SCP11_KEY_USAGE_MACS,
                    host_ephemeral_public.as_bytes(),
                ))?,
                (0x6A, 0x80),
                "scp11b profiled-out key usage 34",
            )?;

            eprintln!("{log_prefix}: SCP11b INTERNAL AUTHENTICATE");
            let response = client.exchange(&CommandBuilder::scp11b_internal_authenticate(
                0x00,
                0x01,
                host_ephemeral_public.as_bytes(),
            ))?;
            let response = expect_scp11c_mutual_authenticate_response(
                &response,
                "scp11b internal authenticate",
            )?;
            let expected_keys = derive_host_scp11b_session_keys(
                &host_ephemeral_secret,
                response.public_key,
                "scp11b internal authenticate",
            )?;
            if !expected_keys.all_distinct() {
                return Err(
                    "scp11b internal authenticate: derived session keys should remain distinct"
                        .into(),
                );
            }
            let expected_receipt = host_scp11c_mutual_authenticate_receipt(
                &expected_keys,
                &CommandBuilder::scp11b_internal_authenticate(
                    0x00,
                    0x01,
                    host_ephemeral_public.as_bytes(),
                )
                .data,
                response.public_key,
                "scp11b internal authenticate",
            )?;
            if response.receipt != expected_receipt {
                return Err("scp11b internal authenticate: receipt mismatch".into());
            }

            eprintln!("{log_prefix}: SCP11b protected GET DATA lifecycle with R-ENC/R-MAC");
            let mut command_mac_chain = expected_receipt;
            let mut response_mac_chain = expected_receipt;
            let mut response_enc_counter = 0u32;
            let protected_get_data_response = [0x9F, 0x70, 0x01, 0x07];
            let response_iv =
                host_scp11c_encryption_iv(&expected_keys.s_enc, &mut response_enc_counter, 0x12)?;
            let encrypted_lifecycle = host_aes_cbc_encrypt(
                &expected_keys.s_enc,
                &response_iv,
                &protected_get_data_response,
                HostCbcPadding::Iso9797M2,
            )?;
            let mut rmac_input = encrypted_lifecycle.clone();
            rmac_input.extend_from_slice(&[0x90, 0x00]);
            let protected_get_data_rmac = host_chained_truncated_aes_cmac(
                &expected_keys.s_rmac,
                &mut response_mac_chain,
                &rmac_input,
                16,
            )?;
            let protected_get_data = CommandBuilder::protected_gp_get_data(
                0x9f70,
                &expected_keys.s_mac,
                &mut command_mac_chain,
                16,
                41,
            )?;
            let protected_response = parse_protected_response(
                client.exchange(&protected_get_data)?,
                "scp11b protected GET DATA lifecycle",
            )?;
            if protected_response.encrypted_data != encrypted_lifecycle
                || protected_response.status != (0x90, 0x00)
                || protected_response.mac != protected_get_data_rmac
            {
                return Err(
                    "scp11b protected GET DATA lifecycle: protected response mismatch".into(),
                );
            }

            eprintln!(
                "{log_prefix}: SCP11b protected install is rejected without OCE authentication"
            );
            let mut command_enc_counter = 0u32;
            // Card authentication alone cannot authorize installation or LOAD.
            for command in [
                CommandBuilder::install(crate_rustlet_minimal_valid_test_aid()),
                CommandBuilder::gp_install_for_load(
                    crate_rustlet_getting_started_test_aid(),
                    root_security_domain_aid(),
                    256,
                    &[0u8; 32],
                ),
                CommandBuilder::gp_load_block(0, true, &[0u8; 16]),
            ] {
                let label = format!(
                    "scp11b rejects INS={:02X} P1={:02X} without OCE authentication",
                    command.ins, command.p1
                );
                eprintln!("{log_prefix}: {label}");
                let encrypted = scp11c_encrypt_command_data(
                    command,
                    &expected_keys,
                    &mut command_mac_chain,
                    &mut command_enc_counter,
                )?;
                let rmac = host_chained_truncated_aes_cmac(
                    &expected_keys.s_rmac,
                    &mut response_mac_chain,
                    &[0x69, 0x85],
                    16,
                )?;
                expect_protected_status(client.exchange(&encrypted)?, (0x69, 0x85), &rmac, &label)?;
            }

            eprintln!("{log_prefix}: SCP11b protected GET DATA replay is rejected");
            expect_status(
                client.exchange(&protected_get_data)?,
                (0x69, 0x82),
                "scp11b protected GET DATA replay",
            )?;

            if ctx.build.without_rustlets {
                return finish_kernel_scp_probe(client, log_prefix, 10 + discovery_total);
            }

            eprintln!(
                "{log_prefix}: clear SELECT terminates SCP11b and selects minimal_valid_test"
            );
            expect_status(
                client.exchange(&CommandBuilder::select(
                    crate_rustlet_minimal_valid_test_aid(),
                ))?,
                (0x90, 0x00),
                "scp11b select minimal_valid_test",
            )?;
            let minimal_total = run_minimal_valid_post_select_apdus(client, log_prefix, true)?;

            Ok(11 + discovery_total + minimal_total)
        },
    );
    test_result.map(TestReport::passed)
}

/// Validates a Rustlet-backed Security Domain through the kernel proxy.
///
/// Unlike `run_security_domain_test_for_board`, this boots with
/// `RustletSecurityDomainProxy` and delegates management decisions to
/// `complete_security_domain`. The test checks the proxy contract: clear PUT
/// KEY, SCP03 setup through the Rustlet SD, protected install, privilege
/// filtering, and selection of content installed under that Rustlet authority.
pub(crate) fn run_rustlet_security_domain_test_for_board(
    ctx: &TestContext,
    image_format: LayoutImageFormat,
    board: &str,
) -> Result<TestReport, Box<dyn Error>> {
    let board = board_spec(board)?;

    let test_result = testing::target::run_apdu(
        ctx,
        board,
        image_format,
        "rustlet-security-domain",
        APDU_RESPONSE_TIMEOUT,
        |client| {
            let log_prefix = "rustlet-security-domain";

            eprintln!("{log_prefix}: select predeployed complete_security_domain instance");
            expect_response(
                client.exchange(&CommandBuilder::select(
                    complete_security_domain_instance_aid(),
                ))?,
                complete_security_domain_select_fci(),
                (0x90, 0x00),
                "select predeployed complete_security_domain instance",
            )?;

            eprintln!("{log_prefix}: complete_security_domain echo");
            expect_response(
                client.exchange(&CommandBuilder::process_with_data_and_le(
                    0x02,
                    &[0x00, 0x01, 0x02, 0x03],
                    0x04,
                ))?,
                &[0x00, 0x01, 0x02, 0x03],
                (0x90, 0x00),
                "complete_security_domain echo",
            )?;

            eprintln!("{log_prefix}: security domain get data lifecycle");
            expect_response(
                client.exchange(&CommandBuilder::gp_get_data(0x9f70, 0x04))?,
                &[0x9F, 0x70, 0x01, 0x07],
                (0x90, 0x00),
                "rustlet security domain get data lifecycle",
            )?;
            let discovery_total = validate_gp_discovery(
                client,
                log_prefix,
                rustlet_runtime::gp::SecurityDomainCapabilities {
                    scp03_s8: true,
                    scp03_s16: true,
                    scp11a: true,
                    scp11b: true,
                    scp11c: true,
                },
            )?;

            let scp03_total = run_rustlet_security_domain_scp03_apdus(client, log_prefix)?;

            eprintln!("{log_prefix}: select minimal_valid_test installed through rustlet SD");
            expect_status(
                client.exchange(&CommandBuilder::select(
                    crate_rustlet_minimal_valid_test_instance_c_aid(),
                ))?,
                (0x90, 0x00),
                "rustlet security domain select minimal_valid_test",
            )?;
            let minimal_total = run_minimal_valid_post_select_apdus(client, log_prefix, false)?;

            Ok(4 + discovery_total + scp03_total + minimal_total)
        },
    );
    test_result.map(TestReport::passed)
}

pub(crate) fn run_rustlet_security_domain_scp11a_test_for_board(
    ctx: &TestContext,
    image_format: LayoutImageFormat,
    board: &str,
) -> Result<TestReport, Box<dyn Error>> {
    let board = board_spec(board)?;

    let test_result = testing::target::run_apdu(
        ctx,
        board,
        image_format,
        "rustlet-security-domain-scp11a",
        APDU_RESPONSE_TIMEOUT,
        |client| {
            let log_prefix = "rustlet-security-domain-scp11a";

            eprintln!("{log_prefix}: select root complete_security_domain instance");
            expect_response(
                client.exchange(&CommandBuilder::select(
                    complete_security_domain_instance_aid(),
                ))?,
                complete_security_domain_select_fci(),
                (0x90, 0x00),
                "scp11a rustlet SD select root complete_security_domain instance",
            )?;

            let host_static_secret_bytes = [
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E,
                0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
                0x4D, 0x4E, 0x4F, 0x50,
            ];
            let host_ephemeral_secret_bytes = [
                0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
                0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
                0x3D, 0x3E, 0x3F, 0x41,
            ];
            let host_static_secret = SecretKey::from_slice(&host_static_secret_bytes)
                .map_err(|_| "scp11a rustlet SD: invalid host static private key")?;
            let host_ephemeral_secret = SecretKey::from_slice(&host_ephemeral_secret_bytes)
                .map_err(|_| "scp11a rustlet SD: invalid host ephemeral private key")?;
            let host_static_public = host_static_secret.public_key().to_encoded_point(false);
            let host_ephemeral_public = host_ephemeral_secret.public_key().to_encoded_point(false);
            let host_certificate = build_dev_oce_certificate(host_static_public.as_bytes())?;

            eprintln!("{log_prefix}: SCP11a PERFORM SECURITY OPERATION");
            expect_status(
                client.exchange(&CommandBuilder::scp11c_perform_security_operation(
                    0x00,
                    0x00,
                    &host_certificate,
                ))?,
                (0x90, 0x00),
                "scp11a rustlet SD perform security operation",
            )?;

            eprintln!("{log_prefix}: Rustlet SD resolves the requested ECKA key");
            expect_status(
                client.exchange(&CommandBuilder::scp11a_mutual_authenticate(
                    0x00,
                    0x02,
                    host_ephemeral_public.as_bytes(),
                ))?,
                (0x6A, 0x88),
                "scp11a rustlet SD wrong ECKA key identifier",
            )?;

            eprintln!("{log_prefix}: SCP11a MUTUAL AUTHENTICATE");
            let response = client.exchange(&CommandBuilder::scp11a_mutual_authenticate(
                0x00,
                0x01,
                host_ephemeral_public.as_bytes(),
            ))?;
            let response = expect_scp11c_mutual_authenticate_response(
                &response,
                "scp11a rustlet SD mutual authenticate",
            )?;
            let expected_keys = derive_host_scp11a_session_keys(
                &host_static_secret,
                &host_ephemeral_secret,
                response.public_key,
                "scp11a rustlet SD mutual authenticate",
            )?;
            let expected_receipt = host_scp11c_mutual_authenticate_receipt(
                &expected_keys,
                &CommandBuilder::scp11a_mutual_authenticate(
                    0x00,
                    0x01,
                    host_ephemeral_public.as_bytes(),
                )
                .data,
                response.public_key,
                "scp11a rustlet SD mutual authenticate",
            )?;
            if response.receipt != expected_receipt {
                return Err("scp11a rustlet SD mutual authenticate: receipt mismatch".into());
            }

            let mut command_mac_chain = expected_receipt;
            let mut response_mac_chain = expected_receipt;
            let mut response_enc_counter = 0u32;
            let protected_get_data_response = [0x9F, 0x70, 0x01, 0x07];
            let response_iv =
                host_scp11c_encryption_iv(&expected_keys.s_enc, &mut response_enc_counter, 0x12)?;
            let encrypted_lifecycle = host_aes_cbc_encrypt(
                &expected_keys.s_enc,
                &response_iv,
                &protected_get_data_response,
                HostCbcPadding::Iso9797M2,
            )?;
            let mut rmac_input = encrypted_lifecycle.clone();
            rmac_input.extend_from_slice(&[0x90, 0x00]);
            let protected_get_data_rmac = host_chained_truncated_aes_cmac(
                &expected_keys.s_rmac,
                &mut response_mac_chain,
                &rmac_input,
                16,
            )?;
            let protected_get_data = CommandBuilder::protected_gp_get_data(
                0x9f70,
                &expected_keys.s_mac,
                &mut command_mac_chain,
                16,
                41,
            )?;
            let protected_response = parse_protected_response(
                client.exchange(&protected_get_data)?,
                "scp11a rustlet SD protected GET DATA lifecycle",
            )?;
            if protected_response.encrypted_data != encrypted_lifecycle
                || protected_response.status != (0x90, 0x00)
                || protected_response.mac != protected_get_data_rmac
            {
                return Err("scp11a rustlet SD protected GET DATA response mismatch".into());
            }

            eprintln!("{log_prefix}: new failed establishment terminates the active session");
            expect_status(
                client.exchange(&CommandBuilder::scp11a_mutual_authenticate(
                    0x00,
                    0x02,
                    host_ephemeral_public.as_bytes(),
                ))?,
                (0x69, 0x85),
                "scp11a rustlet SD failed re-establishment",
            )?;
            let stale_protected_get_data = CommandBuilder::protected_gp_get_data(
                0x9f70,
                &expected_keys.s_mac,
                &mut command_mac_chain,
                16,
                41,
            )?;
            expect_status(
                client.exchange(&stale_protected_get_data)?,
                (0x69, 0x85),
                "scp11a rustlet SD stale session after failed re-establishment",
            )?;

            Ok(7)
        },
    );
    test_result.map(TestReport::passed)
}

pub(crate) fn run_rustlet_security_domain_scp11b_test_for_board(
    ctx: &TestContext,
    image_format: LayoutImageFormat,
    board: &str,
) -> Result<TestReport, Box<dyn Error>> {
    let board = board_spec(board)?;

    let test_result = testing::target::run_apdu(
        ctx,
        board,
        image_format,
        "rustlet-security-domain-scp11b",
        APDU_RESPONSE_TIMEOUT,
        |client| {
            let log_prefix = "rustlet-security-domain-scp11b";

            eprintln!("{log_prefix}: select root complete_security_domain instance");
            expect_response(
                client.exchange(&CommandBuilder::select(
                    complete_security_domain_instance_aid(),
                ))?,
                complete_security_domain_select_fci(),
                (0x90, 0x00),
                "scp11b rustlet SD select root complete_security_domain instance",
            )?;

            let host_ephemeral_secret_bytes = [
                0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
                0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
                0x3D, 0x3E, 0x3F, 0x41,
            ];
            let host_ephemeral_secret = SecretKey::from_slice(&host_ephemeral_secret_bytes)
                .map_err(|_| "scp11b rustlet SD: invalid host ephemeral private key")?;
            let host_ephemeral_public = host_ephemeral_secret.public_key().to_encoded_point(false);

            eprintln!("{log_prefix}: SCP11b MUTUAL AUTHENTICATE INS is rejected");
            expect_status(
                client.exchange(&CommandBuilder::scp11a_mutual_authenticate(
                    0x00,
                    0x01,
                    host_ephemeral_public.as_bytes(),
                ))?,
                (0x6D, 0x00),
                "scp11b rustlet SD mutual authenticate ins rejected",
            )?;

            eprintln!("{log_prefix}: SCP11b INTERNAL AUTHENTICATE");
            let response = client.exchange(&CommandBuilder::scp11b_internal_authenticate(
                0x00,
                0x01,
                host_ephemeral_public.as_bytes(),
            ))?;
            let response = expect_scp11c_mutual_authenticate_response(
                &response,
                "scp11b rustlet SD internal authenticate",
            )?;
            let expected_keys = derive_host_scp11b_session_keys(
                &host_ephemeral_secret,
                response.public_key,
                "scp11b rustlet SD internal authenticate",
            )?;
            let expected_receipt = host_scp11c_mutual_authenticate_receipt(
                &expected_keys,
                &CommandBuilder::scp11b_internal_authenticate(
                    0x00,
                    0x01,
                    host_ephemeral_public.as_bytes(),
                )
                .data,
                response.public_key,
                "scp11b rustlet SD internal authenticate",
            )?;
            if response.receipt != expected_receipt {
                return Err("scp11b rustlet SD internal authenticate: receipt mismatch".into());
            }

            let mut command_mac_chain = expected_receipt;
            let mut response_mac_chain = expected_receipt;
            let mut command_enc_counter = 0u32;
            let mut response_enc_counter = 0u32;
            let protected_get_data_response = [0x9F, 0x70, 0x01, 0x07];
            let response_iv =
                host_scp11c_encryption_iv(&expected_keys.s_enc, &mut response_enc_counter, 0x12)?;
            let encrypted_lifecycle = host_aes_cbc_encrypt(
                &expected_keys.s_enc,
                &response_iv,
                &protected_get_data_response,
                HostCbcPadding::Iso9797M2,
            )?;
            let mut rmac_input = encrypted_lifecycle.clone();
            rmac_input.extend_from_slice(&[0x90, 0x00]);
            let protected_get_data_rmac = host_chained_truncated_aes_cmac(
                &expected_keys.s_rmac,
                &mut response_mac_chain,
                &rmac_input,
                16,
            )?;
            let protected_get_data = CommandBuilder::protected_gp_get_data(
                0x9f70,
                &expected_keys.s_mac,
                &mut command_mac_chain,
                16,
                41,
            )?;
            let protected_response = parse_protected_response(
                client.exchange(&protected_get_data)?,
                "scp11b rustlet SD protected GET DATA lifecycle",
            )?;
            if protected_response.encrypted_data != encrypted_lifecycle
                || protected_response.status != (0x90, 0x00)
                || protected_response.mac != protected_get_data_rmac
            {
                return Err("scp11b rustlet SD protected GET DATA response mismatch".into());
            }

            eprintln!(
                "{log_prefix}: SCP11b protected install is rejected without OCE authentication"
            );
            let encrypted_install = scp11c_encrypt_command_data(
                CommandBuilder::install(crate_rustlet_minimal_valid_test_aid()),
                &expected_keys,
                &mut command_mac_chain,
                &mut command_enc_counter,
            )?;
            let protected_install_rmac = host_chained_truncated_aes_cmac(
                &expected_keys.s_rmac,
                &mut response_mac_chain,
                &[0x69, 0x85],
                16,
            )?;
            expect_protected_status(
                client.exchange(&encrypted_install)?,
                (0x69, 0x85),
                &protected_install_rmac,
                "scp11b rustlet SD encrypted install without OCE authentication",
            )?;

            eprintln!("{log_prefix}: SCP11b protected GET DATA replay is rejected");
            expect_status(
                client.exchange(&protected_get_data)?,
                (0x69, 0x82),
                "scp11b rustlet SD protected GET DATA replay",
            )?;

            eprintln!(
                "{log_prefix}: clear SELECT terminates SCP11b and selects minimal_valid_test"
            );
            expect_status(
                client.exchange(&CommandBuilder::select(
                    crate_rustlet_minimal_valid_test_aid(),
                ))?,
                (0x90, 0x00),
                "scp11b rustlet SD select minimal_valid_test",
            )?;
            let minimal_total = run_minimal_valid_post_select_apdus(client, log_prefix, true)?;

            Ok(8 + minimal_total)
        },
    );
    test_result.map(TestReport::passed)
}

pub(crate) fn run_rustlet_security_domain_scp11c_test_for_board(
    ctx: &TestContext,
    image_format: LayoutImageFormat,
    board: &str,
) -> Result<TestReport, Box<dyn Error>> {
    let board = board_spec(board)?;

    let test_result = testing::target::run_apdu(
        ctx,
        board,
        image_format,
        "rustlet-security-domain-scp11c",
        APDU_RESPONSE_TIMEOUT,
        |client| {
            let log_prefix = "rustlet-security-domain-scp11c";

            eprintln!("{log_prefix}: select root complete_security_domain instance");
            expect_response(
                client.exchange(&CommandBuilder::select(
                    complete_security_domain_instance_aid(),
                ))?,
                complete_security_domain_select_fci(),
                (0x90, 0x00),
                "scp11c rustlet SD select root complete_security_domain instance",
            )?;

            let host_static_secret_bytes = [
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E,
                0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
                0x4D, 0x4E, 0x4F, 0x50,
            ];
            let host_ephemeral_secret_bytes = [
                0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
                0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
                0x3D, 0x3E, 0x3F, 0x41,
            ];
            let host_static_secret = SecretKey::from_slice(&host_static_secret_bytes)
                .map_err(|_| "scp11c rustlet SD: invalid host static private key")?;
            let host_static_public = host_static_secret.public_key().to_encoded_point(false);
            let host_secret = SecretKey::from_slice(&host_ephemeral_secret_bytes)
                .map_err(|_| "scp11c rustlet SD: invalid host ephemeral private key")?;
            let host_public = host_secret.public_key().to_encoded_point(false);
            let host_certificate = build_dev_oce_certificate(host_static_public.as_bytes())?;

            eprintln!("{log_prefix}: SCP11c MUTUAL AUTHENTICATE rejected before PSO");
            expect_status(
                client.exchange(&CommandBuilder::scp11c_mutual_authenticate(
                    0x00,
                    0x01,
                    host_public.as_bytes(),
                ))?,
                (0x69, 0x85),
                "scp11c rustlet SD mutual authenticate before PSO",
            )?;

            eprintln!("{log_prefix}: SCP11c PERFORM SECURITY OPERATION");
            expect_status(
                client.exchange(&CommandBuilder::scp11c_perform_security_operation(
                    0x00,
                    0x00,
                    &host_certificate,
                ))?,
                (0x90, 0x00),
                "scp11c rustlet SD perform security operation",
            )?;

            eprintln!("{log_prefix}: SCP11c MUTUAL AUTHENTICATE");
            let response = client.exchange(&CommandBuilder::scp11c_mutual_authenticate(
                0x00,
                0x01,
                host_public.as_bytes(),
            ))?;
            let response = expect_scp11c_mutual_authenticate_response(
                &response,
                "scp11c rustlet SD mutual authenticate",
            )?;
            let expected_keys = derive_host_scp11c_session_keys(
                &host_static_secret,
                &host_secret,
                response.public_key,
                "scp11c rustlet SD mutual authenticate",
            )?;
            let expected_receipt = host_scp11c_mutual_authenticate_receipt(
                &expected_keys,
                &CommandBuilder::scp11c_mutual_authenticate(0x00, 0x01, host_public.as_bytes())
                    .data,
                response.public_key,
                "scp11c rustlet SD mutual authenticate",
            )?;
            if response.receipt != expected_receipt {
                return Err("scp11c rustlet SD mutual authenticate: receipt mismatch".into());
            }
            let card_static_secret = SecretKey::from_slice(&SCP11_DEV_CARD_STATIC_PRIVATE_KEY)
                .map_err(|_| "scp11c rustlet SD: invalid card static private key")?;
            let card_static_public = card_static_secret.public_key().to_encoded_point(false);
            if response.public_key != card_static_public.as_bytes() {
                return Err(
                    "scp11c rustlet SD mutual authenticate: expected static card public key".into(),
                );
            }

            let mut command_mac_chain = expected_receipt;
            let mut response_mac_chain = expected_receipt;
            let mut command_enc_counter = 0u32;
            let mut response_enc_counter = 0u32;
            let protected_get_data_response = [0x9F, 0x70, 0x01, 0x07];
            let response_iv =
                host_scp11c_encryption_iv(&expected_keys.s_enc, &mut response_enc_counter, 0x12)?;
            let encrypted_lifecycle = host_aes_cbc_encrypt(
                &expected_keys.s_enc,
                &response_iv,
                &protected_get_data_response,
                HostCbcPadding::Iso9797M2,
            )?;
            let mut rmac_input = encrypted_lifecycle.clone();
            rmac_input.extend_from_slice(&[0x90, 0x00]);
            let protected_get_data_rmac = host_chained_truncated_aes_cmac(
                &expected_keys.s_rmac,
                &mut response_mac_chain,
                &rmac_input,
                16,
            )?;
            let protected_get_data = CommandBuilder::protected_gp_get_data(
                0x9f70,
                &expected_keys.s_mac,
                &mut command_mac_chain,
                16,
                41,
            )?;
            let protected_response = parse_protected_response(
                client.exchange(&protected_get_data)?,
                "scp11c rustlet SD protected GET DATA lifecycle",
            )?;
            if protected_response.encrypted_data != encrypted_lifecycle
                || protected_response.status != (0x90, 0x00)
                || protected_response.mac != protected_get_data_rmac
            {
                return Err("scp11c rustlet SD protected GET DATA response mismatch".into());
            }

            eprintln!("{log_prefix}: SCP11c protected PUT KEY is blocked before the Rustlet hook");
            let encrypted_put_key = scp11c_encrypt_command_data(
                CommandBuilder::gp_put_key(0x02, 0x01, &[(&SCP03_ROTATED_ENC_KEY, 0x01)]),
                &expected_keys,
                &mut command_mac_chain,
                &mut command_enc_counter,
            )?;
            let protected_put_key_rmac = host_chained_truncated_aes_cmac(
                &expected_keys.s_rmac,
                &mut response_mac_chain,
                &[0x69, 0x85],
                16,
            )?;
            expect_protected_status(
                client.exchange(&encrypted_put_key)?,
                (0x69, 0x85),
                &protected_put_key_rmac,
                "scp11c rustlet SD encrypted PUT KEY forbidden",
            )?;

            eprintln!("{log_prefix}: SCP11c protected install minimal_valid_test");
            let encrypted_install = scp11c_encrypt_command_data(
                CommandBuilder::install(crate_rustlet_minimal_valid_test_aid()),
                &expected_keys,
                &mut command_mac_chain,
                &mut command_enc_counter,
            )?;
            let protected_install_rmac = host_chained_truncated_aes_cmac(
                &expected_keys.s_rmac,
                &mut response_mac_chain,
                &[0x90, 0x00],
                16,
            )?;
            expect_protected_status(
                client.exchange(&encrypted_install)?,
                (0x90, 0x00),
                &protected_install_rmac,
                "scp11c rustlet SD encrypted install minimal_valid_test",
            )?;

            eprintln!("{log_prefix}: SCP11c protected GET DATA replay is rejected");
            expect_status(
                client.exchange(&protected_get_data)?,
                (0x69, 0x82),
                "scp11c rustlet SD protected GET DATA replay",
            )?;

            eprintln!("{log_prefix}: select minimal_valid_test");
            expect_status(
                client.exchange(&CommandBuilder::select(
                    crate_rustlet_minimal_valid_test_aid(),
                ))?,
                (0x90, 0x00),
                "scp11c rustlet SD select minimal_valid_test",
            )?;
            let minimal_total = run_minimal_valid_post_select_apdus(client, log_prefix, true)?;

            Ok(9 + minimal_total)
        },
    );
    test_result.map(TestReport::passed)
}

pub(crate) fn run_security_domain_profile_test(
    ctx: &TestContext,
    image_format: LayoutImageFormat,
    board: &str,
    default_security_domain: &str,
    scp03_profile: HostScp03Profile,
    log_prefix: &str,
) -> Result<usize, Box<dyn Error>> {
    let board = board_spec(board)?;
    let config = match default_security_domain {
        "NullSecurityDomain" => "configs/config_noscp_test.toml",
        "KernelSecurityDomain" if scp03_profile == HostScp03Profile::S16 => {
            "configs/config_scp03_s16_test.toml"
        }
        "KernelSecurityDomain" => "configs/config_scp03_test.toml",
        other => panic!("unsupported security domain profile test backend {other}"),
    };
    let owned_ctx = ctx.with_config(config);
    let ctx = &owned_ctx;

    testing::target::run_apdu(
        ctx,
        board,
        image_format,
        log_prefix,
        APDU_RESPONSE_TIMEOUT,
        |client| match default_security_domain {
            "KernelSecurityDomain" => run_kernel_security_domain_apdus(
                client,
                log_prefix,
                scp03_profile,
                ctx.build.without_rustlets,
            ),
            _ => run_null_security_domain_apdus(client, log_prefix),
        },
    )
}

pub(crate) fn run_null_security_domain_apdus(
    client: &mut ApduClient,
    log_prefix: &str,
) -> Result<usize, Box<dyn Error>> {
    eprintln!("{log_prefix}: GET DATA lifecycle");
    expect_response(
        client.exchange(&CommandBuilder::gp_get_data(0x9f70, 0x04))?,
        &[0x9F, 0x70, 0x01, 0x07],
        (0x90, 0x00),
        "null security domain GET DATA lifecycle",
    )?;

    let discovery_total = validate_gp_discovery(
        client,
        log_prefix,
        rustlet_runtime::gp::SecurityDomainCapabilities::none(),
    )?;

    eprintln!("{log_prefix}: INITIALIZE UPDATE rejected");
    expect_status(
        client.exchange(&CommandBuilder::initialize_update(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ]))?,
        (0x6D, 0x00),
        "null security domain INITIALIZE UPDATE",
    )?;

    Ok(2 + discovery_total)
}

pub(crate) fn run_clear_registry_access_apdus(
    client: &mut ApduClient,
    log_prefix: &str,
) -> Result<usize, Box<dyn Error>> {
    const DATA_TAG: u16 = 0xDF31;
    const DATA_VALUE_A: &[u8] = b"registry-alpha";
    const DATA_VALUE_B: &[u8] = b"beta";
    const KEY_VERSION: u8 = 0x33;
    const KEY_ID: u8 = 0x01;
    const KEY_USAGE_ENC: u8 = 0x01;
    const KEY_USAGE_MAC: u8 = 0x02;

    eprintln!("{log_prefix}: GET DATA missing registry object");
    expect_status(
        client.exchange(&CommandBuilder::gp_get_data(
            DATA_TAG,
            DATA_VALUE_A.len() as u8,
        ))?,
        (0x6D, 0x00),
        "registry GET DATA missing object",
    )?;

    eprintln!("{log_prefix}: STORE DATA creates registry object");
    expect_status(
        client.exchange(&CommandBuilder::gp_store_data_with_tag(
            DATA_TAG,
            DATA_VALUE_A,
        ))?,
        (0x90, 0x00),
        "registry STORE DATA create",
    )?;

    eprintln!("{log_prefix}: GET DATA reads created object");
    expect_response(
        client.exchange(&CommandBuilder::gp_get_data(
            DATA_TAG,
            DATA_VALUE_A.len() as u8,
        ))?,
        DATA_VALUE_A,
        (0x90, 0x00),
        "registry GET DATA created object",
    )?;

    eprintln!("{log_prefix}: STORE DATA replaces registry object");
    expect_status(
        client.exchange(&CommandBuilder::gp_store_data_with_tag(
            DATA_TAG,
            DATA_VALUE_B,
        ))?,
        (0x90, 0x00),
        "registry STORE DATA replace",
    )?;

    eprintln!("{log_prefix}: GET DATA reads replacement");
    expect_response(
        client.exchange(&CommandBuilder::gp_get_data(
            DATA_TAG,
            DATA_VALUE_B.len() as u8,
        ))?,
        DATA_VALUE_B,
        (0x90, 0x00),
        "registry GET DATA replacement",
    )?;

    eprintln!("{log_prefix}: DELETE data object");
    expect_status(
        client.exchange(&CommandBuilder::gp_delete_aid(&gp_data_object_aid(
            DATA_TAG,
        )))?,
        (0x90, 0x00),
        "registry DELETE data object",
    )?;

    eprintln!("{log_prefix}: GET DATA after DELETE");
    expect_status(
        client.exchange(&CommandBuilder::gp_get_data(
            DATA_TAG,
            DATA_VALUE_B.len() as u8,
        ))?,
        (0x6D, 0x00),
        "registry GET DATA after DELETE",
    )?;

    eprintln!("{log_prefix}: DELETE missing data object rejected");
    expect_status(
        client.exchange(&CommandBuilder::gp_delete_aid(&gp_data_object_aid(
            DATA_TAG,
        )))?,
        (0x69, 0x85),
        "registry DELETE missing data object",
    )?;

    eprintln!("{log_prefix}: PUT KEY creates the ENC/MAC keyset");
    expect_status(
        client.exchange(&CommandBuilder::gp_put_key(
            KEY_VERSION,
            KEY_ID,
            &[
                (&SCP03_ROTATED_ENC_KEY, KEY_USAGE_ENC),
                (&SCP03_ROTATED_MAC_KEY, KEY_USAGE_MAC),
            ],
        ))?,
        (0x90, 0x00),
        "registry PUT KEY ENC/MAC keyset",
    )?;

    eprintln!("{log_prefix}: DELETE ENC key object");
    expect_status(
        client.exchange(&CommandBuilder::gp_delete_aid(&scp03_key_object_aid(
            KEY_VERSION,
            KEY_ID,
            KEY_USAGE_ENC,
        )))?,
        (0x90, 0x00),
        "registry DELETE ENC key",
    )?;

    eprintln!("{log_prefix}: DELETE MAC key object");
    expect_status(
        client.exchange(&CommandBuilder::gp_delete_aid(&scp03_key_object_aid(
            KEY_VERSION,
            KEY_ID + 1,
            KEY_USAGE_MAC,
        )))?,
        (0x90, 0x00),
        "registry DELETE MAC key",
    )?;

    eprintln!("{log_prefix}: DELETE missing key object rejected");
    expect_status(
        client.exchange(&CommandBuilder::gp_delete_aid(&scp03_key_object_aid(
            KEY_VERSION,
            KEY_ID,
            KEY_USAGE_ENC,
        )))?,
        (0x69, 0x85),
        "registry DELETE missing key",
    )?;

    eprintln!("{log_prefix}: INSTALL predeployed package instance");
    expect_status(
        client.exchange(&CommandBuilder::install_with_aids_and_data(
            crate_rustlet_minimal_valid_test_aid(),
            crate_rustlet_minimal_valid_test_aid(),
            crate_rustlet_minimal_valid_test_instance_b_aid(),
            &[],
        ))?,
        (0x90, 0x00),
        "registry INSTALL instance",
    )?;

    eprintln!("{log_prefix}: SELECT installed instance");
    expect_status(
        client.exchange(&CommandBuilder::select(
            crate_rustlet_minimal_valid_test_instance_b_aid(),
        ))?,
        (0x90, 0x00),
        "registry SELECT installed instance",
    )?;
    let minimal_total = run_minimal_valid_post_select_apdus(client, log_prefix, false)?;

    eprintln!("{log_prefix}: DELETE installed instance");
    expect_status(
        client.exchange(&CommandBuilder::gp_delete_aid(
            crate_rustlet_minimal_valid_test_instance_b_aid(),
        ))?,
        (0x90, 0x00),
        "registry DELETE installed instance",
    )?;

    eprintln!("{log_prefix}: SELECT deleted instance rejected");
    expect_status(
        client.exchange(&CommandBuilder::select(
            crate_rustlet_minimal_valid_test_instance_b_aid(),
        ))?,
        (0x6A, 0x82),
        "registry SELECT deleted instance",
    )?;

    Ok(15 + minimal_total)
}

pub(crate) fn run_kernel_security_domain_apdus(
    client: &mut ApduClient,
    log_prefix: &str,
    scp03_profile: HostScp03Profile,
    without_rustlets: bool,
) -> Result<usize, Box<dyn Error>> {
    eprintln!("{log_prefix}: GET DATA lifecycle");
    expect_response(
        client.exchange(&CommandBuilder::gp_get_data(0x9f70, 0x04))?,
        &[0x9F, 0x70, 0x01, 0x07],
        (0x90, 0x00),
        "kernel security domain GET DATA lifecycle",
    )?;

    let discovery_total = validate_gp_discovery(
        client,
        log_prefix,
        rustlet_runtime::gp::SecurityDomainCapabilities {
            scp03_s8: scp03_profile == HostScp03Profile::S8,
            scp03_s16: scp03_profile == HostScp03Profile::S16,
            scp11a: false,
            scp11b: false,
            scp11c: false,
        },
    )?;

    eprintln!("{log_prefix}: BEGIN/END R-MAC SESSION are profiled out");
    expect_status(
        client.exchange(&CommandBuilder::gp_rmac_session(0x7A, 0x10, 0x01))?,
        (0x6D, 0x00),
        "kernel security domain BEGIN R-MAC SESSION profiled out",
    )?;
    expect_status(
        client.exchange(&CommandBuilder::gp_rmac_session(0x78, 0x00, 0x03))?,
        (0x6D, 0x00),
        "kernel security domain END R-MAC SESSION profiled out",
    )?;

    let host_challenge = scp03_profile.challenge();
    // EXTERNAL AUTHENTICATE is rejected before its cryptogram is inspected when
    // no INITIALIZE UPDATE exchange is active.  Use locally-derived dummy
    // material here; every real session below is derived from the fresh card
    // challenge returned by the device.
    let premature = host_scp03_expectations(
        scp03_profile,
        host_challenge,
        &[0u8; 8],
        &SCP03_TEST_ENC_KEY,
        &SCP03_TEST_MAC_KEY,
        0x01,
        0x03,
    )?;
    eprintln!("{log_prefix}: EXTERNAL AUTHENTICATE before INITIALIZE UPDATE rejected");
    let (premature_external_authenticate, _) = CommandBuilder::scp03_external_authenticate(
        0x01,
        &premature.host_cryptogram,
        &premature.session_mac_key,
        scp03_profile.mac_len(),
    )?;
    expect_status(
        client.exchange(&premature_external_authenticate)?,
        (0x69, 0x85),
        "kernel security domain premature EXTERNAL AUTHENTICATE",
    )?;

    eprintln!("{log_prefix}: INITIALIZE UPDATE rejects the wrong challenge length");
    expect_status(
        client.exchange(&CommandBuilder::initialize_update(&host_challenge[..7]))?,
        (0x67, 0x00),
        "kernel security domain short INITIALIZE UPDATE",
    )?;

    eprintln!("{log_prefix}: INITIALIZE UPDATE rejects an unknown keyset");
    expect_status(
        client.exchange(&CommandBuilder::initialize_update_with_keyset(
            0x7F,
            0x7F,
            host_challenge,
        ))?,
        (0x6A, 0x88),
        "kernel security domain unknown INITIALIZE UPDATE keyset",
    )?;

    eprintln!("{log_prefix}: response-protecting SCP03 levels are profiled out");
    for security_level in [0x11, 0x13, 0x33] {
        let expected = exchange_scp03_initialize_update(
            client,
            scp03_profile,
            host_challenge,
            &SCP03_TEST_ENC_KEY,
            &SCP03_TEST_MAC_KEY,
            0x01,
            0x03,
            "kernel security domain INITIALIZE UPDATE before unsupported level",
        )?;
        let (unsupported, _) = CommandBuilder::scp03_external_authenticate(
            security_level,
            &expected.host_cryptogram,
            &expected.session_mac_key,
            scp03_profile.mac_len(),
        )?;
        expect_status(
            client.exchange(&unsupported)?,
            (0x6A, 0x86),
            &format!("kernel security domain SCP03 level {security_level:02X} profiled out"),
        )?;
    }

    eprintln!("{log_prefix}: INITIALIZE UPDATE before bad cryptogram");
    let expected = exchange_scp03_initialize_update(
        client,
        scp03_profile,
        host_challenge,
        &SCP03_TEST_ENC_KEY,
        &SCP03_TEST_MAC_KEY,
        0x01,
        0x03,
        "kernel security domain INITIALIZE UPDATE before bad cryptogram",
    )?;
    let host_cryptogram = expected.host_cryptogram.clone();
    let mut session_mac_key = expected.session_mac_key.clone();

    eprintln!("{log_prefix}: EXTERNAL AUTHENTICATE bad cryptogram rejected");
    let bad_host_cryptogram = vec![0xAA; scp03_profile.cryptogram_len()];
    let (bad_external_authenticate, _) = CommandBuilder::scp03_external_authenticate(
        0x01,
        &bad_host_cryptogram,
        &session_mac_key,
        scp03_profile.mac_len(),
    )?;
    expect_status(
        client.exchange(&bad_external_authenticate)?,
        (0x63, 0x00),
        "kernel security domain EXTERNAL AUTHENTICATE bad cryptogram",
    )?;

    eprintln!("{log_prefix}: EXTERNAL AUTHENTICATE retry requires a new INITIALIZE UPDATE");
    let (external_authenticate_retry, _) = CommandBuilder::scp03_external_authenticate(
        0x01,
        &host_cryptogram,
        &session_mac_key,
        scp03_profile.mac_len(),
    )?;
    expect_status(
        client.exchange(&external_authenticate_retry)?,
        (0x69, 0x85),
        "kernel security domain EXTERNAL AUTHENTICATE retry after failure",
    )?;

    eprintln!("{log_prefix}: INITIALIZE UPDATE before no-secure-messaging session");
    let expected = exchange_scp03_initialize_update(
        client,
        scp03_profile,
        host_challenge,
        &SCP03_TEST_ENC_KEY,
        &SCP03_TEST_MAC_KEY,
        0x01,
        0x03,
        "kernel security domain INITIALIZE UPDATE before no secure messaging",
    )?;

    eprintln!("{log_prefix}: EXTERNAL AUTHENTICATE without secure messaging");
    let (external_authenticate_none, _) = CommandBuilder::scp03_external_authenticate(
        0x00,
        &expected.host_cryptogram,
        &expected.session_mac_key,
        scp03_profile.mac_len(),
    )?;
    expect_status(
        client.exchange(&external_authenticate_none)?,
        (0x90, 0x00),
        "kernel security domain EXTERNAL AUTHENTICATE no secure messaging",
    )?;

    eprintln!("{log_prefix}: INITIALIZE UPDATE after no-secure-messaging session");
    let expected = exchange_scp03_initialize_update(
        client,
        scp03_profile,
        host_challenge,
        &SCP03_TEST_ENC_KEY,
        &SCP03_TEST_MAC_KEY,
        0x01,
        0x03,
        "kernel security domain INITIALIZE UPDATE after no secure messaging",
    )?;
    session_mac_key = expected.session_mac_key.clone();

    eprintln!("{log_prefix}: EXTERNAL AUTHENTICATE");
    let (external_authenticate, initial_mac_chain) = CommandBuilder::scp03_external_authenticate(
        0x01,
        &expected.host_cryptogram,
        &session_mac_key,
        scp03_profile.mac_len(),
    )?;
    expect_status(
        client.exchange(&external_authenticate)?,
        (0x90, 0x00),
        "kernel security domain EXTERNAL AUTHENTICATE",
    )?;
    eprintln!("{log_prefix}: protected GET DATA bad C-MAC rejected");
    expect_status(
        client.exchange(&CommandBuilder::protected_gp_get_data_with_mac(
            0x9f70,
            &vec![0xAA; scp03_profile.mac_len()],
            (4 + scp03_profile.mac_len()) as u8,
        ))?,
        (0x69, 0x82),
        "kernel security domain protected GET DATA bad C-MAC",
    )?;

    eprintln!("{log_prefix}: protected command after bad C-MAC requires re-establishment");
    let mut aborted_chain = initial_mac_chain;
    let command_after_abort = CommandBuilder::protected_gp_get_data(
        0x9f70,
        &session_mac_key,
        &mut aborted_chain,
        scp03_profile.mac_len(),
        41,
    )?;
    expect_status(
        client.exchange(&command_after_abort)?,
        (0x69, 0x85),
        "kernel security domain command after bad C-MAC",
    )?;

    eprintln!("{log_prefix}: re-establish SCP03 after bad C-MAC");
    let expected = exchange_scp03_initialize_update(
        client,
        scp03_profile,
        host_challenge,
        &SCP03_TEST_ENC_KEY,
        &SCP03_TEST_MAC_KEY,
        0x01,
        0x03,
        "kernel security domain INITIALIZE UPDATE after bad C-MAC",
    )?;
    session_mac_key = expected.session_mac_key.clone();
    let (external_authenticate, initial_mac_chain) = CommandBuilder::scp03_external_authenticate(
        0x01,
        &expected.host_cryptogram,
        &session_mac_key,
        scp03_profile.mac_len(),
    )?;
    expect_status(
        client.exchange(&external_authenticate)?,
        (0x90, 0x00),
        "kernel security domain EXTERNAL AUTHENTICATE after bad C-MAC",
    )?;
    let mut command_mac_chain = initial_mac_chain;

    eprintln!("{log_prefix}: protected GET DATA without a trailing C-MAC is malformed");
    expect_status(
        client.exchange(&OwnedT0Command {
            cla: 0x84,
            ins: 0xCA,
            p1: 0x9f,
            p2: 0x70,
            lc: 3,
            le: 41,
            data: vec![0x01, 0x02, 0x03],
        })?,
        (0x67, 0x00),
        "kernel security domain protected GET DATA without a trailing C-MAC",
    )?;

    eprintln!("{log_prefix}: protected GET DATA lifecycle with plain response");
    let protected_get_data = CommandBuilder::protected_gp_get_data(
        0x9f70,
        &session_mac_key,
        &mut command_mac_chain,
        scp03_profile.mac_len(),
        41,
    )?;
    let protected_get_data_response = [0x9F, 0x70, 0x01, 0x07];
    expect_response(
        client.exchange(&protected_get_data)?,
        &protected_get_data_response,
        (0x90, 0x00),
        "kernel security domain protected GET DATA lifecycle",
    )?;

    eprintln!("{log_prefix}: clear install minimal_valid_test rejected");
    expect_status(
        client.exchange(&CommandBuilder::install(
            crate_rustlet_minimal_valid_test_aid(),
        ))?,
        (0x69, 0x85),
        "kernel security domain clear install minimal_valid_test",
    )?;

    eprintln!("{log_prefix}: protected GET DATA replay aborts the session");
    expect_status(
        client.exchange(&protected_get_data)?,
        (0x69, 0x82),
        "kernel security domain protected GET DATA replay",
    )?;

    eprintln!("{log_prefix}: INITIALIZE UPDATE for encrypted secure messaging");
    let expected = exchange_scp03_initialize_update(
        client,
        scp03_profile,
        host_challenge,
        &SCP03_TEST_ENC_KEY,
        &SCP03_TEST_MAC_KEY,
        0x01,
        0x03,
        "kernel security domain encrypted INITIALIZE UPDATE",
    )?;
    let mut session_enc_key = expected.session_enc_key.clone();
    session_mac_key = expected.session_mac_key.clone();

    eprintln!("{log_prefix}: EXTERNAL AUTHENTICATE encrypted level");
    let (external_authenticate, initial_mac_chain) = CommandBuilder::scp03_external_authenticate(
        0x03,
        &expected.host_cryptogram,
        &session_mac_key,
        scp03_profile.mac_len(),
    )?;
    expect_status(
        client.exchange(&external_authenticate)?,
        (0x90, 0x00),
        "kernel security domain encrypted EXTERNAL AUTHENTICATE",
    )?;
    command_mac_chain = initial_mac_chain;
    let mut command_enc_counter = 0u32;

    eprintln!("{log_prefix}: encrypted protected GET DATA with plain response");
    let protected_get_data = CommandBuilder::protected_gp_get_data(
        0x9f70,
        &session_mac_key,
        &mut command_mac_chain,
        scp03_profile.mac_len(),
        41,
    )?;
    expect_response(
        client.exchange(&protected_get_data)?,
        &protected_get_data_response,
        (0x90, 0x00),
        "kernel security domain protected GET DATA lifecycle encrypted",
    )?;

    eprintln!("{log_prefix}: protected STORE DATA with C-ENC large payload");
    let large_store_data = vec![0x5A; protected_load_chunk_len(scp03_profile.mac_len())? - 4];
    let encrypted_store_data = scp03_encrypt_command_data(
        CommandBuilder::gp_store_data_with_tag(0xDF03, &large_store_data),
        &session_enc_key,
        &session_mac_key,
        &mut command_mac_chain,
        &mut command_enc_counter,
        scp03_profile.mac_len(),
    )?;
    expect_status(
        client.exchange(&encrypted_store_data)?,
        (0x90, 0x00),
        "kernel security domain encrypted STORE DATA",
    )?;

    eprintln!("{log_prefix}: encrypted PUT KEY rotated SCP03 keyset");
    let encrypted_put_key = scp03_encrypt_command_data(
        CommandBuilder::gp_put_key(
            0x02,
            0x01,
            &[
                (&SCP03_ROTATED_ENC_KEY, 0x01),
                (&SCP03_ROTATED_MAC_KEY, 0x02),
            ],
        ),
        &session_enc_key,
        &session_mac_key,
        &mut command_mac_chain,
        &mut command_enc_counter,
        scp03_profile.mac_len(),
    )?;
    expect_status(
        client.exchange(&encrypted_put_key)?,
        (0x90, 0x00),
        "kernel security domain encrypted PUT KEY rotated keyset",
    )?;

    eprintln!("{log_prefix}: INITIALIZE UPDATE rotated keyset");
    let rotated = exchange_scp03_initialize_update(
        client,
        scp03_profile,
        host_challenge,
        &SCP03_ROTATED_ENC_KEY,
        &SCP03_ROTATED_MAC_KEY,
        0x02,
        0x01,
        "kernel security domain rotated INITIALIZE UPDATE",
    )?;
    let rotated_host_cryptogram = rotated.host_cryptogram.clone();
    session_enc_key = rotated.session_enc_key.clone();
    session_mac_key = rotated.session_mac_key.clone();

    eprintln!("{log_prefix}: EXTERNAL AUTHENTICATE rotated keyset encrypted level");
    let (external_authenticate, initial_mac_chain) = CommandBuilder::scp03_external_authenticate(
        0x03,
        &rotated_host_cryptogram,
        &session_mac_key,
        scp03_profile.mac_len(),
    )?;
    expect_status(
        client.exchange(&external_authenticate)?,
        (0x90, 0x00),
        "kernel security domain rotated EXTERNAL AUTHENTICATE",
    )?;
    command_mac_chain = initial_mac_chain;
    command_enc_counter = 0u32;

    if without_rustlets {
        return finish_kernel_scp_probe(client, log_prefix, 34 + discovery_total);
    }

    eprintln!("{log_prefix}: encrypted install minimal_valid_test");
    let encrypted_install = scp03_encrypt_command_data(
        CommandBuilder::install(crate_rustlet_minimal_valid_test_aid()),
        &session_enc_key,
        &session_mac_key,
        &mut command_mac_chain,
        &mut command_enc_counter,
        scp03_profile.mac_len(),
    )?;
    expect_status(
        client.exchange(&encrypted_install)?,
        (0x90, 0x00),
        "kernel security domain encrypted install minimal_valid_test",
    )?;

    eprintln!("{log_prefix}: select minimal_valid_test");
    expect_status(
        client.exchange(&CommandBuilder::select(
            crate_rustlet_minimal_valid_test_aid(),
        ))?,
        (0x90, 0x00),
        "kernel security domain select minimal_valid_test",
    )?;
    let minimal_total = run_minimal_valid_post_select_apdus(client, log_prefix, true)?;

    eprintln!("{log_prefix}: second encrypted protected GET DATA with plain response");
    let protected_get_data = CommandBuilder::protected_gp_get_data(
        0x9f70,
        &session_mac_key,
        &mut command_mac_chain,
        scp03_profile.mac_len(),
        41,
    )?;
    expect_response(
        client.exchange(&protected_get_data)?,
        &protected_get_data_response,
        (0x90, 0x00),
        "kernel security domain second protected GET DATA lifecycle encrypted",
    )?;

    eprintln!("{log_prefix}: encrypted install minimal_valid_test with 3-byte privileges");
    let encrypted_install_sd = scp03_encrypt_command_data(
        CommandBuilder::install_with_aids_privileges_and_data(
            crate_rustlet_minimal_valid_test_aid(),
            crate_rustlet_minimal_valid_test_aid(),
            crate_rustlet_minimal_valid_test_instance_b_aid(),
            &[0xA0, 0x00, 0x01],
            &[],
        ),
        &session_enc_key,
        &session_mac_key,
        &mut command_mac_chain,
        &mut command_enc_counter,
        scp03_profile.mac_len(),
    )?;
    expect_status(
        client.exchange(&encrypted_install_sd)?,
        (0x90, 0x00),
        "kernel security domain encrypted install minimal_valid_test with 3-byte privileges",
    )?;

    eprintln!("{log_prefix}: select minimal_valid_test instance B");
    expect_status(
        client.exchange(&CommandBuilder::select(
            crate_rustlet_minimal_valid_test_instance_b_aid(),
        ))?,
        (0x90, 0x00),
        "kernel security domain select minimal_valid_test instance B",
    )?;

    eprintln!("{log_prefix}: encrypted install secondary kernel security domain instance");
    let encrypted_install_child_sd = scp03_encrypt_command_data(
        CommandBuilder::install_with_aids_privileges_and_data(
            kernel_security_domain_package_aid(),
            kernel_security_domain_package_aid(),
            kernel_security_domain_limited_instance_aid(),
            &[0x20, 0x00, 0x00],
            &[],
        ),
        &session_enc_key,
        &session_mac_key,
        &mut command_mac_chain,
        &mut command_enc_counter,
        scp03_profile.mac_len(),
    )?;
    expect_status(
        client.exchange(&encrypted_install_child_sd)?,
        (0x90, 0x00),
        "kernel security domain encrypted install secondary kernel security domain instance",
    )?;

    eprintln!("{log_prefix}: select secondary kernel security domain instance");
    expect_status(
        client.exchange(&CommandBuilder::select(
            kernel_security_domain_limited_instance_aid(),
        ))?,
        (0x90, 0x00),
        "kernel security domain select secondary kernel security domain instance",
    )?;

    eprintln!(
        "{log_prefix}: child kernel security domain EXTERNAL AUTHENTICATE rejected before reinit"
    );
    let (external_authenticate, _) = CommandBuilder::scp03_external_authenticate(
        0x03,
        &rotated_host_cryptogram,
        &session_mac_key,
        scp03_profile.mac_len(),
    )?;
    expect_status(
        client.exchange(&external_authenticate)?,
        (0x69, 0x85),
        "child kernel security domain EXTERNAL AUTHENTICATE before reinit",
    )?;

    eprintln!("{log_prefix}: child kernel security domain INITIALIZE UPDATE");
    let child_expected = exchange_scp03_initialize_update(
        client,
        scp03_profile,
        host_challenge,
        &SCP03_ROTATED_ENC_KEY,
        &SCP03_ROTATED_MAC_KEY,
        0x02,
        0x01,
        "child kernel security domain INITIALIZE UPDATE",
    )?;
    session_enc_key = child_expected.session_enc_key.clone();
    session_mac_key = child_expected.session_mac_key.clone();
    eprintln!("{log_prefix}: child kernel security domain EXTERNAL AUTHENTICATE encrypted level");
    let (external_authenticate, initial_mac_chain) = CommandBuilder::scp03_external_authenticate(
        0x03,
        &child_expected.host_cryptogram,
        &session_mac_key,
        scp03_profile.mac_len(),
    )?;
    expect_status(
        client.exchange(&external_authenticate)?,
        (0x90, 0x00),
        "child kernel security domain EXTERNAL AUTHENTICATE encrypted",
    )?;
    command_mac_chain = initial_mac_chain;
    command_enc_counter = 0u32;

    eprintln!("{log_prefix}: child kernel security domain privilege escalation install rejected");
    let encrypted_install_escalating_sd = scp03_encrypt_command_data(
        CommandBuilder::install_with_aids_privileges_and_data(
            kernel_security_domain_package_aid(),
            kernel_security_domain_package_aid(),
            kernel_security_domain_limited_instance_aid(),
            &[0xFF, 0xFF, 0xFF],
            &[],
        ),
        &session_enc_key,
        &session_mac_key,
        &mut command_mac_chain,
        &mut command_enc_counter,
        scp03_profile.mac_len(),
    )?;
    expect_status(
        client.exchange(&encrypted_install_escalating_sd)?,
        (0x69, 0x85),
        "child kernel security domain escalating install rejected",
    )?;

    eprintln!("{log_prefix}: child kernel security domain cannot select root-owned instance");
    expect_status(
        client.exchange(&CommandBuilder::select(
            crate_rustlet_minimal_valid_test_instance_b_aid(),
        ))?,
        (0x6A, 0x82),
        "child kernel security domain select root-owned instance rejected",
    )?;

    eprintln!("{log_prefix}: child kernel security domain encrypted install minimal_valid_test instance C");
    let encrypted_install_child_app = scp03_encrypt_command_data(
        CommandBuilder::install_with_aids_privileges_and_data(
            crate_rustlet_minimal_valid_test_aid(),
            crate_rustlet_minimal_valid_test_aid(),
            crate_rustlet_minimal_valid_test_instance_c_aid(),
            &[0x00],
            &[],
        ),
        &session_enc_key,
        &session_mac_key,
        &mut command_mac_chain,
        &mut command_enc_counter,
        scp03_profile.mac_len(),
    )?;
    expect_status(
        client.exchange(&encrypted_install_child_app)?,
        (0x90, 0x00),
        "child kernel security domain encrypted install minimal_valid_test instance C",
    )?;

    eprintln!("{log_prefix}: select minimal_valid_test instance C");
    expect_status(
        client.exchange(&CommandBuilder::select(
            crate_rustlet_minimal_valid_test_instance_c_aid(),
        ))?,
        (0x90, 0x00),
        "child kernel security domain select minimal_valid_test instance C",
    )?;

    Ok(44 + discovery_total + minimal_total)
}

pub(crate) fn run_rustlet_security_domain_scp03_apdus(
    client: &mut ApduClient,
    log_prefix: &str,
) -> Result<usize, Box<dyn Error>> {
    let mut total = 3;

    expect_response(
        client.exchange(&CommandBuilder::select(
            complete_security_domain_instance_aid(),
        ))?,
        complete_security_domain_select_fci(),
        (0x90, 0x00),
        "reselect privileged complete_security_domain instance before S8 clear",
    )?;
    total += run_rustlet_security_domain_scp03_round(
        client,
        log_prefix,
        HostScp03Profile::S8,
        false,
        true,
        None,
    )?;
    expect_response(
        client.exchange(&CommandBuilder::select(
            complete_security_domain_instance_aid(),
        ))?,
        complete_security_domain_select_fci(),
        (0x90, 0x00),
        "reselect privileged complete_security_domain instance before S8 encrypted",
    )?;
    total += run_rustlet_security_domain_scp03_round(
        client,
        log_prefix,
        HostScp03Profile::S8,
        true,
        false,
        Some(crate_rustlet_minimal_valid_test_instance_b_aid()),
    )?;
    expect_response(
        client.exchange(&CommandBuilder::select(
            complete_security_domain_instance_aid(),
        ))?,
        complete_security_domain_select_fci(),
        (0x90, 0x00),
        "reselect privileged complete_security_domain instance before S16 encrypted",
    )?;
    total += run_rustlet_security_domain_scp03_round(
        client,
        log_prefix,
        HostScp03Profile::S16,
        true,
        false,
        Some(crate_rustlet_minimal_valid_test_instance_c_aid()),
    )?;
    expect_response(
        client.exchange(&CommandBuilder::select(
            complete_security_domain_instance_aid(),
        ))?,
        complete_security_domain_select_fci(),
        (0x90, 0x00),
        "reselect privileged complete_security_domain instance before SCP03-33",
    )?;
    total += 1;
    total += run_rustlet_security_domain_scp03_33_round(client, log_prefix)?;

    Ok(total)
}

pub(crate) fn run_rustlet_security_domain_scp03_33_round(
    client: &mut ApduClient,
    log_prefix: &str,
) -> Result<usize, Box<dyn Error>> {
    let profile = HostScp03Profile::S16;
    let host_challenge = profile.challenge();
    eprintln!("{log_prefix}: rustlet SD S16 SCP03-33 INITIALIZE UPDATE");
    let expected = exchange_scp03_initialize_update(
        client,
        profile,
        host_challenge,
        &SCP03_TEST_ENC_KEY,
        &SCP03_TEST_MAC_KEY,
        0x01,
        0x03,
        "rustlet security domain SCP03-33",
    )?;

    eprintln!("{log_prefix}: rustlet SD S16 SCP03-33 EXTERNAL AUTHENTICATE");
    let (external_authenticate, initial_mac_chain) = CommandBuilder::scp03_external_authenticate(
        0x33,
        &expected.host_cryptogram,
        &expected.session_mac_key,
        profile.mac_len(),
    )?;
    expect_status(
        client.exchange(&external_authenticate)?,
        (0x90, 0x00),
        "rustlet security domain SCP03-33 EXTERNAL AUTHENTICATE",
    )?;

    eprintln!("{log_prefix}: rustlet SD S16 SCP03-33 protected GET DATA");
    let mut command_mac_chain = initial_mac_chain;
    let protected_get_data = CommandBuilder::protected_gp_get_data(
        0x9f70,
        &expected.session_mac_key,
        &mut command_mac_chain,
        profile.mac_len(),
        41,
    )?;

    let lifecycle = [0x9F, 0x70, 0x01, 0x07];
    let mut response_enc_counter = 0u32;
    let response_iv =
        host_scp03_encryption_iv(&expected.session_enc_key, &mut response_enc_counter, 0x02)?;
    let encrypted_lifecycle = host_aes_cbc_encrypt(
        &expected.session_enc_key,
        &response_iv,
        &lifecycle,
        HostCbcPadding::Iso9797M2,
    )?;
    let mut rmac_input = encrypted_lifecycle.clone();
    rmac_input.extend_from_slice(&[0x90, 0x00]);
    let mut response_mac_chain = initial_mac_chain;
    let expected_rmac = host_chained_truncated_aes_cmac(
        &expected.session_rmac_key,
        &mut response_mac_chain,
        &rmac_input,
        profile.mac_len(),
    )?;
    let protected_response = parse_protected_response(
        client.exchange(&protected_get_data)?,
        "rustlet security domain SCP03-33 protected GET DATA",
    )?;
    if protected_response.encrypted_data != encrypted_lifecycle
        || protected_response.status != (0x90, 0x00)
        || protected_response.mac != expected_rmac
    {
        return Err("rustlet security domain SCP03-33 protected response mismatch".into());
    }

    eprintln!("{log_prefix}: rustlet SD S16 SCP03-33 replay rejected");
    expect_status(
        client.exchange(&protected_get_data)?,
        (0x69, 0x82),
        "rustlet security domain SCP03-33 protected GET DATA replay",
    )?;

    Ok(4)
}

pub(crate) fn run_rustlet_security_domain_scp03_round(
    client: &mut ApduClient,
    log_prefix: &str,
    scp03_profile: HostScp03Profile,
    encrypted: bool,
    include_bad_auth_test: bool,
    install_instance_aid: Option<&[u8]>,
) -> Result<usize, Box<dyn Error>> {
    let host_challenge = scp03_profile.challenge();
    let profile_label = match scp03_profile {
        HostScp03Profile::S8 => "S8",
        HostScp03Profile::S16 => "S16",
    };
    let mode_label = if encrypted { "C-MAC/C-ENC" } else { "C-MAC" };

    eprintln!("{log_prefix}: rustlet SD {profile_label} INITIALIZE UPDATE");
    let mut expected = exchange_scp03_initialize_update(
        client,
        scp03_profile,
        host_challenge,
        &SCP03_TEST_ENC_KEY,
        &SCP03_TEST_MAC_KEY,
        0x01,
        0x03,
        "rustlet security domain INITIALIZE UPDATE",
    )?;
    let mut host_cryptogram = expected.host_cryptogram.clone();
    let mut session_enc_key = expected.session_enc_key.clone();
    let mut session_mac_key = expected.session_mac_key.clone();
    let mut total = 1;

    if include_bad_auth_test {
        eprintln!("{log_prefix}: rustlet SD {profile_label} bad EXTERNAL AUTHENTICATE rejected");
        let bad_host_cryptogram = vec![0xAA; scp03_profile.cryptogram_len()];
        let (bad_external_authenticate, _) = CommandBuilder::scp03_external_authenticate(
            0x01,
            &bad_host_cryptogram,
            &session_mac_key,
            scp03_profile.mac_len(),
        )?;
        expect_status(
            client.exchange(&bad_external_authenticate)?,
            (0x63, 0x00),
            "rustlet security domain EXTERNAL AUTHENTICATE bad cryptogram",
        )?;
        let (retry_without_initialize, _) = CommandBuilder::scp03_external_authenticate(
            0x01,
            &host_cryptogram,
            &session_mac_key,
            scp03_profile.mac_len(),
        )?;
        expect_status(
            client.exchange(&retry_without_initialize)?,
            (0x69, 0x85),
            "rustlet security domain EXTERNAL AUTHENTICATE retry after failure",
        )?;
        expected = exchange_scp03_initialize_update(
            client,
            scp03_profile,
            host_challenge,
            &SCP03_TEST_ENC_KEY,
            &SCP03_TEST_MAC_KEY,
            0x01,
            0x03,
            "rustlet security domain INITIALIZE UPDATE after failed authentication",
        )?;
        host_cryptogram = expected.host_cryptogram.clone();
        session_enc_key = expected.session_enc_key.clone();
        session_mac_key = expected.session_mac_key.clone();
        total += 3;
    }

    let security_level = if encrypted { 0x03 } else { 0x01 };
    let (external_authenticate, initial_mac_chain) = CommandBuilder::scp03_external_authenticate(
        security_level,
        &host_cryptogram,
        &session_mac_key,
        scp03_profile.mac_len(),
    )?;
    if encrypted {
        eprintln!("{log_prefix}: rustlet SD {profile_label} EXTERNAL AUTHENTICATE {mode_label}");
        expect_status(
            client.exchange(&external_authenticate)?,
            (0x90, 0x00),
            "rustlet security domain encrypted EXTERNAL AUTHENTICATE",
        )?;
    } else {
        eprintln!("{log_prefix}: rustlet SD {profile_label} EXTERNAL AUTHENTICATE {mode_label}");
        expect_status(
            client.exchange(&external_authenticate)?,
            (0x90, 0x00),
            "rustlet security domain EXTERNAL AUTHENTICATE",
        )?;
    }
    total += 1;

    let protected_get_data_response = [0x9F, 0x70, 0x01, 0x07];
    let mut command_mac_chain = initial_mac_chain;
    if encrypted {
        eprintln!("{log_prefix}: rustlet SD {profile_label} protected GET DATA {mode_label}");
        let mut command_enc_counter = 0u32;
        let protected_get_data = CommandBuilder::protected_gp_get_data(
            0x9f70,
            &session_mac_key,
            &mut command_mac_chain,
            scp03_profile.mac_len(),
            41,
        )?;
        expect_response(
            client.exchange(&protected_get_data)?,
            &protected_get_data_response,
            (0x90, 0x00),
            "rustlet security domain protected GET DATA lifecycle encrypted",
        )?;

        eprintln!("{log_prefix}: rustlet SD {profile_label} encrypted PUT KEY rotated keyset");
        let encrypted_put_key = scp03_encrypt_command_data(
            CommandBuilder::gp_put_key(
                0x02,
                0x01,
                &[
                    (&SCP03_ROTATED_ENC_KEY, 0x01),
                    (&SCP03_ROTATED_MAC_KEY, 0x02),
                ],
            ),
            &session_enc_key,
            &session_mac_key,
            &mut command_mac_chain,
            &mut command_enc_counter,
            scp03_profile.mac_len(),
        )?;
        expect_status(
            client.exchange(&encrypted_put_key)?,
            (0x90, 0x00),
            "rustlet security domain encrypted PUT KEY rotated keyset",
        )?;

        eprintln!("{log_prefix}: rustlet SD {profile_label} rotated INITIALIZE UPDATE");
        let rotated = exchange_scp03_initialize_update(
            client,
            scp03_profile,
            host_challenge,
            &SCP03_ROTATED_ENC_KEY,
            &SCP03_ROTATED_MAC_KEY,
            0x02,
            0x01,
            "rustlet security domain rotated INITIALIZE UPDATE",
        )?;
        let rotated_host_cryptogram = rotated.host_cryptogram.clone();

        eprintln!(
            "{log_prefix}: rustlet SD {profile_label} rotated EXTERNAL AUTHENTICATE {mode_label}"
        );
        let (external_authenticate, initial_mac_chain) =
            CommandBuilder::scp03_external_authenticate(
                0x03,
                &rotated_host_cryptogram,
                &rotated.session_mac_key,
                scp03_profile.mac_len(),
            )?;
        expect_status(
            client.exchange(&external_authenticate)?,
            (0x90, 0x00),
            "rustlet security domain rotated EXTERNAL AUTHENTICATE",
        )?;
        session_enc_key = rotated.session_enc_key;
        session_mac_key = rotated.session_mac_key;
        command_mac_chain = initial_mac_chain;
        command_enc_counter = 0u32;

        eprintln!("{log_prefix}: rustlet SD {profile_label} encrypted install minimal_valid_test");
        let install_instance_aid =
            install_instance_aid.unwrap_or(crate_rustlet_minimal_valid_test_aid());
        let encrypted_install = scp03_encrypt_command_data(
            CommandBuilder::install_with_aids_and_data(
                crate_rustlet_minimal_valid_test_aid(),
                crate_rustlet_minimal_valid_test_aid(),
                install_instance_aid,
                &[],
            ),
            &session_enc_key,
            &session_mac_key,
            &mut command_mac_chain,
            &mut command_enc_counter,
            scp03_profile.mac_len(),
        )?;
        expect_status(
            client.exchange(&encrypted_install)?,
            (0x90, 0x00),
            "rustlet security domain encrypted install minimal_valid_test",
        )?;
        total += 5;
    } else {
        eprintln!("{log_prefix}: rustlet SD {profile_label} protected GET DATA {mode_label}");
        let protected_get_data = CommandBuilder::protected_gp_get_data(
            0x9f70,
            &session_mac_key,
            &mut command_mac_chain,
            scp03_profile.mac_len(),
            41,
        )?;
        expect_response(
            client.exchange(&protected_get_data)?,
            &protected_get_data_response,
            (0x90, 0x00),
            "rustlet security domain protected GET DATA lifecycle",
        )?;
        total += 1;
    }

    Ok(total)
}
