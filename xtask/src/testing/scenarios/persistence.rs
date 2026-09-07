//! Multi-boot registry transactions; only the first boot loads an image.
use super::*;

/// QEMU owns a backing file; OpenOCD preserves physical flash across resets.
fn persistence_target(
    ctx: &TestContext,
    board: BoardSpec,
) -> Result<testing::target::TargetSession<'_>, Box<dyn Error>> {
    if ctx.openocd().is_none() && board.env_name != "raspi-pico1" {
        return Err("persistent QEMU scenarios require raspi-pico1 flash-file support".into());
    }
    testing::target::prepare_apdu_session(ctx, board, LayoutImageFormat::Elf, true)
}

pub(crate) fn run_persistence_test_for_board(
    ctx: &TestContext,
    board: &str,
) -> Result<TestReport, Box<dyn Error>> {
    let mut summary = run_null_security_domain_persistence_test_for_board(ctx, board)?;
    summary.total += run_with_build_config(ctx, "configs/config_scp03_test.toml", |ctx| {
        run_kernel_security_domain_key_persistence_test_for_board(ctx, board)
    })?;
    summary.total += run_with_build_config(ctx, "configs/config_scp11a_test.toml", |ctx| {
        run_kernel_security_domain_scp11_load_persistence_test_for_board(ctx, board)
    })?;
    summary.total += run_with_build_config(
        ctx,
        "configs/config_rustlet_security_domain_scp03_test.toml",
        |ctx| run_rustlet_security_domain_key_persistence_test_for_board(ctx, board),
    )?;
    Ok(summary)
}

pub(crate) fn run_scp03_install_load_test_for_board(
    ctx: &TestContext,
    board: &str,
) -> Result<TestReport, Box<dyn Error>> {
    let board = board_spec(board)?;
    let mut target = persistence_target(ctx, board)?;

    let dynamic_payload = build_getting_started_dynamic_load_payload(&ctx.build, board)?;
    let test_result = target.boot(
        "scp03 install-load focused boot",
        APDU_RESPONSE_TIMEOUT,
        |client| {
            eprintln!("scp03-install-load: read ATR");
            let mut session = open_host_scp03_session(
                client,
                HostScp03Profile::S8,
                0x01,
                0x03,
                &SCP03_TEST_ENC_KEY,
                &SCP03_TEST_MAC_KEY,
                "scp03-install-load initial keyset",
            )?;
            exchange_protected_scp03_status(
                client,
                &mut session,
                CommandBuilder::gp_install_for_load(
                    crate_rustlet_getting_started_test_aid(),
                    root_security_domain_aid(),
                    dynamic_payload.fae.len() as u32,
                    &dynamic_payload.hash,
                ),
                "scp03-install-load protected INSTALL [for load]",
            )?;
            let load_total = send_gp_load_sequence_protected_scp03(
                client,
                &mut session,
                &dynamic_payload.fae,
                "scp03-install-load protected",
            )?;
            exchange_protected_scp03_status(
                client,
                &mut session,
                CommandBuilder::install(crate_rustlet_getting_started_test_aid()),
                "scp03-install-load protected INSTALL [for install]",
            )?;
            expect_status(
                client.exchange(&CommandBuilder::select(
                    crate_rustlet_getting_started_test_aid(),
                ))?,
                (0x90, 0x00),
                "scp03-install-load SELECT dynamic LOAD instance",
            )?;
            let getting_started_total =
                run_getting_started_post_select_apdus(client, "scp03-install-load dynamic LOAD")?;
            Ok(4 + load_total + getting_started_total)
        },
    );

    Ok(TestReport::passed(test_result?))
}

pub(crate) fn run_null_security_domain_persistence_test_for_board(
    ctx: &TestContext,
    board: &str,
) -> Result<TestReport, Box<dyn Error>> {
    const DATA_TAG: u16 = 0xDF01;
    const DATA_VALUE: &[u8] = b"Oxide SE persistent data";
    const KEY_VERSION: u8 = 0x22;
    const KEY_ID: u8 = 0x01;
    const KEY_USAGE_ENC: u8 = 0x01;
    const KEY_USAGE_MAC: u8 = 0x02;
    let board = board_spec(board)?;
    let mut target = persistence_target(ctx, board)?;

    let dynamic_payload = build_getting_started_dynamic_load_payload(&ctx.build, board)?;

    let test_result = (|| -> Result<usize, Box<dyn Error>> {
        let first = target.boot("persistence boot 1", APDU_RESPONSE_TIMEOUT, |client| {
            eprintln!("persistence: first boot after programming image");
            expect_status(
                client.exchange(&CommandBuilder::gp_get_data(DATA_TAG, 0x40))?,
                (0x6D, 0x00),
                "first boot GET DATA before STORE DATA",
            )?;
            expect_status(
                client.exchange(&CommandBuilder::select(
                    crate_rustlet_minimal_valid_test_instance_b_aid(),
                ))?,
                (0x6A, 0x82),
                "first boot SELECT dynamic preloaded-package instance before INSTALL",
            )?;
            Ok(2)
        })?;

        let second = target.reboot("persistence boot 2", APDU_RESPONSE_TIMEOUT, |client| {
            eprintln!("persistence: second boot from flash");
            expect_status(
                client.exchange(&CommandBuilder::gp_get_data(DATA_TAG, 0x40))?,
                (0x6D, 0x00),
                "second boot GET DATA before STORE DATA",
            )?;
            expect_status(
                client.exchange(&CommandBuilder::gp_store_data_with_tag(
                    DATA_TAG, DATA_VALUE,
                ))?,
                (0x90, 0x00),
                "second boot STORE DATA",
            )?;
            expect_response(
                client.exchange(&CommandBuilder::gp_get_data(
                    DATA_TAG,
                    DATA_VALUE.len() as u8,
                ))?,
                DATA_VALUE,
                (0x90, 0x00),
                "second boot GET DATA after STORE DATA",
            )?;
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
                "second boot PUT KEY persistent SCP03 keyset",
            )?;
            expect_status(
                client.exchange(&CommandBuilder::install_with_aids_and_data(
                    crate_rustlet_minimal_valid_test_aid(),
                    crate_rustlet_minimal_valid_test_aid(),
                    crate_rustlet_minimal_valid_test_instance_b_aid(),
                    &[],
                ))?,
                (0x90, 0x00),
                "second boot INSTALL dynamic instance from predeployed package",
            )?;
            expect_status(
                client.exchange(&CommandBuilder::select(
                    crate_rustlet_minimal_valid_test_instance_b_aid(),
                ))?,
                (0x90, 0x00),
                "second boot SELECT dynamic predeployed-package instance",
            )?;
            let minimal_total = run_minimal_valid_post_select_apdus(
                client,
                "persistence predeployed package",
                false,
            )?;
            expect_status(
                client.exchange(&CommandBuilder::select(
                    crate_rustlet_getting_started_test_aid(),
                ))?,
                (0x6A, 0x82),
                "second boot SELECT dynamic LOAD package before LOAD",
            )?;
            eprintln!("persistence: INSTALL [for load] getting_started_test");
            expect_status(
                client.exchange(&CommandBuilder::gp_install_for_load(
                    crate_rustlet_getting_started_test_aid(),
                    root_security_domain_aid(),
                    dynamic_payload.fae.len() as u32,
                    &dynamic_payload.hash,
                ))?,
                (0x90, 0x00),
                "second boot INSTALL [for load] dynamic package",
            )?;
            let encoded_load = apdu_tool::gp::encode_load_file_data_block(&dynamic_payload.fae)?;
            let probe_end = 8.min(encoded_load.len());
            expect_status(
                client.exchange(&CommandBuilder::gp_load_block(
                    0x00,
                    false,
                    &encoded_load[..probe_end],
                ))?,
                (0x90, 0x00),
                "second boot LOAD first probe block",
            )?;
            expect_response(
                client.exchange(&CommandBuilder::gp_get_data(0x9f70, 0x04))?,
                &[0x9F, 0x70, 0x01, 0x07],
                (0x90, 0x00),
                "second boot GET DATA cancels in-progress dynamic LOAD",
            )?;
            expect_status(
                client.exchange(&CommandBuilder::gp_load_block(
                    0x01,
                    false,
                    &encoded_load[probe_end..probe_end + 1],
                ))?,
                (0x69, 0x85),
                "second boot LOAD rejected after cancellation",
            )?;
            expect_status(
                client.exchange(&CommandBuilder::gp_install_for_load(
                    crate_rustlet_getting_started_test_aid(),
                    root_security_domain_aid(),
                    dynamic_payload.fae.len() as u32,
                    &dynamic_payload.hash,
                ))?,
                (0x90, 0x00),
                "second boot INSTALL [for load] restarts after cancellation",
            )?;
            expect_status(
                client.exchange(&CommandBuilder::gp_load_block(
                    0x00,
                    false,
                    &encoded_load[..probe_end],
                ))?,
                (0x90, 0x00),
                "second boot LOAD first block after cancellation restart",
            )?;
            expect_status(
                client.exchange(&CommandBuilder::gp_load_block(
                    0x02,
                    true,
                    &encoded_load[probe_end..probe_end + 1],
                ))?,
                (0x6A, 0x80),
                "second boot LOAD rejects skipped P2",
            )?;
            expect_status(
                client.exchange(&CommandBuilder::gp_install_for_load(
                    crate_rustlet_getting_started_test_aid(),
                    root_security_domain_aid(),
                    1,
                    &dynamic_payload.hash,
                ))?,
                (0x90, 0x00),
                "second boot INSTALL [for load] aborts previous load",
            )?;
            expect_status(
                client.exchange(&CommandBuilder::gp_load_block(
                    0x00,
                    true,
                    &apdu_tool::gp::encode_load_file_data_block(&dynamic_payload.fae[..2])?,
                ))?,
                (0x6A, 0x80),
                "second boot LOAD rejects bytes beyond announced size",
            )?;
            expect_status(
                client.exchange(&CommandBuilder::gp_install_for_load(
                    crate_rustlet_getting_started_test_aid(),
                    root_security_domain_aid(),
                    dynamic_payload.fae.len() as u32,
                    &dynamic_payload.hash,
                ))?,
                (0x90, 0x00),
                "second boot INSTALL [for load] final dynamic package",
            )?;
            let load_total = send_gp_load_sequence(client, &dynamic_payload.fae)?;
            expect_status(
                client.exchange(&CommandBuilder::install(
                    crate_rustlet_getting_started_test_aid(),
                ))?,
                (0x90, 0x00),
                "second boot INSTALL dynamic LOAD instance",
            )?;
            expect_status(
                client.exchange(&CommandBuilder::select(
                    crate_rustlet_getting_started_test_aid(),
                ))?,
                (0x90, 0x00),
                "second boot SELECT dynamic LOAD instance",
            )?;
            let getting_started_total =
                run_getting_started_post_select_apdus(client, "persistence dynamic LOAD")?;
            Ok(13 + load_total + minimal_total + getting_started_total)
        })?;

        let third = target.reboot("persistence boot 3", APDU_RESPONSE_TIMEOUT, |client| {
            eprintln!("persistence: third boot from flash");
            expect_response(
                client.exchange(&CommandBuilder::gp_get_data(
                    DATA_TAG,
                    DATA_VALUE.len() as u8,
                ))?,
                DATA_VALUE,
                (0x90, 0x00),
                "third boot GET DATA persisted value",
            )?;
            expect_status(
                client.exchange(&CommandBuilder::select(
                    crate_rustlet_minimal_valid_test_instance_b_aid(),
                ))?,
                (0x90, 0x00),
                "third boot SELECT persisted dynamic predeployed-package instance",
            )?;
            let minimal_total = run_minimal_valid_post_select_apdus(
                client,
                "persistence predeployed package after reboot",
                false,
            )?;
            expect_status(
                client.exchange(&CommandBuilder::select(
                    crate_rustlet_getting_started_test_aid(),
                ))?,
                (0x90, 0x00),
                "third boot SELECT persisted dynamic LOAD instance",
            )?;
            let getting_started_total = run_getting_started_post_select_apdus(
                client,
                "persistence dynamic LOAD after reboot",
            )?;
            expect_status(
                client.exchange(&CommandBuilder::gp_delete_aid(&scp03_key_object_aid(
                    KEY_VERSION,
                    KEY_ID,
                    KEY_USAGE_ENC,
                )))?,
                (0x90, 0x00),
                "third boot DELETE persistent ENC key",
            )?;
            expect_status(
                client.exchange(&CommandBuilder::gp_delete_aid(&scp03_key_object_aid(
                    KEY_VERSION,
                    KEY_ID + 1,
                    KEY_USAGE_MAC,
                )))?,
                (0x90, 0x00),
                "third boot DELETE persistent MAC key",
            )?;
            Ok(5 + minimal_total + getting_started_total)
        })?;

        let fourth = target.reboot("persistence boot 4", APDU_RESPONSE_TIMEOUT, |client| {
            eprintln!("persistence: fourth boot from flash");
            expect_response(
                client.exchange(&CommandBuilder::gp_get_data(
                    DATA_TAG,
                    DATA_VALUE.len() as u8,
                ))?,
                DATA_VALUE,
                (0x90, 0x00),
                "fourth boot GET DATA persisted value after DELETE",
            )?;
            expect_status(
                client.exchange(&CommandBuilder::gp_delete_aid(&scp03_key_object_aid(
                    KEY_VERSION,
                    KEY_ID,
                    KEY_USAGE_ENC,
                )))?,
                (0x69, 0x85),
                "fourth boot DELETE already deleted ENC key",
            )?;
            Ok(2)
        })?;

        Ok(first + second + third + fourth)
    })();

    Ok(TestReport::passed(test_result?))
}

pub(crate) fn run_kernel_security_domain_key_persistence_test_for_board(
    ctx: &TestContext,
    board: &str,
) -> Result<usize, Box<dyn Error>> {
    const KEY_VERSION: u8 = 0x22;
    const KEY_ID: u8 = 0x01;
    const KEY_USAGE_ENC: u8 = 0x01;
    const KEY_USAGE_MAC: u8 = 0x02;

    let board = board_spec(board)?;
    let mut target = persistence_target(ctx, board)?;

    let dynamic_payload = build_getting_started_dynamic_load_payload(&ctx.build, board)?;

    let test_result = (|| -> Result<usize, Box<dyn Error>> {
        let first = target.boot("persistence scp03 boot 1", APDU_RESPONSE_TIMEOUT, |client| {
                eprintln!("persistence-scp03: first boot after programming image");
                let mut session = open_host_scp03_session(
                    client,
                    HostScp03Profile::S8,
                    0x01,
                    0x03,
                    &SCP03_TEST_ENC_KEY,
                    &SCP03_TEST_MAC_KEY,
                    "persistence-scp03 initial keyset",
                )?;
                exchange_protected_scp03_status(
                    client,
                    &mut session,
                    CommandBuilder::gp_install_for_load(
                        crate_rustlet_getting_started_test_aid(),
                        root_security_domain_aid(),
                        dynamic_payload.fae.len() as u32,
                        &dynamic_payload.hash,
                    ),
                    "persistence-scp03 protected INSTALL [for load]",
                )?;
                let encoded_load =
                    apdu_tool::gp::encode_load_file_data_block(&dynamic_payload.fae)?;
                let probe_chunk_len = protected_load_chunk_len(session.profile.mac_len())?;
                let probe_end = probe_chunk_len.min(encoded_load.len());
                exchange_protected_scp03_status(
                    client,
                    &mut session,
                    CommandBuilder::gp_load_block(0x00, false, &encoded_load[..probe_end]),
                    "persistence-scp03 protected LOAD first probe block",
                )?;
                exchange_protected_scp03_status(
                    client,
                    &mut session,
                    CommandBuilder::gp_store_data_with_tag(0xDF7D, b"cancel-load"),
                    "persistence-scp03 protected STORE DATA cancels in-progress dynamic LOAD",
                )?;
                if probe_end >= encoded_load.len() {
                    return Err("persistence-scp03 dynamic payload is too small for LOAD cancellation probe".into());
                }
                let rejected_probe_end = (probe_end + 1).min(encoded_load.len());
                exchange_protected_scp03_expected_status(
                    client,
                    &mut session,
                    CommandBuilder::gp_load_block(
                        0x01,
                        false,
                        &encoded_load[probe_end..rejected_probe_end],
                    ),
                    (0x69, 0x85),
                    "persistence-scp03 protected LOAD rejected after cancellation",
                )?;
                exchange_protected_scp03_status(
                    client,
                    &mut session,
                    CommandBuilder::gp_install_for_load(
                        crate_rustlet_getting_started_test_aid(),
                        root_security_domain_aid(),
                        dynamic_payload.fae.len() as u32,
                        &dynamic_payload.hash,
                    ),
                    "persistence-scp03 protected INSTALL [for load] restarts after cancellation",
                )?;
                let load_total = send_gp_load_sequence_protected_scp03(
                    client,
                    &mut session,
                    &dynamic_payload.fae,
                    "persistence-scp03 protected",
                )?;
                exchange_protected_scp03_status(
                    client,
                    &mut session,
                    CommandBuilder::install(crate_rustlet_getting_started_test_aid()),
                    "persistence-scp03 protected INSTALL dynamic LOAD instance",
                )?;
                expect_status(
                    client.exchange(&CommandBuilder::select(
                        crate_rustlet_getting_started_test_aid(),
                    ))?,
                    (0x90, 0x00),
                    "persistence-scp03 SELECT dynamic LOAD instance",
                )?;
                let getting_started_total = run_getting_started_post_select_apdus(
                    client,
                    "persistence-scp03 dynamic LOAD",
                )?;
                exchange_protected_scp03_status(
                    client,
                    &mut session,
                    CommandBuilder::gp_put_key(
                        KEY_VERSION,
                        KEY_ID,
                        &[
                            (&SCP03_ROTATED_ENC_KEY, KEY_USAGE_ENC),
                            (&SCP03_ROTATED_MAC_KEY, KEY_USAGE_MAC),
                        ],
                    ),
                    "persistence-scp03 protected PUT KEY keyset",
                )?;
                Ok(10 + load_total + getting_started_total)
            },
        )?;

        let second = target.reboot(
            "persistence scp03 boot 2",
            APDU_RESPONSE_TIMEOUT,
            |client| {
                eprintln!("persistence-scp03: second boot from flash");
                let mut session = open_host_scp03_session(
                    client,
                    HostScp03Profile::S8,
                    KEY_VERSION,
                    KEY_ID,
                    &SCP03_ROTATED_ENC_KEY,
                    &SCP03_ROTATED_MAC_KEY,
                    "persistence-scp03 persisted rotated keyset",
                )?;
                exchange_protected_scp03_status(
                    client,
                    &mut session,
                    CommandBuilder::gp_delete_aid(&scp03_key_object_aid(
                        KEY_VERSION,
                        KEY_ID,
                        KEY_USAGE_ENC,
                    )),
                    "persistence-scp03 protected DELETE ENC key",
                )?;
                exchange_protected_scp03_status(
                    client,
                    &mut session,
                    CommandBuilder::gp_delete_aid(&scp03_key_object_aid(
                        KEY_VERSION,
                        KEY_ID + 1,
                        KEY_USAGE_MAC,
                    )),
                    "persistence-scp03 protected DELETE MAC key",
                )?;
                expect_status(
                    client.exchange(&CommandBuilder::select(
                        crate_rustlet_getting_started_test_aid(),
                    ))?,
                    (0x90, 0x00),
                    "persistence-scp03 SELECT persisted dynamic LOAD instance",
                )?;
                let getting_started_total = run_getting_started_post_select_apdus(
                    client,
                    "persistence-scp03 dynamic LOAD after reboot",
                )?;
                Ok(5 + getting_started_total)
            },
        )?;

        let third = target.reboot(
            "persistence scp03 boot 3",
            APDU_RESPONSE_TIMEOUT,
            |client| {
                eprintln!("persistence-scp03: third boot from flash");
                expect_status(
                    client.exchange(&CommandBuilder::initialize_update_with_keyset(
                        KEY_VERSION,
                        KEY_ID,
                        HostScp03Profile::S8.challenge(),
                    ))?,
                    (0x6A, 0x88),
                    "persistence-scp03 deleted rotated keyset rejected",
                )?;
                Ok(2)
            },
        )?;

        Ok(first + second + third)
    })();

    test_result
}

pub(crate) fn run_kernel_security_domain_scp11_load_persistence_test_for_board(
    ctx: &TestContext,
    board: &str,
) -> Result<usize, Box<dyn Error>> {
    let board = board_spec(board)?;
    let mut target = persistence_target(ctx, board)?;

    let dynamic_payload = build_getting_started_dynamic_load_payload(&ctx.build, board)?;

    let test_result = (|| -> Result<usize, Box<dyn Error>> {
        let first = target.boot(
            "persistence scp11 boot 1",
            APDU_RESPONSE_TIMEOUT,
            |client| {
                eprintln!("persistence-scp11: first boot after programming image");
                let mut session =
                    open_host_scp11a_session(client, "persistence-scp11 initial session")?;
                exchange_protected_scp11_status(
                    client,
                    &mut session,
                    CommandBuilder::gp_install_for_load(
                        crate_rustlet_getting_started_test_aid(),
                        root_security_domain_aid(),
                        dynamic_payload.fae.len() as u32,
                        &dynamic_payload.hash,
                    ),
                    "persistence-scp11 protected INSTALL [for load]",
                )?;
                let load_total = send_gp_load_sequence_protected_scp11(
                    client,
                    &mut session,
                    &dynamic_payload.fae,
                    "persistence-scp11 protected",
                )?;
                exchange_protected_scp11_status(
                    client,
                    &mut session,
                    CommandBuilder::install(crate_rustlet_getting_started_test_aid()),
                    "persistence-scp11 protected INSTALL dynamic LOAD instance",
                )?;
                expect_status(
                    client.exchange(&CommandBuilder::select(
                        crate_rustlet_getting_started_test_aid(),
                    ))?,
                    (0x90, 0x00),
                    "persistence-scp11 SELECT dynamic LOAD instance",
                )?;
                let getting_started_total = run_getting_started_post_select_apdus(
                    client,
                    "persistence-scp11 dynamic LOAD",
                )?;
                Ok(4 + load_total + getting_started_total)
            },
        )?;

        let second = target.reboot(
            "persistence scp11 boot 2",
            APDU_RESPONSE_TIMEOUT,
            |client| {
                eprintln!("persistence-scp11: second boot from flash");
                expect_status(
                    client.exchange(&CommandBuilder::select(
                        crate_rustlet_getting_started_test_aid(),
                    ))?,
                    (0x90, 0x00),
                    "persistence-scp11 SELECT persisted dynamic LOAD instance",
                )?;
                let getting_started_total = run_getting_started_post_select_apdus(
                    client,
                    "persistence-scp11 dynamic LOAD after reboot",
                )?;
                Ok(1 + getting_started_total)
            },
        )?;

        Ok(first + second)
    })();

    test_result
}

pub(crate) fn run_rustlet_security_domain_key_persistence_test_for_board(
    ctx: &TestContext,
    board: &str,
) -> Result<usize, Box<dyn Error>> {
    const KEY_VERSION: u8 = 0x23;
    const KEY_ID: u8 = 0x01;
    const KEY_USAGE_ENC: u8 = 0x01;
    const KEY_USAGE_MAC: u8 = 0x02;

    let board = board_spec(board)?;
    let mut target = persistence_target(ctx, board)?;

    let test_result = (|| -> Result<usize, Box<dyn Error>> {
        let first = target.boot(
            "persistence rustlet-sd boot 1",
            APDU_RESPONSE_TIMEOUT,
            |client| {
                eprintln!("persistence-rustlet-sd: first boot after programming image");
                select_complete_security_domain(client, "persistence-rustlet-sd boot 1")?;
                let mut session = open_host_scp03_session(
                    client,
                    HostScp03Profile::S8,
                    0x01,
                    0x03,
                    &SCP03_TEST_ENC_KEY,
                    &SCP03_TEST_MAC_KEY,
                    "persistence-rustlet-sd initial keyset",
                )?;
                exchange_protected_scp03_status(
                    client,
                    &mut session,
                    CommandBuilder::gp_put_key(
                        KEY_VERSION,
                        KEY_ID,
                        &[
                            (&SCP03_ROTATED_ENC_KEY, KEY_USAGE_ENC),
                            (&SCP03_ROTATED_MAC_KEY, KEY_USAGE_MAC),
                        ],
                    ),
                    "persistence-rustlet-sd protected PUT KEY keyset",
                )?;
                Ok(4)
            },
        )?;

        let second = target.reboot(
            "persistence rustlet-sd boot 2",
            APDU_RESPONSE_TIMEOUT,
            |client| {
                eprintln!("persistence-rustlet-sd: second boot from flash");
                select_complete_security_domain(client, "persistence-rustlet-sd boot 2")?;
                let mut session = open_host_scp03_session(
                    client,
                    HostScp03Profile::S8,
                    KEY_VERSION,
                    KEY_ID,
                    &SCP03_ROTATED_ENC_KEY,
                    &SCP03_ROTATED_MAC_KEY,
                    "persistence-rustlet-sd persisted rotated keyset",
                )?;
                exchange_protected_scp03_status(
                    client,
                    &mut session,
                    CommandBuilder::gp_delete_aid(&scp03_key_object_aid(
                        KEY_VERSION,
                        KEY_ID,
                        KEY_USAGE_ENC,
                    )),
                    "persistence-rustlet-sd protected DELETE ENC key",
                )?;
                exchange_protected_scp03_status(
                    client,
                    &mut session,
                    CommandBuilder::gp_delete_aid(&scp03_key_object_aid(
                        KEY_VERSION,
                        KEY_ID + 1,
                        KEY_USAGE_MAC,
                    )),
                    "persistence-rustlet-sd protected DELETE MAC key",
                )?;
                Ok(5)
            },
        )?;

        let third = target.reboot(
            "persistence rustlet-sd boot 3",
            APDU_RESPONSE_TIMEOUT,
            |client| {
                eprintln!("persistence-rustlet-sd: third boot from flash");
                select_complete_security_domain(client, "persistence-rustlet-sd boot 3")?;
                expect_status(
                    client.exchange(&CommandBuilder::initialize_update_with_keyset(
                        KEY_VERSION,
                        KEY_ID,
                        HostScp03Profile::S8.challenge(),
                    ))?,
                    (0x6A, 0x88),
                    "persistence-rustlet-sd deleted rotated keyset rejected",
                )?;
                Ok(3)
            },
        )?;

        Ok(first + second + third)
    })();

    test_result
}
