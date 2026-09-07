//! kernel scenario operations and assertions, shared by individual tests and campaigns.
use super::*;

/// Runs the low-level core-test firmware under QEMU and parses its text report.
///
/// This predates the APDU-driven GP/Rustlet campaigns and remains useful for
/// checking board bring-up, allocator basics, and target support without
/// booting the full GP kernel.
pub(crate) fn run_core_test_with_context(
    ctx: &TestContext,
    board: &str,
) -> Result<TestReport, Box<dyn Error>> {
    let board = board_spec(board)?;
    testing::target::run_core(ctx, board, "qemu", "kernel-core", |output| {
        let stdout = String::from_utf8(output.stdout).map_err(|_| "qemu stdout was not utf-8")?;
        let stderr = String::from_utf8(output.stderr).map_err(|_| "qemu stderr was not utf-8")?;
        let summary = parse_core_test_output(&stdout, &stderr)?;

        if !output.status.success() {
            return Err(format!(
                "qemu test process failed on {} with status {}\nstdout:\n{}\nstderr:\n{}",
                board.env_name, output.status, stdout, stderr
            )
            .into());
        }

        if summary.failed != 0 {
            return Err(format!("embedded tests failed on {}", board.env_name).into());
        }

        Ok(summary)
    })
}

/// Runs the core-test stack-guard firmware under QEMU or on physical Pico2.
///
/// The test intentionally triggers the guard path and succeeds only when QEMU
/// reports the expected guard diagnostic, making it a focused regression for
/// kernel stack protection. OpenOCD instead checks STKOF at UsageFault entry
/// and the boot-configured MSPLIM, without relying on console output.
pub(crate) fn run_kernel_stack_guard_test_for_board(
    ctx: &TestContext,
    board: &str,
) -> Result<(), Box<dyn Error>> {
    let board = board_spec(board)?;
    let owned_ctx = ctx.with_fault("OXIDE_SE_KERNEL_STACK_GUARD_TEST");
    let ctx = &owned_ctx;

    if ctx.openocd().is_some() {
        if board.env_name != "raspi-pico2" {
            return Err("hardware stack guard observation is supported only on Pico2".into());
        }
        build_firmware(
            &ctx.build,
            FirmwareKind::CoreTest,
            None,
            board.env_name,
            "hardware",
        )?;
        return testing::openocd::run_stack_guard(
            ctx,
            board,
            &firmware_elf_path(FirmwareKind::CoreTest)?,
        );
    }

    testing::target::run_core(
        ctx,
        board,
        "qemu-kernel-stack-guard",
        "kernel-stack-guard",
        |output| {
            let stdout =
                String::from_utf8(output.stdout).map_err(|_| "qemu stdout was not utf-8")?;
            let stderr =
                String::from_utf8(output.stderr).map_err(|_| "qemu stderr was not utf-8")?;
            let combined = format!("{stdout}\n{stderr}");

            let expected_m_profile = "kernel MemManage: kernel stack overflow suspected";
            let expected_armv6m = "kernel ARMv6-M HardFault: kernel stack overflow suspected";
            if !combined.contains(expected_m_profile) && !combined.contains(expected_armv6m) {
                return Err(format!(
            "kernel stack guard test did not report the expected fault\nstdout:\n{stdout}\nstderr:\n{stderr}"
        )
        .into());
            }

            Ok(())
        },
    )
}

/// Runs the core-test RAM execute-never firmware under QEMU.
///
/// The embedded test attempts to branch to a RAM-resident `BX LR` instruction
/// while the kernel is active. A passing target must fault before returning,
/// proving that kernel-phase RAM-XN is actually enforced by the MPU.
pub(crate) fn run_kernel_ram_nx_test_for_board(
    ctx: &TestContext,
    board: &str,
) -> Result<(), Box<dyn Error>> {
    let board = board_spec(board)?;
    if ctx.openocd().is_some() {
        if board.env_name != "raspi-pico2" {
            return Err("hardware RAM NX observation is supported only on Pico2".into());
        }
        let ctx = ctx.with_fault("OXIDE_SE_KERNEL_RAM_NX_TEST");
        build_firmware(
            &ctx.build,
            FirmwareKind::CoreTest,
            None,
            board.env_name,
            "hardware",
        )?;
        return testing::openocd::run_ram_nx(
            &ctx,
            board,
            &firmware_elf_path(FirmwareKind::CoreTest)?,
        );
    }
    if !kernel_ram_nx_qemu_supported(board) {
        return Err(format!(
            "kernel RAM NX QEMU regression is currently validated only on boards with a clean RAM-NX fault path; {} is unsupported",
            board.env_name
        )
        .into());
    }

    let owned_ctx = ctx.with_fault("OXIDE_SE_KERNEL_RAM_NX_TEST");
    let ctx = &owned_ctx;

    testing::target::run_core(
        ctx,
        board,
        "qemu-kernel-ram-nx",
        "kernel-ram-nx",
        |output| {
            let stdout =
                String::from_utf8(output.stdout).map_err(|_| "qemu stdout was not utf-8")?;
            let stderr =
                String::from_utf8(output.stderr).map_err(|_| "qemu stderr was not utf-8")?;
            let combined = format!("{stdout}\n{stderr}");

            if combined.contains("TEST-UNSUPPORTED kernel-ram-nx") {
                return Err(format!(
                    "kernel RAM NX test is unsupported on {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
                    board.env_name
                )
                .into());
            }

            if combined.contains("TEST-FAIL kernel-ram-nx ram-execution-returned")
                || combined.contains("kernel RAM NX test did not fault")
            {
                return Err(format!(
            "kernel RAM NX test returned from RAM execution\nstdout:\n{stdout}\nstderr:\n{stderr}",
        )
                .into());
            }

            let expected_m_profile = "fatal MemManage";
            let expected_armv6m = "fatal ARMv6-M HardFault";
            if !combined.contains(expected_m_profile) && !combined.contains(expected_armv6m) {
                return Err(format!(
            "kernel RAM NX test did not report the expected fault\nstdout:\n{stdout}\nstderr:\n{stderr}"
        )
        .into());
            }

            Ok(())
        },
    )
}

/// Validates ping and response lengths 0, 16, 32, ..., 240, 255 bytes.
///
/// Its dedicated manifest selects only the `ping` module, so it isolates the
/// APDU transport and kernel main loop from Rustlet loading and GP management.
/// Nonempty patterns exercise both direct Le-driven output and case-4 echo
/// with one GET RESPONSE, including payload bytes resembling T=0 status/NULL.
pub(crate) fn run_kernel_ping_test_for_board(
    ctx: &TestContext,
    board: &str,
) -> Result<TestReport, Box<dyn Error>> {
    let board = board_spec(board)?;
    let test_result = testing::target::run_apdu(
        ctx,
        board,
        LayoutImageFormat::Elf,
        "kernel-ping",
        APDU_RESPONSE_TIMEOUT,
        |client| {
            let payload = [0x12, 0x34, 0x56, 0x78];
            let response = client.exchange(&CommandBuilder::kernel_ping(&payload))?;
            expect_response(response, &payload, (0x90, 0x00), "kernel ping")?;
            let mut command = CommandBuilder::kernel_ping(&[]);
            command.p1 = 2;
            expect_response(
                client.exchange(&command)?,
                &[],
                (0x90, 0x00),
                "kernel ping empty",
            )?;
            for len in (16..=240).step_by(16).chain(std::iter::once(255)) {
                let expected: Vec<u8> = (0..len).map(|index| index as u8).collect();
                let label = format!("kernel ping direct Le={len}");
                eprintln!("kernel-ping: {label}");
                command.p1 = 1;
                command.le = len as u8;
                expect_response(client.exchange(&command)?, &expected, (0x90, 0x00), &label)?;
                let label = format!("kernel ping GET RESPONSE length={len}");
                eprintln!("kernel-ping: {label}");
                expect_response(
                    client.exchange(&CommandBuilder::kernel_ping(&expected))?,
                    &expected,
                    (0x90, 0x00),
                    &label,
                )?;
            }
            Ok(())
        },
    );
    test_result?;

    Ok(TestReport::passed(34))
}

/// Exercises the kernel T=0 transport edge cases on the selected backend.
///
/// The scenario checks ATR delivery, no-data status handling, case-3 ingress,
/// case-2 egress, and case-4 in/out behavior without involving Rustlets.
pub(crate) fn run_kernel_t0_test_for_board(
    ctx: &TestContext,
    board: &str,
) -> Result<TestReport, Box<dyn Error>> {
    let board = board_spec(board)?;
    let test_result = testing::target::run_apdu(
        ctx,
        board,
        LayoutImageFormat::Elf,
        "kernel-t0",
        APDU_RESPONSE_TIMEOUT,
        |client| {
            eprintln!("kernel-t0: empty");
            expect_status(
                client.exchange(&CommandBuilder::process_no_data(0x00))?,
                (0x90, 0x00),
                "kernel_main_app empty",
            )?;

            eprintln!("kernel-t0: inbound");
            expect_status(
                client.exchange(&CommandBuilder::process_with_data(
                    0x02,
                    &[0x00, 0x01, 0x02, 0x03],
                ))?,
                (0x90, 0x00),
                "kernel_main_app inbound",
            )?;

            eprintln!("kernel-t0: outbound with 6C retry");
            let response = client.exchange(&CommandBuilder::process_no_data_with_le(0x04, 0x02))?;
            expect_response(
                response,
                &[0x00, 0x01, 0x02],
                (0x90, 0x00),
                "kernel_main_app outbound",
            )?;

            eprintln!("kernel-t0: in/out");
            let response = client.exchange(&CommandBuilder::process_with_data_and_le(
                0x06,
                &[0x00, 0x01, 0x02, 0x03],
                0x04,
            ))?;
            expect_response(
                response,
                &[0x03, 0x02, 0x01, 0x00],
                (0x90, 0x00),
                "kernel_main_app in/out",
            )?;

            Ok(())
        },
    );
    test_result?;

    Ok(TestReport::passed(4))
}

/// Verifies periodic SysTick delivery and the explicit top/bottom-half boundary.
pub(crate) fn run_kernel_timer_test_for_board(
    ctx: &TestContext,
    board: &str,
) -> Result<TestReport, Box<dyn Error>> {
    let board = board_spec(board)?;
    testing::target::run_apdu(
        ctx,
        board,
        LayoutImageFormat::Elf,
        "kernel-timer",
        APDU_RESPONSE_TIMEOUT,
        |client| {
            let first = client.exchange(&CommandBuilder::kernel_timer(0))?;
            let (first_top, first_bottom, first_nulls) = timer_counters(first)?;

            let second = client.exchange(&CommandBuilder::kernel_timer(1))?;
            let (second_top, second_bottom, second_nulls) = timer_counters(second)?;
            let elapsed_ticks = second_top.wrapping_sub(first_top);
            eprintln!(
                "kernel-timer: period=100ms top={first_top}->{second_top} bottom={first_bottom}->{second_bottom} null={first_nulls}->{second_nulls}"
            );
            if elapsed_ticks < 3 {
                return Err(format!(
                    "periodic timer advanced only {elapsed_ticks} times during the observation window"
                )
                .into());
            }
            if second_bottom.wrapping_sub(first_bottom) < 3 {
                return Err("bottom-half marker was not reached periodically".into());
            }
            if second_top.abs_diff(second_bottom) > 1 {
                return Err(format!(
                    "top/bottom-half counters diverged: top={second_top}, bottom={second_bottom}"
                )
                .into());
            }
            if second_nulls <= first_nulls {
                return Err("delayed APDU emitted no periodic T=0 NULL byte".into());
            }
            Ok(())
        },
    )?;
    Ok(TestReport::passed(3))
}

/// Verifies that a pending T=0 command emits one NULL byte every ten ticks.
///
/// The embedded command remains busy for thirty-two 100 ms ticks. The timer
/// owns all NULL transmission, so exactly three successful `0x60` writes must
/// occur before the real response starts.
pub(crate) fn run_kernel_null_byte_test_for_board(
    ctx: &TestContext,
    board: &str,
) -> Result<TestReport, Box<dyn Error>> {
    let board = board_spec(board)?;
    testing::target::run_apdu(
        ctx,
        board,
        LayoutImageFormat::Elf,
        "kernel-null-byte",
        APDU_RESPONSE_TIMEOUT,
        |client| {
            let before = client.exchange(&CommandBuilder::kernel_timer(0))?;
            let (before_top, _, before_nulls) = timer_counters(before)?;
            let after = client.exchange(&CommandBuilder::kernel_timer(2))?;
            let (after_top, _, after_nulls) = timer_counters(after)?;
            let elapsed_ticks = after_top.wrapping_sub(before_top);
            let emitted_nulls = after_nulls.wrapping_sub(before_nulls);
            eprintln!(
                "kernel-null-byte: period=1s ticks={elapsed_ticks} nulls={before_nulls}->{after_nulls}"
            );
            if !(32..=33).contains(&elapsed_ticks) {
                return Err(format!(
                    "NULL-byte observation lasted {elapsed_ticks} ticks instead of 32..=33"
                )
                .into());
            }
            if emitted_nulls != 3 {
                return Err(format!(
                    "expected three periodic T=0 NULL bytes, observed {emitted_nulls}"
                )
                .into());
            }
            Ok(())
        },
    )?;
    Ok(TestReport::passed(2))
}

fn timer_counters(response: T0Response) -> Result<(u32, u32, u32), Box<dyn Error>> {
    if response.status != (0x90, 0x00) || response.data.len() != 12 {
        return Err(format!(
            "kernel timer counter response malformed: len={}, status={:02X}{:02X}",
            response.data.len(),
            response.status.0,
            response.status.1
        )
        .into());
    }
    Ok((
        u32::from_be_bytes(response.data[..4].try_into().unwrap()),
        u32::from_be_bytes(response.data[4..8].try_into().unwrap()),
        u32::from_be_bytes(response.data[8..12].try_into().unwrap()),
    ))
}

/// Three complete boots; only the first programs the image. Each subsequent
/// boot runs normal registry initialization before reading the diagnostic tail.
/// Exercise the normal registry APIs and boot recovery, with no raw flash access.
pub(crate) fn run_kernel_registry_test_for_board(
    ctx: &TestContext,
    board: &str,
) -> Result<usize, Box<dyn Error>> {
    let board = board_spec(board)?;
    let mut target =
        testing::target::prepare_apdu_session(ctx, board, LayoutImageFormat::Elf, true)?;
    // 17 + 17 * 244 = 4165 payload bytes. Each 244-byte object plus
    // persistence header/CRC spans two 256-byte logical pages.
    let mut expected: Vec<Vec<u8>> = (0..18usize)
        .map(|id| {
            (0..if id == 0 { 17 } else { 244 })
                .map(|offset| ((id * 53 + offset * 7 + offset / 13) & 255) as u8)
                .collect()
        })
        .collect();
    let mut total = 0;
    for boot in 0..3 {
        let label = format!("kernel-registry-boot-{boot}");
        let mut scenario = |client: &mut ApduClient| {
            if boot == 0 {
                let missing = CommandBuilder::gp_command(0xa0, 2, 0, &[], 17);
                expect_response(
                    client.exchange(&missing)?,
                    &[],
                    (0x69, 0x85),
                    "registry starts empty",
                )?;
                total += 1;
                for (id, data) in expected.iter().enumerate() {
                    eprintln!("kernel-registry: write object {id}, {} bytes", data.len());
                    let write = CommandBuilder::gp_command(0xa0, 1, id as u8, data, 0);
                    expect_response(client.exchange(&write)?, &[], (0x90, 0), "registry write")?;
                    total += 1;
                }
            }
            for (id, data) in expected.iter().enumerate() {
                eprintln!(
                    "kernel-registry: boot {boot}, read object {id}, {} bytes",
                    data.len()
                );
                total += read_registry_object(client, id as u8, data)?;
            }
            if boot == 1 {
                // Replace one multi-page object with a shorter, different value.
                expected[1] = (0..31).map(|i| 0xe3u8.wrapping_sub(i * 3)).collect();
                let data = &expected[1];
                let write = CommandBuilder::gp_command(0xa0, 1, 1, data, 0);
                expect_response(
                    client.exchange(&write)?,
                    &[],
                    (0x90, 0),
                    "registry replacement",
                )?;
                total += 1 + read_registry_object(client, 1, data)?;
            }
            Ok(())
        };
        if boot == 0 {
            target.boot(&label, APDU_RESPONSE_TIMEOUT, &mut scenario)?;
        } else {
            target.reboot(&label, APDU_RESPONSE_TIMEOUT, &mut scenario)?;
        }
    }
    Ok(total)
}

/// Compares the complete object in a single response, including after reset.
fn read_registry_object(
    client: &mut ApduClient,
    id: u8,
    data: &[u8],
) -> Result<usize, Box<dyn Error>> {
    let read = CommandBuilder::gp_command(0xa0, 2, id, &[], data.len() as u8);
    expect_response(
        client.exchange(&read)?,
        data,
        (0x90, 0),
        &format!("registry object {id}"),
    )?;
    Ok(1)
}

pub(crate) fn run_kernel_flash_test_for_board(
    ctx: &TestContext,
    board: &str,
) -> Result<(), Box<dyn Error>> {
    let board = board_spec(board)?;
    let layout = read_target_memory_layout(board)?;
    let mut target =
        testing::target::prepare_apdu_session(ctx, board, LayoutImageFormat::Elf, true)?;
    let prefix = |marker| {
        [
            0x52, 0x4c, 0x4f, 0x53, 0x46, 0x4c, 0x53, 0x48, marker, 0x8e, 16, 0, 0xa5, 0xff, 0xff,
            0xff,
        ]
    };
    target.boot("kernel-flash-write-A5", APDU_RESPONSE_TIMEOUT, |client| {
        let info = client.exchange(&CommandBuilder::process_no_data_with_le(0x8e, 12))?;
        let start = layout
            .flash_base
            .checked_add(layout.flash_size)
            .and_then(|end| end.checked_sub(4096))
            .ok_or("invalid flash layout")?;
        let mut expected = Vec::new();
        expected.extend_from_slice(&(u32::try_from(start)?).to_le_bytes());
        expected.extend_from_slice(&16u32.to_le_bytes());
        expected.extend_from_slice(&256u32.to_le_bytes());
        expect_response(info, &expected, (0x90, 0), "diagnostic block geometry")?;
        eprintln!("kernel-flash: reserved block 0x{start:08X}, 4096 bytes; write A5");
        let mut write = CommandBuilder::process_no_data_with_le(0x8e, 16);
        write.p1 = 1;
        write.p2 = 0xa5;
        expect_response(
            client.exchange(&write)?,
            &prefix(0xa5),
            (0x90, 0),
            "write/read A5",
        )
    })?;
    target.reboot(
        "kernel-flash-read-A5-write-5A",
        APDU_RESPONSE_TIMEOUT,
        |client| {
            let mut read = CommandBuilder::process_no_data_with_le(0x8e, 16);
            read.p1 = 2;
            expect_response(
                client.exchange(&read)?,
                &prefix(0xa5),
                (0x90, 0),
                "A5 retained after complete boot",
            )?;
            let mut write = CommandBuilder::process_no_data_with_le(0x8e, 16);
            write.p1 = 1;
            write.p2 = 0x5a;
            expect_response(
                client.exchange(&write)?,
                &prefix(0x5a),
                (0x90, 0),
                "erase/rewrite 5A",
            )
        },
    )?;
    target.reboot("kernel-flash-read-5A", APDU_RESPONSE_TIMEOUT, |client| {
        let mut read = CommandBuilder::process_no_data_with_le(0x8e, 16);
        read.p1 = 2;
        expect_response(
            client.exchange(&read)?,
            &prefix(0x5a),
            (0x90, 0),
            "5A retained after complete boot",
        )
    })
}

/// Exercises kernel-local crypto APIs on the selected backend without entering a Rustlet.
///
/// The scenario runs through the same kernel-owned APDU plumbing as
/// `test kernel_t0`, but the handlers call `oxi_core::core::crypto` directly.
/// This keeps runtime syscalls and Rustlet isolation out of the diagnostic
/// path when debugging target-specific crypto behavior.
pub(crate) fn run_kernel_crypto_test_for_board(
    ctx: &TestContext,
    board: &str,
    bench: Option<&KernelCryptoBench>,
) -> Result<TestReport, Box<dyn Error>> {
    const AES128_NIST_CIPHERTEXT: [u8; 16] = [
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19,
        0x7d,
    ];

    let board = board_spec(board)?;
    let test_result = testing::target::run_apdu(
        ctx,
        board,
        LayoutImageFormat::Elf,
        "kernel-crypto",
        if bench.is_some() {
            KERNEL_CRYPTO_BENCH_TIMEOUT
        } else {
            APDU_RESPONSE_TIMEOUT
        },
        |client| {
            if let Some(bench) = bench {
                return run_kernel_crypto_bench(client, board.env_name, bench);
            }

            eprintln!("kernel-crypto: random");
            let random = client.exchange(&CommandBuilder::process_no_data_with_le(0x80, 0x10))?;
            if random.status != (0x90, 0x00) || random.data.len() != 16 {
                return Err(format!(
                "kernel crypto random: expected 16 bytes and status 9000, got data {:02X?} and status {:02X?}",
                random.data, random.status
            )
            .into());
            }

            eprintln!("kernel-crypto: AES-128 CBC");
            expect_response(
                client.exchange(&CommandBuilder::process_no_data_with_le(0x82, 0x10))?,
                &AES128_NIST_CIPHERTEXT,
                (0x90, 0x00),
                "kernel crypto AES-128 CBC",
            )?;

            eprintln!("kernel-crypto: P-256 keygen");
            let start = Instant::now();
            let p256 = exchange_kernel_crypto(
                client,
                &CommandBuilder::process_no_data_with_le(0x84, 0x41),
            )?;
            println!(
                "KERNEL-CRYPTO-TIMING board={} op=p256_generate_keypair apdu_elapsed_ms={}",
                board.env_name,
                start.elapsed().as_millis()
            );
            if p256.status != (0x90, 0x00) || p256.data.len() != 65 || p256.data[0] != 0x04 {
                return Err(format!(
                "kernel crypto P-256 keygen: expected uncompressed public key and status 9000, got data {:02X?} and status {:02X?}",
                p256.data, p256.status
            )
            .into());
            }

            Ok(())
        },
    );
    test_result?;

    Ok(TestReport::passed(if bench.is_some() { 1 } else { 3 }))
}

fn exchange_kernel_crypto(
    client: &mut ApduClient,
    command: &OwnedT0Command,
) -> Result<T0Response, Box<dyn Error>> {
    let mut command = command.clone();
    if matches!(
        command.ins,
        0x84 | KernelCryptoBench::INS_P256_GENERATE_KEYPAIR
    ) {
        command.p1 = 1;
        command.lc = 1;
        command.data = vec![0];
    }
    // Key generation keeps its case-4 coverage, with the complete result
    // retrieved from the shared APDU buffer in one GET RESPONSE.
    client.exchange(&command)
}

pub(crate) fn run_kernel_crypto_bench(
    client: &mut ApduClient,
    board: &str,
    bench: &KernelCryptoBench,
) -> Result<(), Box<dyn Error>> {
    eprintln!("kernel-crypto-bench: {}", bench.op_name());
    let command = bench.command();
    let start = Instant::now();
    let response = exchange_kernel_crypto(client, &command)?;
    let elapsed = start.elapsed();
    bench.verify_response(&response)?;
    println!(
        "KERNEL-CRYPTO-BENCH board={} op={} elapsed_ms={} data={}",
        board,
        bench.op_name(),
        elapsed.as_millis(),
        hex_bytes_upper(&response.data)
    );
    Ok(())
}
