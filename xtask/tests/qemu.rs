#[test]
fn core_test_runs_on_supported_system_qemu_boards() {
    // Pico1 uses the repository's dedicated QEMU fork and is validated by the
    // Pico1 scenarios; b-l475e-iot01a is intentionally build-only.
    for board in ["mps2-an385", "olimex-stm32-h405"] {
        let summary = xtask::run_qemu_test_for_board(board)
            .unwrap_or_else(|err| panic!("qemu test failed on {board}: {err}"));
        assert_eq!(summary.failed, 0, "embedded failures on {board}");
        assert!(
            summary.total >= 3,
            "unexpected embedded test count on {board}"
        );
    }
}
