register_kernel_app_modules! {
    {
        name: "registry-test",
        module: registry_test,
        path: "kernel_main_app/registry_test.rs",
        hooks: [apdu_filter],
    },
    {
        name: "ping",
        module: ping,
        path: "kernel_main_app/ping.rs",
        hooks: [apdu_filter],
    },
    {
        name: "t0-test",
        module: t0_test,
        path: "kernel_main_app/t0_test.rs",
        hooks: [apdu_filter],
    },
    {
        name: "timer-test",
        module: timer_test,
        path: "kernel_main_app/timer_test.rs",
        hooks: [apdu_filter],
    },
    {
        name: "crypto-self-test",
        module: crypto_self_test,
        path: "kernel_main_app/crypto_self_test.rs",
        hooks: [apdu_filter],
    },
    {
        name: "flash-probe",
        module: flash_probe,
        path: "kernel_main_app/flash_probe.rs",
        hooks: [apdu_filter],
    },
    {
        name: "kernel-stack-monitor",
        module: kernel_stack_monitor,
        path: "kernel_main_app/kernel_stack_monitor.rs",
        hooks: [apdu_filter, after_apdu, preserve_clear_apdu_session],
    },
    {
        name: "rustlet-stack-monitor",
        module: rustlet_stack_monitor,
        path: "kernel_main_app/rustlet_stack_monitor.rs",
        hooks: [
            apdu_filter,
            before_rustlet,
            after_rustlet,
            preserve_clear_apdu_session,
        ],
    },
}
