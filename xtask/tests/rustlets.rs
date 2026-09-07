#[test]
fn rustlet_declare_app_forms_build_as_fae() {
    let summary = xtask::run_rustlet_macro_build_tests()
        .unwrap_or_else(|err| panic!("rustlet declare_app! build tests failed: {err}"));
    assert_eq!(
        summary.total, 3,
        "unexpected rustlet macro build test count"
    );
}
