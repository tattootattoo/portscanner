from portscanner.cli import BUILTIN_DEFAULTS, _load_profile, build_parser


def test_load_profile_reads_scan_table(tmp_path):
    profile = tmp_path / "test.toml"
    profile.write_text('[scan]\nhost = "10.0.0.5"\nconcurrency = 250\n')
    data = _load_profile(str(profile))
    assert data["host"] == "10.0.0.5"
    assert data["concurrency"] == 250


def test_load_profile_reads_flat_table(tmp_path):
    profile = tmp_path / "flat.toml"
    profile.write_text('host = "10.0.0.5"\n')
    data = _load_profile(str(profile))
    assert data["host"] == "10.0.0.5"


def test_cli_flags_default_to_suppress_when_unset():
    """The flag must be entirely absent from the namespace if the user
    didn't set it — so a TOML profile can fill it in without the CLI
    overwriting it with an empty default value."""
    args = build_parser().parse_args(["--host", "10.0.0.1"])
    ns = vars(args)
    assert "ports" not in ns
    assert "transport" not in ns
    assert "no_identify" not in ns
    assert "all_states" not in ns
    assert ns["host"] == "10.0.0.1"


def test_cli_explicit_flag_present_when_set():
    args = build_parser().parse_args(["--host", "10.0.0.1", "--ports", "3868"])
    ns = vars(args)
    assert ns["ports"] == "3868"


def test_merge_priority_cli_overrides_profile_overrides_builtin(tmp_path):
    profile = tmp_path / "p.toml"
    profile.write_text('[scan]\nconcurrency = 100\ntransport = "tcp"\n')

    args = build_parser().parse_args([
        "--host", "10.0.0.1", "--profile", str(profile), "--concurrency", "999",
    ])

    merged = dict(BUILTIN_DEFAULTS)
    merged.update(_load_profile(args.profile))
    explicit = {k: v for k, v in vars(args).items() if k != "profile"}
    merged.update(explicit)

    assert merged["concurrency"] == 999  # an explicit CLI flag overrides the profile
    assert merged["transport"] == "tcp"  # the profile overrides BUILTIN_DEFAULTS ("all")
    assert merged["ports"] == BUILTIN_DEFAULTS["ports"]  # nobody set it — stays at the default
