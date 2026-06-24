# Publishing And Release Plan

`rskrb5` has a published `0.1` preview. The next pre-`1.0` preview may make
breaking Rust API changes to reduce compatibility shims and tighten the public
surface around client-side login, file-backed keytab and credential-cache
handling, default config loading, HTTP Negotiate/SPNEGO header generation, and
password-change flows.

## Distribution Model

- GitHub is the source of truth for development, CI, issues, examples, Docker
  integration tests, tags, and release notes.
- crates.io is the public Rust distribution channel. A Kerberos client/service
  library needs normal Cargo dependency resolution, docs.rs rendering, semver
  metadata, and discoverability in the Rust ecosystem.
- GitHub-only distribution remains acceptable for unreleased development
  branches, but release previews are distributed through crates.io.

## Release Gate

Before publishing a release, the crate should have:

- A positive decision-gate result in `docs/compatibility-report.md`.
- A supported preview scope stated in the README, with unsupported gokrb5
  features called out plainly.
- Release notes that list intentional breaking API changes for the preview.
- A semver version matching the release intent. Use a new minor version such as
  `0.2.0` for breaking pre-`1.0` API changes.
- No AGPL or LGPL dependency in default/core features. Any such dependency must
  be isolated behind a clearly named, non-default feature.
- A clean package manifest with repository, license, README, keywords,
  categories, examples, and feature flags that match the published support
  story.
- Local and CI success for the release preflight below.
- At least two crates.io owners before any release intended for external users,
  so the crate is not locked to one maintainer.

## Release Preflight

Run these checks before tagging or publishing:

```sh
cargo fmt --check
cargo check --no-default-features
cargo check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo doc --all-features --no-deps
cargo package --locked
prek run --all-files --stage pre-push
```

For integration coverage, run or dispatch the gated Docker jobs that apply to
the release:

```sh
scripts/run-gated-integration.sh run --test client_integration
TEST_KPASSWD=1 scripts/run-gated-integration.sh run --test client_integration
INTEGRATION=1 TESTAD=1 TESTAD_REQUIRED=1 scripts/check-ad-integration-env.py
INTEGRATION=1 TESTAD=1 TESTAD_REQUIRED=1 cargo test --all-features --test client_ad_integration -- --nocapture
```

`TESTPRIVILEGED=1` and `TEST_KPASSWD=1` are additive gates on top of
`INTEGRATION=1`; the local runner enables `TESTPRIVILEGED=1` by default and
documents fixture setup in [`gated-integration.md`](gated-integration.md).
`TESTAD=1` uses the Active Directory lab endpoints documented in
[`ad-integration.md`](ad-integration.md) and remains optional until that lab is
maintained in CI. Use `TESTAD_REQUIRED=1` whenever an AD run is used as release
evidence. The manual GitHub Actions `test_ad=true` gate runs on a self-hosted
`rskrb5-ad` runner and preflights the required endpoint and keytab secrets
before running `tests/client_ad_integration.rs`. Use
`scripts/check-github-ad-gate.py` to verify those GitHub-side prerequisites
before dispatching the AD gate.

## crates.io Release

When the gate is met:

1. Confirm `Cargo.toml` has the intended semver version and is not marked
   `publish = false`.
2. Regenerate `Cargo.lock` if dependency resolution changes.
3. Run the release preflight and at least the default Docker MIT KDC
   integration job.
4. Inspect the packaged contents:

   ```sh
   cargo package --locked --list
   ```

5. Publish only after a successful dry run:

   ```sh
   cargo publish --locked --dry-run
   cargo publish --locked
   ```

6. Tag the published revision as `vX.Y.Z` and create a GitHub release that
   summarizes supported features, known gaps, breaking API changes, and the
   matching compatibility report revision.

## Versioning Policy

- `0.x` releases may make breaking API changes, but each release should still
  state compatibility changes explicitly.
- Prefer a minor version bump for breaking pre-`1.0` API changes, even though
  Cargo permits broader `0.x` breakage.
- Cryptographic behavior, wire formats, and parsed data structures should be
  treated as compatibility-sensitive even before `1.0`.
- Raise MSRV only in a minor release and document the reason.
- Stabilize toward `1.0` only after the gokrb5-equivalent client, service,
  SPNEGO, PAC, config, keytab, ccache, and integration-test contracts are
  consistently passing.
