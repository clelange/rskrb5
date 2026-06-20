# Publishing And Release Plan

`rskrb5` is prepared for a narrow `0.1.x` crates.io preview. The first
publishable surface is intentionally limited to client-side login,
file-backed keytab and credential-cache handling, default config loading, and
HTTP Negotiate/SPNEGO header generation and password-change flows on
`TokioClient` plus wrapper clients.

## Distribution Model

- GitHub is the source of truth for development, CI, issues, examples, Docker
  integration tests, tags, and release notes.
- crates.io is the right public Rust distribution channel once the decision
  gate is complete. A Kerberos client/service library needs normal Cargo
  dependency resolution, docs.rs rendering, semver metadata, and discoverability
  in the Rust ecosystem.
- GitHub-only distribution remains acceptable for unreleased development
  branches, but the `0.1.x` preview is intended for normal Cargo dependency
  resolution through crates.io.

## Release Gate

Before publishing a release, the crate should have:

- A positive decision-gate result in `docs/compatibility-report.md`.
- A first supported scope stated in the README, with unsupported gokrb5 features
  called out plainly.
- A semver version greater than `0.0.0`; use `0.1.0` for the first public API
  preview.
- No AGPL or LGPL dependency in default/core features. Any such dependency must
  be isolated behind a clearly named, non-default feature.
- A clean package manifest with repository, license, README, keywords,
  categories, examples, and feature flags that match the published support
  story.
- Local and CI success for the release preflight below.
- A crates.io owner account and an additional owner invited before the first
  real release, so the crate is not locked to one maintainer.

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
INTEGRATION=1 TESTAD=1 cargo test --all-features --test client_ad_integration
```

`TESTPRIVILEGED=1` and `TEST_KPASSWD=1` are additive gates on top of
`INTEGRATION=1`; the local runner enables `TESTPRIVILEGED=1` by default and
documents fixture setup in [`gated-integration.md`](gated-integration.md).
`TESTAD=1` uses the Active Directory lab endpoints documented in the README and
remains optional until that lab is maintained in CI.

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
   summarizes supported features, known gaps, and the matching compatibility
   report revision.

## Versioning Policy

- `0.x` releases may make breaking API changes, but each release should still
  state compatibility changes explicitly.
- Cryptographic behavior, wire formats, and parsed data structures should be
  treated as compatibility-sensitive even before `1.0`.
- Raise MSRV only in a minor release and document the reason.
- Stabilize toward `1.0` only after the gokrb5-equivalent client, service,
  SPNEGO, PAC, config, keytab, ccache, and integration-test contracts are
  consistently passing.
