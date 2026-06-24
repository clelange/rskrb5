#!/usr/bin/env python3
"""Check GitHub-side readiness for the strict AD integration gate."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys


REQUIRED_SECRETS = [
    "TEST_AD_USER_KDC_ADDR",
    "TEST_AD_RESOURCE_KDC_ADDR",
    "TEST_AD_USER_ADMIN_ADDR",
    "TEST_AD_RESOURCE_ADMIN_ADDR",
    "TEST_AD_TESTUSER1_KEYTAB_BASE64",
    "TEST_AD_TESTUSER2_KEYTAB_BASE64",
    "TEST_AD_TESTUSER3_KEYTAB_BASE64",
    "TEST_AD_SYSHTTP_KEYTAB_BASE64",
]

REQUIRED_RUNNER_LABELS = {"self-hosted", "linux", "x64", "rskrb5-ad"}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check required GitHub runner/secrets for test_ad=true."
    )
    parser.add_argument(
        "--dispatch",
        action="store_true",
        help="Dispatch CI with test_ad=true when all prerequisites are ready.",
    )
    parser.add_argument(
        "--ref",
        default="main",
        help="Git ref to dispatch when --dispatch is used. Defaults to main.",
    )
    args = parser.parse_args()

    repo = gh_json(["repo", "view", "--json", "nameWithOwner"])["nameWithOwner"]
    print(f"Repository: {repo}")

    missing_secrets = sorted(set(REQUIRED_SECRETS) - actions_secret_names())
    if missing_secrets:
        print("Missing Actions secrets:")
        for name in missing_secrets:
            print(f"  - {name}")
    else:
        print("Actions secrets: all required AD secrets are present.")

    matching_runners, runners = ad_runner_inventory(repo)
    if matching_runners:
        print("AD runners:")
        for runner in matching_runners:
            labels = ", ".join(sorted(runner["labels"]))
            print(f"  - {runner['name']} ({runner['status']}, labels: {labels})")
    elif runners:
        print("Registered self-hosted runners:")
        for runner in runners:
            labels = ", ".join(sorted(runner["labels"]))
            print(f"  - {runner['name']} ({runner['status']}, labels: {labels})")
        print(
            "No online runner has the complete required label set: "
            + ", ".join(sorted(REQUIRED_RUNNER_LABELS))
        )
    else:
        print("No self-hosted runners are registered for this repository.")
        print("Required runner labels: " + ", ".join(sorted(REQUIRED_RUNNER_LABELS)))

    errors = []
    if missing_secrets:
        errors.append("required Actions secrets are missing")
    if not matching_runners:
        if runners:
            errors.append(
                "no online self-hosted runner has the complete rskrb5-ad label set"
            )
        else:
            errors.append("no self-hosted runner is registered")

    if errors:
        sys.stdout.flush()
        print("\nGitHub AD gate is not ready:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        print(
            "\nSee docs/github-ad-gate-setup.md for the runner and secret setup.",
            file=sys.stderr,
        )
        return 1

    print("GitHub AD gate is ready.")
    if args.dispatch:
        gh(
            [
                "workflow",
                "run",
                "ci.yml",
                "--ref",
                args.ref,
                "--field",
                "integration=false",
                "--field",
                "test_ad=true",
                "--field",
                "test_kpasswd=false",
            ]
        )
        print(f"Dispatched ci.yml with test_ad=true on {args.ref}.")
    return 0


def actions_secret_names() -> set[str]:
    result = gh_json(["api", "repos/:owner/:repo/actions/secrets"])
    return {secret["name"] for secret in result.get("secrets", [])}


def ad_runner_inventory(
    repo: str,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    result = gh_json(["api", f"repos/{repo}/actions/runners"])
    inventory = []
    runners = []
    for runner in result.get("runners", []):
        labels = {label["name"] for label in runner.get("labels", [])}
        entry = {
            "name": runner["name"],
            "status": runner["status"],
            "labels": labels,
        }
        inventory.append(entry)
        if REQUIRED_RUNNER_LABELS.issubset(labels) and runner.get("status") == "online":
            runners.append(entry)
    return runners, inventory


def gh_json(args: list[str]) -> dict[str, object]:
    output = gh(args)
    return json.loads(output)


def gh(args: list[str]) -> str:
    completed = subprocess.run(
        ["gh", *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout


if __name__ == "__main__":
    raise SystemExit(main())
