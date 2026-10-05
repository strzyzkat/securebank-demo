#!/usr/bin/env python3
"""
Extensible AI Security Gate & Auto-Patcher for Android Pull Requests.

Evaluates PR diffs and project context against a registry of Android security guards,
compiles and verifies AI-generated patches with Gradle, commits the fix directly to
the PR branch, and posts a detailed root-cause and diff explanation on the PR.
"""

from dataclasses import dataclass
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path


GEMINI_MODEL = "gemini-3.8-flash"
MANIFEST_PATH = Path("app/src/main/AndroidManifest.xml")
AUTO_FIX_COMMIT_PREFIX = "fix(security):"


@dataclass(frozen=True)
class SecurityGuard:
    guard_id: str
    cwe: str
    title: str
    detection_criteria: str
    remediation_strategy: str


# Registry of security guards. Add new SecurityGuard entries here to extend coverage.
SECURITY_GUARDS: list[SecurityGuard] = [
    SecurityGuard(
        guard_id="intent-redirection",
        cwe="CWE-940",
        title="Android Intent Redirection (Confused Deputy)",
        detection_criteria=(
            "An exported component (Activity, Service, or BroadcastReceiver) extracts a nested "
            "Intent from incoming extras (e.g., getParcelableExtra, IntentCompat.getParcelableExtra, "
            "or Bundle.getParcelable) and passes it to startActivity, startActivities, "
            "startActivityForResult, startService, startForegroundService, bindService, or "
            "sendBroadcast without verifying the destination component or stripping URI grant flags."
        ),
        remediation_strategy=(
            "1. Strip dangerous URI permission flags on the nested Intent using "
            "redirectIntent.removeFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or "
            "Intent.FLAG_GRANT_WRITE_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or "
            "Intent.FLAG_GRANT_PREFIX_URI_PERMISSION).\n"
            "2. Resolve the target component using "
            "val targetInfo = redirectIntent.resolveActivityInfo(packageManager, 0) and only launch "
            "redirectIntent when targetInfo != null && targetInfo.exported && "
            "targetInfo.packageName != packageName, blocking access to internal or non-exported "
            "components."
        ),
    ),
    SecurityGuard(
        guard_id="pending-intent-mutability",
        cwe="CWE-927",
        title="Mutable or Implicit PendingIntent Exposure",
        detection_criteria=(
            "A PendingIntent is created with PendingIntent.FLAG_MUTABLE wrapping an implicit Intent "
            "(missing an explicit ComponentName or package), or is constructed without "
            "PendingIntent.FLAG_IMMUTABLE when mutability is not strictly required."
        ),
        remediation_strategy=(
            "Make the wrapped Intent explicit (set ComponentName or class) and replace "
            "PendingIntent.FLAG_MUTABLE with PendingIntent.FLAG_IMMUTABLE."
        ),
    ),
    SecurityGuard(
        guard_id="improper-component-export",
        cwe="CWE-926",
        title="Unprotected Exported Android Component",
        detection_criteria=(
            "A sensitive internal Activity, Service, BroadcastReceiver, or ContentProvider "
            "(such as one performing financial transfers, account mutations, or file access) "
            "is marked android:exported=\"true\" in AndroidManifest.xml without a signature-level "
            "android:permission or caller identity verification."
        ),
        remediation_strategy=(
            "Set android:exported=\"false\" on internal components in AndroidManifest.xml or "
            "enforce caller verification before executing sensitive state changes."
        ),
    ),
    SecurityGuard(
        guard_id="insecure-webview-bridge",
        cwe="CWE-749",
        title="Insecure WebView Configuration or JavaScript Interface",
        detection_criteria=(
            "A WebView enables addJavascriptInterface on untrusted content, enables "
            "allowFileAccessFromFileURLs or allowUniversalAccessFromFileURLs, or loads arbitrary "
            "URLs from unvalidated Intent extras."
        ),
        remediation_strategy=(
            "Disable allowFileAccessFromFileURLs and allowUniversalAccessFromFileURLs, and validate "
            "any URL loaded from an Intent against an explicit HTTPS origin allowlist."
        ),
    ),
]


def run_cmd(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(args, text=True, capture_output=True, check=check)


def get_last_commit_subject() -> str:
    res = run_cmd(["git", "log", "-1", "--pretty=%s"], check=False)
    return res.stdout.strip()


def get_pr_diff(base_ref: str) -> str:
    run_cmd(["git", "fetch", "origin", base_ref], check=False)
    res = run_cmd(["git", "diff", f"origin/{base_ref}...HEAD"], check=False)
    return res.stdout


def get_project_source_files(base_ref: str) -> dict[str, str]:
    """Return modified files plus all app source files for cross-component analysis."""
    diff_res = run_cmd(["git", "diff", "--name-only", f"origin/{base_ref}...HEAD"], check=False)
    changed_paths = {
        Path(line.strip())
        for line in diff_res.stdout.splitlines()
        if line.strip()
    }

    relevant_Changed = [
        p for p in changed_paths
        if p.exists() and p.suffix in {".kt", ".java", ".xml"} and "app/src/main" in str(p)
    ]
    if not relevant_Changed:
        return {}

    all_app_sources: dict[str, str] = {}
    for root_file in sorted(Path("app/src/main/java").rglob("*")):
        if root_file.is_file() and root_file.suffix in {".kt", ".java"}:
            all_app_sources[str(root_file)] = root_file.read_text(encoding="utf-8")

    return all_app_sources


def build_guards_prompt_section(guards: list[SecurityGuard]) -> str:
    blocks = []
    for idx, g in enumerate(guards, start=1):
        blocks.append(
            f"{idx}. [{g.guard_id}] {g.cwe} - {g.title}\n"
            f"   Detection criteria: {g.detection_criteria}\n"
            f"   Required remediation strategy:\n   {g.remediation_strategy}"
        )
    return "\n\n".join(blocks)


def call_gemini(
    api_key: str,
    manifest_xml: str,
    pr_diff: str,
    source_files: dict[str, str],
    guards: list[SecurityGuard],
) -> dict:
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={api_key}"

    files_section = "\n\n".join(
        f"--- FILE: {path} ---\n{content}" for path, content in source_files.items()
    )
    guards_section = build_guards_prompt_section(guards)

    prompt = f"""You are an automated Android application security gate in a CI/CD pipeline.
Evaluate the Pull Request diff alongside AndroidManifest.xml and the application source files against the registered security guards below.

=== REGISTERED SECURITY GUARDS ===
{guards_section}

=== INSTRUCTIONS ===
1. Correlate the PR diff with AndroidManifest.xml and all application source files. Look at how exported components interact with non-exported components (such as `TransferMoneyActivity`).
2. If one or more guards are violated by the code in this PR:
   - Set `vulnerable` to `true`.
   - Populate `findings` with one entry per violated guard, explaining clearly:
     * `why_dangerous`: How an attacker or external app can exploit the vulnerability in this codebase.
     * `how_patched`: How the generated patch neutralizes the attack vector.
   - Populate `patched_files` with the complete, compilable file content for every file that needs modification to fix all findings.
   - Preserve all existing package declarations, imports, UI composables, and helper methods so `./gradlew :app:compileDebugKotlin :app:testDebugUnitTest` succeeds without errors.
3. If no security guard is violated, set `vulnerable` to `false` and return empty arrays for `findings` and `patched_files`.

--- ANDROID MANIFEST ({MANIFEST_PATH}) ---
{manifest_xml}

--- PULL REQUEST DIFF ---
{pr_diff}

--- APPLICATION SOURCE FILES ---
{files_section}
"""

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "responseMimeType": "application/json",
            "responseSchema": {
                "type": "OBJECT",
                "properties": {
                    "vulnerable": {"type": "BOOLEAN"},
                    "findings": {
                        "type": "ARRAY",
                        "items": {
                            "type": "OBJECT",
                            "properties": {
                                "guard_id": {"type": "STRING"},
                                "cwe": {"type": "STRING"},
                                "title": {"type": "STRING"},
                                "file": {"type": "STRING"},
                                "why_dangerous": {"type": "STRING"},
                                "how_patched": {"type": "STRING"},
                            },
                            "required": [
                                "guard_id",
                                "cwe",
                                "title",
                                "file",
                                "why_dangerous",
                                "how_patched",
                            ],
                        },
                    },
                    "patched_files": {
                        "type": "ARRAY",
                        "items": {
                            "type": "OBJECT",
                            "properties": {
                                "path": {"type": "STRING"},
                                "content": {"type": "STRING"},
                            },
                            "required": ["path", "content"],
                        },
                    },
                },
                "required": ["vulnerable", "findings", "patched_files"],
            },
        },
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=90) as resp:
        body = json.loads(resp.read().decode("utf-8"))

    text = body["candidates"][0]["content"]["parts"][0]["text"]
    return json.loads(text)


def verify_gradle_build() -> tuple[bool, str]:
    print("Running Gradle compile and unit test verification...")
    res = run_cmd(["./gradlew", ":app:compileDebugKotlin", ":app:testDebugUnitTest"], check=False)
    output = (res.stdout or "") + "\n" + (res.stderr or "")
    return res.returncode == 0, output


def commit_and_push_patch(head_ref: str, paths: list[str], cwes: list[str]) -> tuple[str, str]:
    cwe_label = ", ".join(dict.fromkeys(cwes)) or "CWE-940"
    run_cmd(["git", "config", "user.name", "github-actions[bot]"])
    run_cmd(["git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com"])
    for p in paths:
        run_cmd(["git", "add", p])
    commit_msg = f"{AUTO_FIX_COMMIT_PREFIX} auto-remediate {cwe_label} vulnerability"
    run_cmd(["git", "commit", "-m", commit_msg])
    sha = run_cmd(["git", "rev-parse", "--short", "HEAD"]).stdout.strip()
    patch_diff = run_cmd(["git", "show", "--format=", "--unified=3", "HEAD"]).stdout.strip()
    if head_ref:
        run_cmd(["git", "push", "origin", f"HEAD:{head_ref}"])
    return sha, patch_diff


def format_pr_comment(findings: list[dict], commit_sha: str, patch_diff: str) -> str:
    rows = "\n".join(
        f"| `{f['guard_id']}` | **{f['cwe']}** | {f['title']} | `{f['file']}` |"
        for f in findings
    )

    details = "\n\n".join(
        f"#### {f['cwe']}: {f['title']} (`{f['file']}`)\n"
        f"- **Why this was blocked:** {f['why_dangerous']}\n"
        f"- **How the automatic patch fixes it:** {f['how_patched']}"
        for f in findings
    )

    return (
        f"## Security Gate Blocked PR & Applied Automatic Patch (`{commit_sha}`)\n\n"
        f"| Guard | CWE | Vulnerability | File |\n"
        f"| :--- | :--- | :--- | :--- |\n"
        f"{rows}\n\n"
        f"### Root cause & remediation details\n\n"
        f"{details}\n\n"
        f"### Applied security patch (`{commit_sha}`)\n\n"
        f"```diff\n{patch_diff}\n```"
    )


def post_pr_comment(token: str, repo: str, pr_number: str, markdown_body: str) -> None:
    if not token or not repo or not pr_number:
        print("Skipping PR comment (missing GitHub environment variables).")
        return

    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    req = urllib.request.Request(
        url,
        data=json.dumps({"body": markdown_body}).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        print(f"Posted PR security review comment (HTTP {resp.status}).")


def main() -> int:
    last_subject = get_last_commit_subject()
    if last_subject.startswith(AUTO_FIX_COMMIT_PREFIX):
        print(f"Latest commit ('{last_subject}') is an automated security patch. Verifying build...")
        ok, output = verify_gradle_build()
        if not ok:
            print(output, file=sys.stderr)
            return 1
        print("Build and unit tests succeeded.")
        return 0

    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        print("ERROR: GEMINI_API_KEY environment variable is not set.", file=sys.stderr)
        return 1

    base_ref = os.environ.get("BASE_REF", "main")
    head_ref = os.environ.get("HEAD_REF", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    pr_number = os.environ.get("PR_NUMBER", "")
    github_token = os.environ.get("GITHUB_TOKEN", "")

    pr_diff = get_pr_diff(base_ref)
    source_files = get_project_source_files(base_ref)

    if not source_files:
        print("No Android source or manifest files modified in this PR. Running standard verification...")
        ok, output = verify_gradle_build()
        if not ok:
            print(output, file=sys.stderr)
            return 1
        return 0

    manifest_xml = MANIFEST_PATH.read_text(encoding="utf-8") if MANIFEST_PATH.exists() else ""

    print(
        f"Evaluating PR against {len(SECURITY_GUARDS)} security guards "
        f"across {len(source_files)} source file(s) using {GEMINI_MODEL}..."
    )
    result = call_gemini(api_key, manifest_xml, pr_diff, source_files, SECURITY_GUARDS)

    if not result.get("vulnerable", False):
        print("All security guards passed. Verifying build...")
        ok, output = verify_gradle_build()
        if not ok:
            print(output, file=sys.stderr)
            return 1
        return 0

    findings = result.get("findings", [])
    for f in findings:
        print(f"[{f['guard_id']}] {f['cwe']} ({f['file']}): {f['why_dangerous']}")

    patched_files = result.get("patched_files", [])
    modified_paths: list[str] = []
    backups: dict[Path, str] = {}

    for item in patched_files:
        file_path = Path(item["path"])
        if file_path.exists():
            backups[file_path] = file_path.read_text(encoding="utf-8")
        file_path.write_text(item["content"], encoding="utf-8")
        modified_paths.append(str(file_path))

    ok, build_output = verify_gradle_build()
    if not ok:
        print("Generated patch failed to compile; restoring original files.", file=sys.stderr)
        print(build_output, file=sys.stderr)
        for file_path, original in backups.items():
            file_path.write_text(original, encoding="utf-8")
        return 1

    cwes = [f.get("cwe", "CWE-940") for f in findings]
    commit_sha, patch_diff = commit_and_push_patch(head_ref, modified_paths, cwes)
    print(f"Pushed verified security remediation commit: {commit_sha}")

    comment_md = format_pr_comment(findings, commit_sha, patch_diff)
    post_pr_comment(github_token, repo, pr_number, comment_md)

    # Return non-zero so the check on the vulnerable PR commit is marked as Failed.
    return 1


if __name__ == "__main__":
    sys.exit(main())
