#!/usr/bin/env python3
"""
Automated CI/CD Security Gate for Android Intent Redirection (CWE-940).
Analyzes PR diffs alongside AndroidManifest.xml using Google Gemini, blocks vulnerable
commits, and pushes a compiled security patch directly to the PR branch.
"""

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path


GEMINI_MODEL = "gemini-3.8-flash"
MANIFEST_PATH = Path("app/src/main/AndroidManifest.xml")


def run_cmd(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(args, text=True, capture_output=True, check=check)


def get_last_commit_subject() -> str:
    res = run_cmd(["git", "log", "-1", "--pretty=%s"], check=False)
    return res.stdout.strip()


def get_pr_diff(base_ref: str) -> str:
    run_cmd(["git", "fetch", "origin", base_ref], check=False)
    res = run_cmd(["git", "diff", f"origin/{base_ref}...HEAD"], check=False)
    return res.stdout


def get_changed_source_files(base_ref: str) -> list[Path]:
    res = run_cmd(["git", "diff", "--name-only", f"origin/{base_ref}...HEAD"], check=False)
    files = []
    for line in res.stdout.splitlines():
        path = Path(line.strip())
        if path.exists() and path.suffix in {".kt", ".java"} and "app/src/main" in str(path):
            files.append(path)
    return files


def call_gemini(api_key: str, manifest_xml: str, pr_diff: str, source_files: dict[str, str]) -> dict:
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={api_key}"

    files_section = "\n\n".join(
        f"--- FILE: {path} ---\n{content}" for path, content in source_files.items()
    )

    prompt = f"""You are an Android application security gate in a CI/CD pipeline.
Analyze the following Pull Request diff, AndroidManifest.xml, and modified source files for CWE-940 (Improper Verification of Source of a Communication Channel / Android Intent Redirection).

Specifically:
1. Check if an exported Activity (`android:exported="true"` in AndroidManifest.xml) extracts a nested Parcelable Intent (e.g. via `getParcelableExtra` or `IntentCompat.getParcelableExtra`) and passes it to `startActivity`, `startActivityForResult`, `startService`, or `sendBroadcast` without verifying the target component.
2. Check if non-exported internal components (such as `TransferMoneyActivity` with `android:exported="false"`) can be reached by external apps through this redirection.

If the PR is vulnerable:
- Set `vulnerable` to `true`.
- Provide a concise `summary` explaining how an external app can exploit the exported router Activity to reach non-exported components.
- Provide a concise `remediation_explanation` describing how the patch fixes the issue.
- In `patched_files`, return the complete, compilable Kotlin source file for each vulnerable file. Remediate the Intent Redirection by:
  1. Stripping URI grant flags:
     `redirectIntent.removeFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)`
  2. Resolving the target Activity with `val targetInfo = redirectIntent.resolveActivityInfo(packageManager, 0)` and only calling `startActivity(redirectIntent)` if `targetInfo != null && targetInfo.exported && targetInfo.packageName != packageName` so internal or non-exported components (like `TransferMoneyActivity`) can never be launched via redirection.
  3. Preserving all existing package declarations, imports, UI composables, and helper functions so the file compiles cleanly.

--- ANDROID MANIFEST ({MANIFEST_PATH}) ---
{manifest_xml}

--- PULL REQUEST DIFF ---
{pr_diff}

--- FULL MODIFIED SOURCE FILES ---
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
                    "cwe": {"type": "STRING"},
                    "summary": {"type": "STRING"},
                    "remediation_explanation": {"type": "STRING"},
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
                "required": [
                    "vulnerable",
                    "cwe",
                    "summary",
                    "remediation_explanation",
                    "patched_files",
                ],
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


def verify_gradle_build() -> tuple[bool, str]:
    print("Running Gradle compile and unit test verification...")
    res = run_cmd(["./gradlew", ":app:compileDebugKotlin", ":app:testDebugUnitTest"], check=False)
    output = (res.stdout or "") + "\n" + (res.stderr or "")
    return res.returncode == 0, output


def commit_and_push_patch(head_ref: str, paths: list[str]) -> str:
    run_cmd(["git", "config", "user.name", "github-actions[bot]"])
    run_cmd(["git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com"])
    for p in paths:
        run_cmd(["git", "add", p])
    run_cmd(["git", "commit", "-m", "fix(security): block unverified intent redirection (CWE-940)"])
    sha = run_cmd(["git", "rev-parse", "--short", "HEAD"]).stdout.strip()
    if head_ref:
        run_cmd(["git", "push", "origin", f"HEAD:{head_ref}"])
    return sha


def main() -> int:
    last_subject = get_last_commit_subject()
    if last_subject.startswith("fix(security):"):
        print(f"Latest commit ('{last_subject}') is an automated security patch. Verifying build...")
        ok, output = verify_gradle_build()
        if not ok:
            print(output)
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
    changed_files = get_changed_source_files(base_ref)

    if not changed_files:
        print("No Android source files modified in this PR. Running standard verification...")
        ok, output = verify_gradle_build()
        if not ok:
            print(output)
            return 1
        return 0

    manifest_xml = MANIFEST_PATH.read_text(encoding="utf-8") if MANIFEST_PATH.exists() else ""
    source_contents = {str(p): p.read_text(encoding="utf-8") for p in changed_files}

    print(f"Analyzing {len(changed_files)} modified file(s) with Gemini ({GEMINI_MODEL})...")
    result = call_gemini(api_key, manifest_xml, pr_diff, source_contents)

    if not result.get("vulnerable", False):
        print("No Intent Redirection vulnerability detected. Verifying build...")
        ok, output = verify_gradle_build()
        if not ok:
            print(output)
            return 1
        return 0

    print(f"VULNERABILITY DETECTED: {result.get('cwe', 'CWE-940')}")
    print(f"Summary: {result.get('summary', '')}")

    patched_files = result.get("patched_files", [])
    modified_paths = []
    backups = {}

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

    commit_sha = commit_and_push_patch(head_ref, modified_paths)
    print(f"Pushed verified security remediation commit: {commit_sha}")

    comment_md = (
        f"### Security Gate Blocked PR: {result.get('cwe', 'CWE-940')} (Intent Redirection)\n\n"
        f"**Finding**\n"
        f"{result.get('summary', '')}\n\n"
        f"**Automated Remediation (`{commit_sha}`)**\n"
        f"{result.get('remediation_explanation', '')}\n\n"
        f"Updated file(s): {', '.join(f'`{p}`' for p in modified_paths)}"
    )
    post_pr_comment(github_token, repo, pr_number, comment_md)

    # Exit non-zero so the check on the vulnerable commit is marked as Failed.
    return 1


if __name__ == "__main__":
    sys.exit(main())
