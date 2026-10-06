#!/usr/bin/env python3
"""
Extensible AI Security Gate & Auto-Patcher for Android Pull Requests.

Combines a fast static Semgrep pre-filter with Google Gemini cross-component analysis,
verifies AI-generated patches with Gradle, commits the fix directly to the PR branch,
and posts a detailed root-cause and diff explanation on the PR.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import random
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-flash-latest")
# Models tried in order when the previous model is under high demand or unavailable.
GEMINI_FALLBACK_MODELS = [
    m.strip()
    for m in os.environ.get("GEMINI_FALLBACK_MODELS", "gemini-pro-latest,gemini-3.6-flash").split(",")
    if m.strip()
]
GEMINI_MAX_ATTEMPTS = int(os.environ.get("GEMINI_MAX_ATTEMPTS", "4"))
GEMINI_TIMEOUT_SECONDS = int(os.environ.get("GEMINI_TIMEOUT_SECONDS", "180"))
# Times to send compiler errors back to Gemini when a generated patch does not compile.
GEMINI_PATCH_REPAIR_ATTEMPTS = int(os.environ.get("GEMINI_PATCH_REPAIR_ATTEMPTS", "2"))
RETRYABLE_HTTP_CODES = {429, 500, 502, 503, 504}
# High demand / quota errors: switch to the next model immediately instead of retrying.
SWITCH_MODEL_HTTP_CODES = {429, 503}
# Model not found (e.g. alias unavailable for this key): skip to the next model.
SKIP_MODEL_HTTP_CODES = {404}
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
    """Return all app source files when any source or manifest file in app/src/main changed."""
    diff_res = run_cmd(["git", "diff", "--name-only", f"origin/{base_ref}...HEAD"], check=False)
    changed_paths = {
        Path(line.strip())
        for line in diff_res.stdout.splitlines()
        if line.strip()
    }

    relevant_changed = [
        p for p in changed_paths
        if p.exists() and p.suffix in {".kt", ".java", ".xml"} and "app/src/main" in str(p)
    ]
    if not relevant_changed:
        return {}

    all_app_sources: dict[str, str] = {}
    for root_file in sorted(Path("app/src/main/java").rglob("*")):
        if root_file.is_file() and root_file.suffix in {".kt", ".java"}:
            all_app_sources[str(root_file)] = root_file.read_text(encoding="utf-8")

    return all_app_sources


def load_semgrep_prefilter_summary(semgrep_path_str: str) -> str:
    """Parse Semgrep JSON output into a concise summary of flagged locations for the LLM."""
    path = Path(semgrep_path_str) if semgrep_path_str else None
    if not path or not path.exists():
        return "Semgrep pre-filter file not provided."

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return f"Unable to parse Semgrep output: {exc}"

    results = raw.get("results", [])
    if not results:
        return "No static findings flagged by Semgrep pre-filter (perform full semantic analysis on diff and manifest)."

    lines = []
    for item in results:
        check_id = item.get("check_id", "unknown-rule")
        file_path = item.get("path", "")
        start_line = item.get("start", {}).get("line", "?")
        end_line = item.get("end", {}).get("line", "?")
        message = item.get("extra", {}).get("message", "")
        lines.append(
            f"- Rule `{check_id}` at `{file_path}:{start_line}-{end_line}`: {message}"
        )
    return "\n".join(lines)


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
    semgrep_summary: str,
    source_files: dict[str, str],
    guards: list[SecurityGuard],
) -> dict:
    files_section = "\n\n".join(
        f"--- FILE: {path} ---\n{content}" for path, content in source_files.items()
    )
    guards_section = build_guards_prompt_section(guards)

    prompt = f"""You are an automated Android static code analysis and defensive remediation tool in a CI/CD pipeline.
Review the Pull Request diff alongside the Semgrep static pre-filter signals, AndroidManifest.xml, and the application source files against the registered defensive coding guards below.

=== REGISTERED DEFENSIVE GUARDS ===
{guards_section}

=== INSTRUCTIONS ===
1. Review the Semgrep static pre-filter findings and correlate the PR diff with AndroidManifest.xml and all application source files. Check how exported components interact with non-exported components (such as `TransferMoneyActivity`).
2. If one or more guards are violated by the code in this PR:
   - Set `vulnerable` to `true`.
   - Populate `findings` with one entry per violated guard, explaining clearly:
     * `why_dangerous`: Why the unverified dataflow violates Android component isolation in this codebase.
     * `how_patched`: How the generated defensive patch validates the target component and neutralizes the risk.
   - Populate `patched_files` with the complete, compilable file content for every file that needs modification to fix all findings.
   - Preserve all existing package declarations, imports, UI composables, and helper methods so `./gradlew :app:compileDebugKotlin :app:testDebugUnitTest` succeeds without errors.
   - Each `content` value must be the raw source file: real newlines, `package` declaration first, one `import` per line, no markdown code fences, no line numbers.
3. If no guard is violated, set `vulnerable` to `false` and return empty arrays for `findings` and `patched_files`.

--- STEP 1: SEMGREP STATIC PRE-FILTER FINDINGS ---
{semgrep_summary}

--- ANDROID MANIFEST ({MANIFEST_PATH}) ---
{manifest_xml}

--- PULL REQUEST DIFF ---
{pr_diff}

--- APPLICATION SOURCE FILES ---
{files_section}
"""

    return generate_structured(api_key, prompt)


RESPONSE_SCHEMA = {
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
}


def generate_structured(api_key: str, prompt: str) -> dict:
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "safetySettings": [
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
        ],
        "generationConfig": {
            "temperature": 0.1,
            "responseMimeType": "application/json",
            "responseSchema": RESPONSE_SCHEMA,
        },
    }

    body, model_used = post_gemini_with_retry(api_key, payload)
    print(f"Gemini response received from model '{model_used}'.")

    candidates = body.get("candidates")
    if not candidates:
        print(f"Unexpected Gemini API response (no candidates): {json.dumps(body, indent=2)}", file=sys.stderr)
        raise RuntimeError(f"Gemini returned no candidates: {body.get('promptFeedback', body)}")

    finish_reason = candidates[0].get("finishReason")
    if finish_reason and finish_reason != "STOP":
        print(f"WARNING: Gemini finishReason={finish_reason}; output may be truncated.", file=sys.stderr)

    parts = candidates[0].get("content", {}).get("parts", [])
    if not parts or "text" not in parts[0]:
        print(f"Unexpected Gemini candidate structure: {json.dumps(candidates[0], indent=2)}", file=sys.stderr)
        raise RuntimeError(f"Gemini candidate had no text part (finishReason={finish_reason})")

    text = "".join(p.get("text", "") for p in parts)
    return json.loads(text)


def request_patch_repair(
    api_key: str,
    findings: list[dict],
    original_files: dict[str, str],
    patched_files: list[dict],
    build_errors: str,
) -> dict:
    """Send the failed patch and compiler errors back to Gemini and ask for a corrected patch."""
    originals_section = "\n\n".join(
        f"--- ORIGINAL FILE: {path} ---\n{content}" for path, content in original_files.items()
    )
    patched_section = "\n\n".join(
        f"--- FAILED PATCH: {item['path']} ---\n{item['content']}" for item in patched_files
    )
    prompt = f"""You are fixing an Android Kotlin security patch that failed to compile.

The previous patch addressed these findings:
{json.dumps(findings, indent=2)}

Return corrected, complete, compilable file contents in `patched_files`, and repeat the same `findings` with `vulnerable` set to true.
Rules:
- Each `content` value must be the raw source file: real newlines, one statement per line, no markdown code fences, no line numbers.
- Start each Kotlin file with its `package` declaration, followed by one `import` per line.
- Keep every import, class, composable, and helper from the original file unless the fix requires changing it.
- Change only what is needed to fix the security findings and the compiler errors.

--- KOTLIN COMPILER ERRORS ---
{build_errors}

{patched_section}

{originals_section}
"""
    return generate_structured(api_key, prompt)


def sanitize_patched_content(content: str) -> str:
    """Remove common LLM output artifacts from generated source files."""
    text = content.replace("\r\n", "\n")
    stripped = text.strip()
    # Strip a surrounding markdown code fence (``` or ```kotlin).
    if stripped.startswith("```"):
        lines = stripped.split("\n")
        lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines)
    # Double-escaped output: literal "\n" sequences instead of real newlines.
    if text.count("\\n") > text.count("\n"):
        text = text.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\t", "\t").replace('\\"', '"')
    return text.rstrip() + "\n"


def extract_compiler_errors(build_output: str, limit: int = 60) -> str:
    errors = [line for line in build_output.splitlines() if line.startswith(("e: ", "error:"))]
    if not errors:
        return build_output[-6000:]
    return "\n".join(errors[:limit])


def apply_patched_files(patched_files: list[dict], backups: dict[Path, str | None]) -> list[str]:
    modified: list[str] = []
    for item in patched_files:
        file_path = Path(item["path"])
        if file_path not in backups:
            backups[file_path] = file_path.read_text(encoding="utf-8") if file_path.exists() else None
        item["content"] = sanitize_patched_content(item["content"])
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(item["content"], encoding="utf-8")
        modified.append(str(file_path))
    return modified


def restore_backups(backups: dict[Path, str | None]) -> None:
    for file_path, original in backups.items():
        if original is None:
            file_path.unlink(missing_ok=True)
        else:
            file_path.write_text(original, encoding="utf-8")


def print_file_head(path: str, lines: int = 15) -> None:
    p = Path(path)
    if not p.exists():
        return
    print(f"--- First {lines} lines of generated {path} ---", file=sys.stderr)
    for idx, line in enumerate(p.read_text(encoding="utf-8").splitlines()[:lines], start=1):
        print(f"{idx:4}: {line}", file=sys.stderr)


def post_gemini_with_retry(api_key: str, payload: dict) -> tuple[dict, str]:
    """POST to Gemini, switching models on high demand and retrying other transient errors."""
    data = json.dumps(payload).encode("utf-8")
    models = list(dict.fromkeys([GEMINI_MODEL, *GEMINI_FALLBACK_MODELS]))
    last_exc: Exception | None = None

    for index, model in enumerate(models):
        is_last_model = index == len(models) - 1
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        for attempt in range(1, GEMINI_MAX_ATTEMPTS + 1):
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            retry_after: float | None = None
            try:
                with urllib.request.urlopen(req, timeout=GEMINI_TIMEOUT_SECONDS) as resp:
                    return json.loads(resp.read().decode("utf-8")), model
            except urllib.error.HTTPError as exc:
                err_body = exc.read().decode("utf-8", errors="replace")
                print(
                    f"Gemini API error on model '{model}' (HTTP {exc.code}, attempt {attempt}/{GEMINI_MAX_ATTEMPTS}): {err_body}",
                    file=sys.stderr,
                )
                last_exc = exc
                if exc.code in SKIP_MODEL_HTTP_CODES and not is_last_model:
                    print(f"Model '{model}' not found; switching to '{models[index + 1]}'.", file=sys.stderr)
                    break
                if exc.code in SWITCH_MODEL_HTTP_CODES and not is_last_model:
                    print(f"Model '{model}' under high demand; switching to '{models[index + 1]}'.", file=sys.stderr)
                    break
                if exc.code not in RETRYABLE_HTTP_CODES:
                    raise
                header = exc.headers.get("Retry-After") if exc.headers else None
                if header and header.isdigit():
                    retry_after = float(header)
            except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError) as exc:
                print(
                    f"Gemini network error on model '{model}' (attempt {attempt}/{GEMINI_MAX_ATTEMPTS}): {exc}",
                    file=sys.stderr,
                )
                last_exc = exc

            if attempt < GEMINI_MAX_ATTEMPTS:
                delay = retry_after if retry_after is not None else min(60.0, 2 ** attempt) + random.uniform(0, 1)
                print(f"Retrying in {delay:.1f}s...", file=sys.stderr)
                time.sleep(delay)
        else:
            print(f"Model '{model}' unavailable after {GEMINI_MAX_ATTEMPTS} attempts.", file=sys.stderr)

    raise RuntimeError(f"All Gemini models failed ({', '.join(models)})") from last_exc


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
    semgrep_path = os.environ.get("SEMGREP_RESULTS_PATH", "semgrep_raw.json")

    pr_diff = get_pr_diff(base_ref)
    source_files = get_project_source_files(base_ref)

    if not source_files:
        print("No Android source or manifest files modified in this PR. Running standard verification...")
        ok, output = verify_gradle_build()
        if not ok:
            print(output, file=sys.stderr)
            return 1
        return 0

    semgrep_summary = load_semgrep_prefilter_summary(semgrep_path)
    print("Semgrep pre-filter summary:")
    print(semgrep_summary)

    manifest_xml = MANIFEST_PATH.read_text(encoding="utf-8") if MANIFEST_PATH.exists() else ""

    print(
        f"Evaluating PR against {len(SECURITY_GUARDS)} security guards "
        f"across {len(source_files)} source file(s) using {GEMINI_MODEL}..."
    )
    result = call_gemini(
        api_key,
        manifest_xml,
        pr_diff,
        semgrep_summary,
        source_files,
        SECURITY_GUARDS,
    )

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
    if not patched_files:
        print("Gemini reported findings but returned no patched files.", file=sys.stderr)
        return 1

    backups: dict[Path, str | None] = {}
    modified_paths = apply_patched_files(patched_files, backups)
    ok, build_output = verify_gradle_build()

    for repair_attempt in range(1, GEMINI_PATCH_REPAIR_ATTEMPTS + 1):
        if ok:
            break
        build_errors = extract_compiler_errors(build_output)
        print(
            f"Generated patch failed to compile; requesting repair "
            f"({repair_attempt}/{GEMINI_PATCH_REPAIR_ATTEMPTS}).",
            file=sys.stderr,
        )
        print(build_errors, file=sys.stderr)
        for path in modified_paths:
            print_file_head(path)

        originals = {str(p): content for p, content in backups.items() if content is not None}
        repaired = request_patch_repair(api_key, findings, originals, patched_files, build_errors)
        repaired_files = repaired.get("patched_files", [])
        if not repaired_files:
            print("Repair response contained no patched files.", file=sys.stderr)
            break
        findings = repaired.get("findings") or findings
        patched_files = repaired_files
        modified_paths = list(dict.fromkeys(modified_paths + apply_patched_files(patched_files, backups)))
        ok, build_output = verify_gradle_build()

    if not ok:
        print("Generated patch failed to compile after repair attempts; restoring original files.", file=sys.stderr)
        print(build_output, file=sys.stderr)
        for path in modified_paths:
            print_file_head(path)
        restore_backups(backups)
        return 1

    cwes = [f.get("cwe", "CWE-940") for f in findings]
    commit_sha, patch_diff = commit_and_push_patch(head_ref, modified_paths, cwes)
    print(f"Pushed verified security remediation commit: {commit_sha}")

    comment_md = format_pr_comment(findings, commit_sha, patch_diff)
    post_pr_comment(github_token, repo, pr_number, comment_md)

    # Return non-zero so the check on the vulnerable PR commit is marked as Failed.
    return 1


if __name__ == "__main__":
    # Keep stdout and stderr in order in CI logs.
    sys.stdout.reconfigure(line_buffering=True)
    sys.exit(main())
