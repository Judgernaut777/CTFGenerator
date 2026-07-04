"""Deterministic renderer for the ``mobile_insecure_storage`` challenge family.

An Android-style app "protects" a sensitive note with a lightweight local
cipher before storing it in ``SharedPreferences`` (and, because the manifest
opts the app into full device backups, in an ``adb backup`` extraction too).
The cipher itself is fine as far as it goes -- the problem is that its key is
hardcoded straight into the decompiled source (CWE-798: use of hard-coded
credentials) and nothing about the on-device storage is actually protected
against an attacker who can read the app's private files or take a backup
(CWE-312: cleartext storage of sensitive information -- "encrypted with a key
that ships next to the ciphertext" is cleartext for every practical purpose).

RED mode: play the attacker. Given the bundle (decompiled source tree stand-in
+ extracted shared_prefs/backup files), find the hardcoded key, use it to
decrypt the protected value, and submit the recovered flag.

BLUE mode: play the mobile AppSec engineer doing insecure-storage triage on
the same bundle. Catalog the insecure-storage / hardcoded-secret findings
(CWE-312, CWE-798) you can support with concrete evidence, then prove impact
on the most severe one by actually recovering the plaintext value and
submitting it as the flag.

This module is intentionally standalone: it must NOT import ``families``
(which imports it) to avoid a circular import. It exports the fixed
renderer-module interface that ``families.py`` wires up in a later step.
"""

from __future__ import annotations

import base64
import json
import random
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ctf_generator.models import ChallengeSpec
from ctf_generator.yaml_writer import dump_yaml

if TYPE_CHECKING:
    from ctf_generator.cve_source import CveRecord

# --- Renderer-module interface (see families.py FamilyRenderer contract) -----

FAMILY_NAME = "mobile_insecure_storage"
CATEGORY = "mobile"
MODES: tuple[str, ...] = ("red", "blue")
DIFFICULTIES: tuple[str, ...] = ("easy", "medium", "hard")
CVE_DRIVEN = True
LLM_BRIEF = (
    "An Android app 'encrypts' a sensitive note with a local cipher whose key "
    "is hardcoded in the decompiled source (CWE-798) and stores the result in "
    "SharedPreferences and a full-device backup with no real protection "
    "(CWE-312); red-mode players recover the key and decrypt the flag, "
    "blue-mode players triage the bundle for insecure-storage findings and "
    "prove impact by doing the same recovery."
)
# No container: this is a static bundle-analysis challenge, not a live
# service, so there is nothing for docker-compose.yml to describe.
COMPOSE_MARKERS: tuple[str, ...] = ()
SCORING_HINTS: dict[str, object] = {
    "has_worker": False,
    "has_queue": False,
    "live_interaction": False,
    "decoy_density": "medium",
}

# Fixed package layout for the decompiled source tree. The package/directory
# names themselves stay constant across instances (REQUIRED_FILES must be a
# static set); everything *inside* the files -- app name, key material,
# credentials, labels -- varies per instance via the seeded rng.
_PACKAGE_PATH = "com/acmemobile/vault"
_JAVA_DIR = f"public/app/src/main/java/{_PACKAGE_PATH}"

REQUIRED_FILES: tuple[str, ...] = (
    "challenge.yaml",
    "public/app/AndroidManifest.xml",
    f"{_JAVA_DIR}/MainActivity.java",
    f"{_JAVA_DIR}/CryptoVault.java",
    f"{_JAVA_DIR}/LoginActivity.java",
    "public/app/res/xml/backup_rules.xml",
    "public/app/shared_prefs/vault_prefs.xml",
    "public/app/backup/vault_backup.xml",
    "public/description.md",
    "public/hints.yaml",
    "private/solution.md",
    "private/solver.py",
    "private/variant.json",
    "private/checkpoints.yaml",
    "tests/healthcheck.py",
)


@dataclass(frozen=True)
class Variant:
    app_name: str
    company: str
    pref_key: str
    note_label: str
    account_holder: str
    key_hex: str
    debug_host: str
    debug_user: str
    debug_password: str
    session_token: str
    flag: str
    ciphertext_b64: str


def render(
    spec: ChallengeSpec,
    rng: random.Random,
    cve_record: "CveRecord | None" = None,
) -> dict[str, str]:
    variant = _variant(rng)
    is_blue = spec.mode == "blue"

    public_hints = [
        {
            "level": 1,
            "text": (
                "Start with public/app/res/xml/backup_rules.xml and the "
                "manifest's android:allowBackup flag -- what does that tell "
                "you about which shared_prefs file ends up in a full backup?"
            ),
        },
        {
            "level": 2,
            "text": (
                "CryptoVault.java claims to 'protect' the note before it is "
                "stored. Read protect()/reveal() closely: what operation is "
                "actually performed, and where does its key come from?"
            ),
        },
        {
            "level": 3,
            "text": (
                f"The value stored under '{variant.pref_key}' in "
                f"vault_prefs.xml is base64 of a byte-for-byte XOR against "
                f"the hardcoded key in CryptoVault.java. Decode, XOR, decode "
                f"UTF-8, and look for the flag inside."
            ),
        },
    ]

    files = {
        "public/app/AndroidManifest.xml": _manifest(variant),
        f"{_JAVA_DIR}/MainActivity.java": _main_activity(variant),
        f"{_JAVA_DIR}/CryptoVault.java": _crypto_vault(variant),
        f"{_JAVA_DIR}/LoginActivity.java": _login_activity(variant),
        "public/app/res/xml/backup_rules.xml": _backup_rules(),
        "public/app/shared_prefs/vault_prefs.xml": _shared_prefs(variant),
        "public/app/backup/vault_backup.xml": _backup_xml(variant),
        "public/description.md": _description(spec, variant, is_blue, cve_record),
        "public/hints.yaml": dump_yaml({"hints": public_hints}),
        "private/solution.md": _solution(spec, variant, is_blue),
        "private/solver.py": _solver(variant),
        "private/variant.json": _variant_json(spec, variant),
        "private/checkpoints.yaml": dump_yaml(
            {"checkpoints": [{"name": name, "required": True} for name in spec.checkpoints]}
        ),
        "tests/healthcheck.py": _healthcheck(),
    }
    return files


# --- Variant generation ------------------------------------------------------


def _token_hex(rng: random.Random, byte_count: int) -> str:
    return rng.getrandbits(byte_count * 8).to_bytes(byte_count, "big").hex()


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _variant(rng: random.Random) -> Variant:
    app_name = rng.choice(
        ["PayNimbus", "VaultTrail", "SecureLoop", "TrustCache", "NightSafe", "QuietLedger"]
    )
    company = rng.choice(
        ["Acme Mobile Labs", "Nimbus Software", "Northwind Apps", "Cobalt Mobile Inc."]
    )
    pref_key = rng.choice(
        ["secure_blob", "vault_cipher", "encrypted_token", "cipher_store", "protected_note"]
    )
    note_label = rng.choice(
        ["recovery_seed", "master_api_token", "wallet_passphrase", "escrow_unlock_code"]
    )
    account_holder = rng.choice(["r.alvarez", "j.chen", "m.okafor", "s.patel", "t.nilsson"])
    key_hex = _token_hex(rng, 16)
    debug_host = rng.choice(
        ["api-staging.internal", "debug.acmemobile.local", "qa-api.acmemobile.io"]
    )
    debug_user = rng.choice(["svc_debug", "qa_bot", "internal_qa", "staging_ci"])
    debug_password = f"{rng.choice(['Spring', 'River', 'Delta', 'Ember'])}{rng.randrange(100, 999)}!"
    session_token = f"sess_{_token_hex(rng, 8)}"
    flag = f"ctf{{mobile_insecure_storage_{_token_hex(rng, 6)}}}"

    plaintext = json.dumps({"label": note_label, "value": flag}, separators=(",", ":"))
    ciphertext_b64 = base64.b64encode(
        _xor_bytes(plaintext.encode("utf-8"), bytes.fromhex(key_hex))
    ).decode("ascii")

    return Variant(
        app_name=app_name,
        company=company,
        pref_key=pref_key,
        note_label=note_label,
        account_holder=account_holder,
        key_hex=key_hex,
        debug_host=debug_host,
        debug_user=debug_user,
        debug_password=debug_password,
        session_token=session_token,
        flag=flag,
        ciphertext_b64=ciphertext_b64,
    )


# --- App bundle source files (Java/XML use %-style formatting: the content
#     is brace-heavy and %-substitution avoids having to escape every literal
#     '{' / '}' the way an f-string would require) -----------------------------

_MANIFEST_TEMPLATE = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.acmemobile.vault">

    <uses-permission android:name="android.permission.INTERNET" />

    <application
        android:label="%(app_name)s"
        android:allowBackup="true"
        android:fullBackupContent="@xml/backup_rules"
        android:debuggable="false">

        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <activity android:name=".LoginActivity" android:exported="false" />
    </application>
</manifest>
"""


def _manifest(v: Variant) -> str:
    return _MANIFEST_TEMPLATE % {"app_name": v.app_name}


_BACKUP_RULES = """<?xml version="1.0" encoding="utf-8"?>
<!--
  Full-backup descriptor for com.acmemobile.vault. android:allowBackup is
  "true" in the manifest and no BackupAgent is registered, so adb (and any
  cloud backup transport) copies everything listed here off the device with
  no additional protection beyond whatever the device backup itself has.
-->
<full-backup-content>
    <include domain="sharedpref" path="vault_prefs.xml" />
</full-backup-content>
"""


def _backup_rules() -> str:
    return _BACKUP_RULES


_CRYPTO_VAULT_TEMPLATE = """package com.acmemobile.vault;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Lightweight local "protection" helper used to obscure the user's
 * %(note_label)s before it is written to SharedPreferences.
 *
 * TODO(security): this predates the migration to Android Keystore-backed
 * EncryptedSharedPreferences (see JIRA VAULT-482) and was only ever meant to
 * keep the value out of a casual `adb shell cat` while that work landed.
 * Do not ship a release build with this class still in use.
 */
public final class CryptoVault {

    // Static key for the interim XOR scheme above. Rotate once the
    // Keystore migration lands; until then this key is the *only* thing
    // standing between the stored value and plaintext.
    private static final String XOR_KEY_HEX = "%(key_hex)s";

    private CryptoVault() {
    }

    /** Called before a value is written to SharedPreferences. */
    public static String protect(String plaintext) {
        byte[] key = hexToBytes(XOR_KEY_HEX);
        byte[] data = plaintext.getBytes(StandardCharsets.UTF_8);
        return Base64.getEncoder().encodeToString(xor(data, key));
    }

    /** Called after a value is read back from SharedPreferences. */
    public static String reveal(String encoded) {
        byte[] key = hexToBytes(XOR_KEY_HEX);
        byte[] data = Base64.getDecoder().decode(encoded);
        return new String(xor(data, key), StandardCharsets.UTF_8);
    }

    private static byte[] xor(byte[] data, byte[] key) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            out[i] = (byte) (data[i] ^ key[i %% key.length]);
        }
        return out;
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return out;
    }
}
"""


def _crypto_vault(v: Variant) -> str:
    return _CRYPTO_VAULT_TEMPLATE % {"key_hex": v.key_hex, "note_label": v.note_label}


_MAIN_ACTIVITY_TEMPLATE = """package com.acmemobile.vault;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    private static final String PREFS_NAME = "vault_prefs";
    private static final String PREF_KEY = "%(pref_key)s";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        // ... view binding / click listeners omitted for brevity ...
    }

    /** Persists the user's %(note_label)s, "protected" via CryptoVault. */
    private void saveNote(String plaintextNote) {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        prefs.edit()
                .putString(PREF_KEY, CryptoVault.protect(plaintextNote))
                .putString("account_holder", "%(account_holder)s")
                .putBoolean("onboarding_complete", true)
                .apply();
    }

    /** Reads the %(note_label)s back for display in the app UI. */
    private String loadNote() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        String encoded = prefs.getString(PREF_KEY, null);
        return encoded == null ? null : CryptoVault.reveal(encoded);
    }
}
"""


def _main_activity(v: Variant) -> str:
    return _MAIN_ACTIVITY_TEMPLATE % {
        "pref_key": v.pref_key,
        "note_label": v.note_label,
        "account_holder": v.account_holder,
    }


_LOGIN_ACTIVITY_TEMPLATE = """package com.acmemobile.vault;

import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;

public class LoginActivity extends AppCompatActivity {

    // Convenience auto-login for the internal staging build; stripped by
    // the "release" product flavor before store submission (see
    // app/build.gradle productFlavors), but still present in the debug
    // build this decompiled bundle was pulled from.
    private static final String DEBUG_HOST = "https://%(debug_host)s";
    private static final String DEBUG_USER = "%(debug_user)s";
    private static final String DEBUG_PASSWORD = "%(debug_password)s";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);
        if (BuildConfig.DEBUG) {
            autoFillDebugCredentials(DEBUG_USER, DEBUG_PASSWORD);
        }
    }

    private String debugBasicAuthHeader() {
        String raw = DEBUG_USER + ":" + DEBUG_PASSWORD;
        return "Basic " + android.util.Base64.encodeToString(
                raw.getBytes(), android.util.Base64.NO_WRAP);
    }

    private void autoFillDebugCredentials(String user, String password) {
        // Pre-fills the login form fields for the internal QA build against
        // DEBUG_HOST. Not reachable from the production flavor.
    }
}
"""


def _login_activity(v: Variant) -> str:
    return _LOGIN_ACTIVITY_TEMPLATE % {
        "debug_host": v.debug_host,
        "debug_user": v.debug_user,
        "debug_password": v.debug_password,
    }


_SHARED_PREFS_TEMPLATE = """<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="%(pref_key)s">%(ciphertext)s</string>
    <string name="account_holder">%(account_holder)s</string>
    <boolean name="onboarding_complete" value="true" />
</map>
"""


def _shared_prefs(v: Variant) -> str:
    return _SHARED_PREFS_TEMPLATE % {
        "pref_key": v.pref_key,
        "ciphertext": v.ciphertext_b64,
        "account_holder": v.account_holder,
    }


_BACKUP_XML_TEMPLATE = """<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<!-- Extracted via: adb backup -f vault.ab com.acmemobile.vault
     (then unpacked with android-backup-extractor). -->
<backup package="com.acmemobile.vault">
    <sharedpref file="vault_prefs.xml">
        <string name="%(pref_key)s">%(ciphertext)s</string>
        <string name="account_holder">%(account_holder)s</string>
    </sharedpref>
    <!-- Left over from a support session; not cleared before this backup
         was taken. Stored as plain text -- there is no CryptoVault call on
         this path at all. -->
    <string name="last_session_token">%(session_token)s</string>
</backup>
"""


def _backup_xml(v: Variant) -> str:
    return _BACKUP_XML_TEMPLATE % {
        "pref_key": v.pref_key,
        "ciphertext": v.ciphertext_b64,
        "account_holder": v.account_holder,
        "session_token": v.session_token,
    }


# --- public/private docs ------------------------------------------------------


def _bundle_file_list() -> str:
    return "\n".join(f"- `{path}`" for path in REQUIRED_FILES if path != "challenge.yaml")


def _description(
    spec: ChallengeSpec,
    v: Variant,
    is_blue: bool,
    cve_record: "CveRecord | None",
) -> str:
    cve_note = ""
    if cve_record is not None:
        cve_note = (
            f"\nThis challenge is themed after the broader class of insecure "
            f"on-device storage illustrated by {cve_record.cve_id} "
            f"({cve_record.cvss_severity.title()}, "
            f"{', '.join(cve_record.cwe_ids) or 'unclassified CWE'}): "
            f"{cve_record.description}\n"
        )

    if is_blue:
        return f"""# {spec.title}

Difficulty: {spec.difficulty}

You are the mobile AppSec engineer assigned to sign off **{v.app_name}**
({v.company}) before its next release. Legal has already flagged that the
app allows full device backups; your job is to determine whether any
sensitive data is *actually* recoverable from the bundle below, not just
whether the code path near it looks encrypted.

Bundle under review:

{_bundle_file_list()}

Deliverables:

1. Catalog every insecure-storage / hardcoded-secret finding you can
   support with concrete evidence (a specific file and what it shows) --
   look for both CWE-312 (cleartext storage) and CWE-798 (hardcoded
   credentials) patterns.
2. For each finding, note whether it is *required* to explain the exposure
   of the protected value or a decoy that is real but unrelated -- a
   catalog that cannot tell the two apart is not triage, it's grep output.
3. Prove impact on the most severe finding: actually recover the plaintext
   value the app is supposed to be protecting under the app's
   SharedPreferences, and submit it as the flag (`ctf{{...}}`).
{cve_note}
This challenge is generated as a mobile insecure-storage variant. The app
name, package contents, hardcoded key material, preference keys, and decoy
credentials differ across generated instances.
"""

    return f"""# {spec.title}

Difficulty: {spec.difficulty}

You've obtained a leaked Android app bundle for **{v.app_name}**
({v.company}) -- a decompiled source tree plus an `adb backup` extraction.
The app claims to protect a sensitive note before storing it locally, but
that claim doesn't hold up to a closer read.

Bundle:

{_bundle_file_list()}

Find the hardcoded secret the app uses to "protect" its data, use it to
recover the value stored on-device, and submit it as the flag (`ctf{{...}}`).
{cve_note}
This challenge is generated as a mobile insecure-storage variant. The app
name, package contents, hardcoded key material, preference keys, and decoy
credentials differ across generated instances.
"""


def _findings_table(v: Variant, is_blue: bool = False) -> str:
    table = f"""| id | CWE     | file                                             | required for flag | evidence |
|----|---------|---------------------------------------------------|--------------------|----------|
| F1 | CWE-798 | `{_JAVA_DIR}/CryptoVault.java`                      | yes                | `XOR_KEY_HEX` static field holds the only key used to protect/reveal on-device data |
| F2 | CWE-312 | `public/app/shared_prefs/vault_prefs.xml`           | yes                | `{v.pref_key}` is base64(XOR(plaintext, key)) with the key from F1 sitting in the same bundle -- recoverable, not protected |
| F3 | CWE-798 | `{_JAVA_DIR}/LoginActivity.java`                    | no (decoy)         | `DEBUG_USER` / `DEBUG_PASSWORD` hardcoded for an internal staging host; unrelated to the protected note |
| F4 | CWE-312 | `public/app/backup/vault_backup.xml`                | no (decoy)         | `last_session_token` stored fully in the clear, with no CryptoVault call on that path at all |
"""
    if is_blue:
        table += (
            "| F5 | CWE-312 | `public/app/AndroidManifest.xml` + `backup_rules.xml` | "
            "no (risk amplifier) | `android:allowBackup=\"true\"` plus the "
            "full-backup `sharedpref` include means F2's exposure needs no "
            "device access at all -- `adb backup` alone reaches the same "
            "ciphertext via `public/app/backup/vault_backup.xml` |\n"
        )
    return table


def _solution(spec: ChallengeSpec, v: Variant, is_blue: bool) -> str:
    header = "# Private Solution\n"
    intro = f"""
`CryptoVault.protect()`/`reveal()` implement a reversible byte-wise XOR
against `XOR_KEY_HEX`, a compile-time constant in
`{_JAVA_DIR}/CryptoVault.java` (CWE-798: hardcoded key). Because the key
ships in the same bundle as the ciphertext it protects, the value stored
under `{v.pref_key}` in `public/app/shared_prefs/vault_prefs.xml` -- and
duplicated in `public/app/backup/vault_backup.xml` thanks to
`android:allowBackup="true"` -- is recoverable by anyone who can read either
file (CWE-312: cleartext storage of sensitive information).

## Findings
{_findings_table(v, is_blue)}
"""
    solve_steps = f"""
## Solve path

1. Read `public/app/AndroidManifest.xml` and
   `public/app/res/xml/backup_rules.xml`: `android:allowBackup="true"` plus
   the `sharedpref` include confirms `vault_prefs.xml` is exported whole in
   any full backup.
2. Open `{_JAVA_DIR}/CryptoVault.java` and read off
   `XOR_KEY_HEX = "{v.key_hex}"`.
3. Open `public/app/shared_prefs/vault_prefs.xml` and read the base64 value
   stored under `{v.pref_key}`.
4. Base64-decode that value, XOR it byte-for-byte against
   `bytes.fromhex("{v.key_hex}")` (repeating the key), and UTF-8 decode the
   result -- it is a small JSON envelope: `{{"label": "...", "value":
   "{v.flag}"}}`.
5. Submit `value` as the flag: `{v.flag}`.

`private/solver.py` automates steps 2-5 against the bundle.
"""
    if is_blue:
        teaching = """
This is meant to teach that "we encrypt it" is not a finding-closing
statement in a mobile app review: a defender must trace the key's storage
location, not just confirm a cipher call exists. A key hardcoded next to
(or shipped in the same package as) its ciphertext provides no protection
against anyone who can read the app's files or take a device backup --
which for a mobile app includes, at minimum, the app's own decompiled
source.
"""
        deliverable = f"""
## Analyst deliverable (grading rubric)

A complete blue-mode submission is a short triage write-up plus the
recovered flag, not just the flag. Grade the write-up against:

1. **Findings catalog** -- credits F1 (CWE-798, hardcoded XOR key in
   `CryptoVault.java`) and F2 (CWE-312, cleartext-equivalent value in
   `vault_prefs.xml`) as the pair *required* to explain how the protected
   value is recoverable. F3 (`LoginActivity` debug credentials) and F4
   (backup session token) are real findings but decoys with respect to the
   protected note -- reporting them as required for the flag is a
   misattribution and should be marked down.
2. **Impact evidence** -- the write-up must show the actual recovered
   plaintext envelope (`{{"label": "...", "value": "..."}}`), not merely
   assert that the value "could be" decrypted; `{v.flag}` is the value that
   must appear.
3. **Backup exposure (F5)** -- credit for calling out that
   `android:allowBackup="true"` plus the `backup_rules.xml` full-backup
   include means F2 is reachable via `adb backup` alone, with no on-device
   access required at all: `public/app/backup/vault_backup.xml` carries the
   identical ciphertext.
"""
    else:
        teaching = """
This is meant to teach that local "encryption" backed by a key baked into
the APK is not encryption from an attacker's perspective -- the key is
always in the box with the ciphertext. Real protection for on-device
secrets requires hardware-backed storage (Android Keystore /
EncryptedSharedPreferences with a Keystore-wrapped key), not a
compile-time constant.
"""
        deliverable = ""
    del spec
    return header + intro + solve_steps + teaching + deliverable


def _solver(v: Variant) -> str:
    return f'''from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

_KEY_RE = re.compile(r'XOR_KEY_HEX\\s*=\\s*"([0-9a-fA-F]+)"')
_FLAG_RE = re.compile(r"ctf\\{{[^}}]+\\}}")


def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def find_key(crypto_vault_path: Path) -> str:
    text = crypto_vault_path.read_text(encoding="utf-8")
    match = _KEY_RE.search(text)
    if not match:
        raise RuntimeError(f"hardcoded key not found in {{crypto_vault_path}}")
    return match.group(1)


def find_flag(shared_prefs_path: Path, key_hex: str) -> str:
    key = bytes.fromhex(key_hex)
    tree = ET.parse(shared_prefs_path)
    for elem in tree.getroot().findall("string"):
        value = elem.text or ""
        try:
            raw = base64.b64decode(value)
            candidate = _xor(raw, key).decode("utf-8")
        except Exception:
            continue
        match = _FLAG_RE.search(candidate)
        if match:
            return match.group(0)
        try:
            envelope = json.loads(candidate)
        except Exception:
            continue
        inner = str(envelope.get("value", ""))
        match = _FLAG_RE.search(inner)
        if match:
            return match.group(0)
    raise RuntimeError(f"flag not found in {{shared_prefs_path}}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", default="public/app")
    args = parser.parse_args()
    base = Path(args.bundle)
    key_hex = find_key(base / "src/main/java/{_PACKAGE_PATH}/CryptoVault.java")
    flag = find_flag(base / "shared_prefs/vault_prefs.xml", key_hex)
    print(flag)
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def _variant_json(spec: ChallengeSpec, v: Variant) -> str:
    return json.dumps(
        {
            "meta": spec.meta_mapping(),
            "family": FAMILY_NAME,
            "mode": spec.mode,
            "flag": v.flag,
            "app": {
                "name": v.app_name,
                "company": v.company,
                "package": "com.acmemobile.vault",
            },
            "storage": {
                "pref_key": v.pref_key,
                "note_label": v.note_label,
                "account_holder": v.account_holder,
                "ciphertext_b64": v.ciphertext_b64,
            },
            "credentials": {
                "hardcoded_xor_key_hex": v.key_hex,
                "debug_host": v.debug_host,
                "debug_user": v.debug_user,
                "debug_password": v.debug_password,
            },
            "decoys": {
                "backup_session_token": v.session_token,
            },
            "findings": [
                {
                    "id": "F1",
                    "cwe": "CWE-798",
                    "file": f"{_JAVA_DIR}/CryptoVault.java",
                    "required_for_flag": True,
                },
                {
                    "id": "F2",
                    "cwe": "CWE-312",
                    "file": "public/app/shared_prefs/vault_prefs.xml",
                    "required_for_flag": True,
                },
                {
                    "id": "F3",
                    "cwe": "CWE-798",
                    "file": f"{_JAVA_DIR}/LoginActivity.java",
                    "required_for_flag": False,
                },
                {
                    "id": "F4",
                    "cwe": "CWE-312",
                    "file": "public/app/backup/vault_backup.xml",
                    "required_for_flag": False,
                },
            ],
        },
        indent=2,
        sort_keys=True,
    ) + "\n"


def _healthcheck() -> str:
    return f'''from __future__ import annotations

import sys
from pathlib import Path

# No live service backs this challenge: it is a static bundle-analysis
# challenge, so "healthy" means the app bundle the player is meant to
# analyze is present and non-empty, not that a port is listening.
_REQUIRED_RELATIVE = [
    "app/AndroidManifest.xml",
    "app/src/main/java/{_PACKAGE_PATH}/MainActivity.java",
    "app/src/main/java/{_PACKAGE_PATH}/CryptoVault.java",
    "app/src/main/java/{_PACKAGE_PATH}/LoginActivity.java",
    "app/res/xml/backup_rules.xml",
    "app/shared_prefs/vault_prefs.xml",
    "app/backup/vault_backup.xml",
]


def main() -> int:
    public_dir = Path(__file__).resolve().parent.parent / "public"
    missing = [rel for rel in _REQUIRED_RELATIVE if not (public_dir / rel).is_file()]
    if missing:
        print("missing bundle files: " + ", ".join(missing))
        return 1
    empty = [
        rel for rel in _REQUIRED_RELATIVE if (public_dir / rel).stat().st_size == 0
    ]
    if empty:
        print("empty bundle files: " + ", ".join(empty))
        return 1
    print("ok: mobile app bundle present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''
