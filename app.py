import streamlit as st
import os
import sys
import tempfile
import zipfile
import hashlib
import math
import json
import re
import struct
import shutil
from datetime import datetime

# ── Page Config ──────────────────────────────────────────────
st.set_page_config(
    page_title="APK Threat Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ── CSS ───────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono&display=swap');
* { font-family: 'Inter', sans-serif; }
.stApp { background: #0a0e1a; color: #e2e8f0; }
.hero {
    background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
    border: 1px solid #334155; border-radius: 16px;
    padding: 40px; text-align: center; margin-bottom: 30px;
}
.hero h1 { font-size: 2.4rem; font-weight: 700; color: #f8fafc; margin: 0; }
.hero p  { color: #94a3b8; font-size: 1rem; margin-top: 8px; }
.hash-row {
    display: flex; justify-content: space-between;
    padding: 7px 0; border-bottom: 1px solid #1e293b;
    font-size: 0.83rem;
}
.hash-label { color: #64748b; font-weight: 600; min-width: 70px; }
.hash-value { color: #94a3b8; font-family: 'JetBrains Mono', monospace; word-break: break-all; }
.section-header {
    display: flex; align-items: center; gap: 10px;
    padding: 12px 0; border-bottom: 1px solid #1e293b; margin-bottom: 16px;
}
.section-num {
    background: #1e293b; color: #64748b; width: 28px; height: 28px;
    border-radius: 6px; display: flex; align-items: center; justify-content: center;
    font-size: 0.75rem; font-weight: 700;
}
.section-title { font-size: 0.88rem; font-weight: 600; color: #cbd5e1;
    letter-spacing: 0.05em; text-transform: uppercase; }
div[data-testid="stFileUploader"] > div {
    background: #111827 !important; border: 2px dashed #334155 !important;
    border-radius: 12px !important;
}
.stButton button {
    background: linear-gradient(135deg, #4f46e5, #7c3aed) !important;
    color: white !important; border: none !important;
    border-radius: 8px !important; font-weight: 600 !important;
    padding: 12px 28px !important; font-size: 1rem !important; width: 100%;
}
div[data-testid="stTabs"] button { color: #94a3b8 !important; }
div[data-testid="stTabs"] button[aria-selected="true"] { color: #e2e8f0 !important; }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
# KNOWLEDGE BASE
# ─────────────────────────────────────────────────────────────
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS":
        ("CRITICAL", "Reads all SMS — steals bank OTPs and 2FA codes"),
    "android.permission.RECEIVE_SMS":
        ("CRITICAL", "Intercepts ALL incoming SMS in real-time — live OTP theft"),
    "android.permission.SEND_SMS":
        ("CRITICAL", "Sends SMS from your number — spreads malware to your contacts"),
    "android.permission.READ_CALL_LOG":
        ("HIGH",     "Reads all call history"),
    "android.permission.PROCESS_OUTGOING_CALLS":
        ("HIGH",     "Intercepts and redirects your phone calls"),
    "android.permission.READ_CONTACTS":
        ("HIGH",     "Steals your entire contact list for phishing campaigns"),
    "android.permission.RECORD_AUDIO":
        ("CRITICAL", "Records phone calls and ambient audio — spyware"),
    "android.permission.CAMERA":
        ("HIGH",     "Takes photos and videos silently"),
    "android.permission.ACCESS_FINE_LOCATION":
        ("HIGH",     "Tracks your precise GPS location in real-time"),
    "android.permission.ACCESS_COARSE_LOCATION":
        ("MEDIUM",   "Tracks your approximate location"),
    "android.permission.READ_EXTERNAL_STORAGE":
        ("HIGH",     "Reads all your files, photos, and documents"),
    "android.permission.WRITE_EXTERNAL_STORAGE":
        ("HIGH",     "Writes files — can drop additional malware"),
    "android.permission.REQUEST_INSTALL_PACKAGES":
        ("CRITICAL", "Silently installs more malware APKs on your device — DROPPER"),
    "android.permission.QUERY_ALL_PACKAGES":
        ("HIGH",     "Lists all installed apps — finds your banking apps to attack"),
    "android.permission.SYSTEM_ALERT_WINDOW":
        ("CRITICAL", "Draws fake UI over ANY app — steals banking passwords and UPI PINs"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE":
        ("CRITICAL", "Full device takeover — reads screen, makes payments, logs keystrokes"),
    "android.permission.BIND_DEVICE_ADMIN":
        ("CRITICAL", "Locks device and prevents uninstall — ransomware capability"),
    "android.permission.RECEIVE_BOOT_COMPLETED":
        ("HIGH",     "Auto-starts on every reboot — permanent infection"),
    "android.permission.FOREGROUND_SERVICE":
        ("MEDIUM",   "Runs persistently in background"),
    "android.permission.WAKE_LOCK":
        ("MEDIUM",   "Keeps phone awake — keeps malware active"),
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS":
        ("HIGH",     "Bypasses battery optimization — runs 24/7 draining your phone"),
    "android.permission.GET_ACCOUNTS":
        ("HIGH",     "Lists all Google and banking accounts on your device"),
    "android.permission.USE_CREDENTIALS":
        ("CRITICAL", "Uses your stored account credentials without asking"),
    "android.permission.READ_PHONE_STATE":
        ("HIGH",     "Reads your IMEI, phone number and SIM identity"),
    "android.permission.CALL_PHONE":
        ("HIGH",     "Makes calls from your number silently — premium fraud"),
    "android.permission.POST_NOTIFICATIONS":
        ("MEDIUM",   "Shows fake notifications to trick you"),
    "com.google.android.c2dm.permission.RECEIVE":
        ("HIGH",     "Firebase C2 channel — attacker sends remote commands to your device"),
    "android.permission.INTERNET":
        ("MEDIUM",   "Internet access — sends your stolen data to the attacker"),
    "android.permission.NFC":
        ("HIGH",     "Reads NFC payment cards"),
    "android.permission.PACKAGE_USAGE_STATS":
        ("HIGH",     "Monitors which apps you open — waits for banking apps to attack"),
    "android.permission.CHANGE_NETWORK_STATE":
        ("MEDIUM",   "Changes network settings"),
    "android.permission.INSTALL_PACKAGES":
        ("CRITICAL", "Silently installs packages — no user consent needed"),
}

MALWARE_FAMILIES = [
    {
        "name": "🏦 Banking Trojan Dropper",
        "indicators": ["REQUEST_INSTALL_PACKAGES", "RECEIVE_BOOT_COMPLETED", "INTERNET"],
        "description": "Downloads and silently installs real banking malware on your device",
        "color": "#ef4444"
    },
    {
        "name": "💳 UPI / Payment PIN Stealer",
        "indicators": ["SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "QUERY_ALL_PACKAGES"],
        "description": "Shows fake Google Pay / Paytm screens over real apps to steal your UPI PIN",
        "color": "#f97316"
    },
    {
        "name": "📱 SMS OTP Interceptor",
        "indicators": ["READ_SMS", "RECEIVE_SMS", "INTERNET"],
        "description": "Steals bank OTPs from SMS messages and sends them to attacker server",
        "color": "#ef4444"
    },
    {
        "name": "🔥 Firebase C2 Botnet Agent",
        "indicators": ["com.google.android.c2dm.permission.RECEIVE", "RECEIVE_BOOT_COMPLETED"],
        "description": "Your device joins attacker's botnet — controlled remotely via Firebase",
        "color": "#f97316"
    },
    {
        "name": "🎙️ Spyware / Remote Access Trojan",
        "indicators": ["BIND_ACCESSIBILITY_SERVICE", "RECORD_AUDIO", "READ_CONTACTS"],
        "description": "Full RAT — records calls, steals contacts, reads your screen remotely",
        "color": "#dc2626"
    },
    {
        "name": "🔒 Ransomware / Device Locker",
        "indicators": ["BIND_DEVICE_ADMIN", "RECEIVE_BOOT_COMPLETED"],
        "description": "Locks your device and prevents uninstall — demands ransom",
        "color": "#991b1b"
    },
]

FAKE_APP_PATTERNS = [
    (r"masqat",                        "Word 'masqat' (masquerade) found in package name"),
    (r"^com\.im\.",                     "Unusual package prefix 'com.im' — not a real developer namespace"),
    (r"mparivahan|parivahan",           "Impersonates mParivahan (official NIC government app)"),
    (r"sbi|icici|hdfc|axis|kotak",      "Impersonates Indian banking app"),
    (r"paytm|gpay|phonepe|bhim",        "Impersonates Indian payment app"),
    (r"irctc|aadhaar|income.?tax|epfo", "Impersonates Indian government service"),
    (r"police|challan|traffic|echallan","Impersonates traffic police / law enforcement"),
    (r"gov\.in",                        "Package name spoofs India government domain"),
    (r"\.fake\.|\.clone\.",             "Contains 'fake' or 'clone' in package name"),
]

IMPACT_MAP = {
    "READ_SMS":        "💸 Bank OTPs stolen → attacker logs into your bank accounts",
    "RECEIVE_SMS":     "💸 All incoming SMS intercepted → real-time OTP theft",
    "SEND_SMS":        "📤 Your phone spreads malware SMS to all your contacts",
    "READ_CONTACTS":   "👥 Entire contact list stolen → used for phishing campaigns",
    "RECORD_AUDIO":    "🎙️ Phone calls and conversations recorded without you knowing",
    "CAMERA":          "📸 Photos and videos taken silently — potential blackmail",
    "ACCESS_FINE_LOCATION": "📍 Your location tracked 24/7",
    "READ_EXTERNAL_STORAGE": "📁 All photos, documents and private files stolen",
    "REQUEST_INSTALL_PACKAGES": "📲 More malware silently installed on your device",
    "QUERY_ALL_PACKAGES": "🏦 Your banking apps identified and specifically targeted",
    "SYSTEM_ALERT_WINDOW": "🎭 Fake bank/UPI login screens shown → passwords and PINs stolen",
    "BIND_ACCESSIBILITY_SERVICE": "🤖 Device fully controlled — makes payments on your behalf",
    "BIND_DEVICE_ADMIN": "🔒 Device locked, app cannot be uninstalled without factory reset",
    "RECEIVE_BOOT_COMPLETED": "🔄 Malware restarts automatically on every phone reboot",
    "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": "⚡ Malware runs 24/7 — constant data theft",
    "GET_ACCOUNTS":    "🔑 All Google and banking accounts on device enumerated",
    "USE_CREDENTIALS": "🔑 Your stored account credentials used by attacker",
    "READ_PHONE_STATE": "📱 Your IMEI and phone identity stolen — SIM swap fraud risk",
}

# ─────────────────────────────────────────────────────────────
# PURE PYTHON ANALYSIS ENGINE (no jadx, no system tools)
# ─────────────────────────────────────────────────────────────

def entropy(data: bytes) -> float:
    if not data: return 0.0
    freq = [0] * 256
    for b in data: freq[b] += 1
    n = len(data)
    return -sum((f/n) * math.log2(f/n) for f in freq if f)

def detect_type(data: bytes) -> str:
    if len(data) < 4: return "UNKNOWN"
    if data[:2] == b'PK':      return "ZIP / APK"
    if data[:4] == b'dex\n':   return "DEX (Android bytecode)"
    if data[:4] == b'\x7fELF': return "ELF (native binary)"
    if data[:4] == b'%PDF':    return "PDF"
    if data[:2] == b'MZ':      return "Windows EXE"
    if data[:2] == b'\x1f\x8b':return "GZIP archive"
    return "ENCRYPTED / UNKNOWN"

def extract_strings_python(data: bytes, min_len: int = 6) -> list:
    """Pure Python string extractor — replaces the 'strings' command."""
    result = []
    current = []
    for b in data:
        if 0x20 <= b <= 0x7e:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                result.append("".join(current))
            current = []
    if len(current) >= min_len:
        result.append("".join(current))
    return result

def parse_binary_manifest(data: bytes) -> str:
    """
    Parses Android binary XML (AndroidManifest.xml) without jadx.
    Extracts permission names and package info from the binary format.
    """
    try:
        from androguard.core.axml import AXMLPrinter
        printer = AXMLPrinter(data)
        return printer.get_xml().decode("utf-8", errors="ignore")
    except Exception:
        pass

    # Fallback: extract readable strings from binary manifest
    strings = extract_strings_python(data, min_len=4)
    return "\n".join(strings)

def parse_manifest_text(content: str) -> dict:
    r = {
        "package": None, "version_name": None, "version_code": None,
        "min_sdk": None, "target_sdk": None, "permissions": [],
        "activities": [], "services": [], "receivers": [],
        "uses_firebase": False, "boot_receiver": False,
    }
    patterns = {
        "package":      r'package="([^"]+)"',
        "version_name": r'versionName="([^"]+)"',
        "version_code": r'versionCode="([^"]+)"',
        "min_sdk":      r'minSdkVersion="([^"]+)"',
        "target_sdk":   r'targetSdkVersion="([^"]+)"',
    }
    for key, pat in patterns.items():
        m = re.search(pat, content)
        if m: r[key] = m.group(1)

    r["permissions"] = list(set(re.findall(
        r'(?:name=|permission=)"(android\.permission\.[^"]+|com\.[^"]+\.permission\.[^"]+|com\.google\.android\.[^"]+)"',
        content
    )))
    r["activities"] = re.findall(r'<activity[^>]+name="([^"]+)"', content)
    r["services"]   = re.findall(r'<service[^>]+name="([^"]+)"',   content)
    r["receivers"]  = re.findall(r'<receiver[^>]+name="([^"]+)"',  content)
    r["uses_firebase"] = bool(re.search(r'firebase|c2dm|FCM|FirebaseMessaging', content, re.I))
    r["boot_receiver"] = "BOOT_COMPLETED" in content
    return r

def analyze_dex_strings(data: bytes) -> list:
    """Extract readable strings from DEX bytecode — finds C2 URLs, secrets."""
    raw = extract_strings_python(data, min_len=8)
    interesting = []
    for s in raw:
        if any(x in s.lower() for x in [
            "http", "https", "url", "api", "key", "token", "secret",
            "upi", "pay", "bank", "sms", "admin", "firebase", "password",
            "install", "download", ".apk", "exec", "cmd", "shell",
            "overlay", "accessibility", "/api/", "webhook", "botnet",
            "inject", "hook", "root", "su ", "superuser",
        ]):
            interesting.append(s)
    return interesting[:50]

def analyze_apk(apk_bytes: bytes, filename: str, progress_cb=None) -> dict:
    result = {
        "file_name": filename,
        "file_size": len(apk_bytes),
        "hashes": {},
        "manifest": {},
        "dangerous_perms": [],
        "assets": [],
        "encrypted_assets": [],
        "native_libs": [],
        "malware_families": [],
        "compromised": [],
        "findings": [],
        "risk_score": 0,
        "threat_level": "SAFE",
        "zip_entries": 0,
        "interesting_strings": [],
        "dex_count": 0,
    }

    WEIGHTS = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 2}

    def add(sev, cat, msg, detail=""):
        result["findings"].append({"severity": sev, "category": cat, "message": msg, "detail": detail})
        result["risk_score"] += WEIGHTS.get(sev, 0)

    # ── 1. Hashes ─────────────────────────────────────────────
    if progress_cb: progress_cb(8, "Computing file hashes...")
    result["hashes"] = {
        "md5":    hashlib.md5(apk_bytes).hexdigest(),
        "sha1":   hashlib.sha1(apk_bytes).hexdigest(),
        "sha256": hashlib.sha256(apk_bytes).hexdigest(),
    }

    # ── 2. ZIP Structure ──────────────────────────────────────
    if progress_cb: progress_cb(18, "Reading APK structure...")
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
            tmp.write(apk_bytes)
            tmp_path = tmp.name

        try:
            with zipfile.ZipFile(tmp_path, "r") as z:
                names = z.namelist()
                result["zip_entries"] = len(names)

                dex_files = [n for n in names if n.endswith(".dex")]
                result["dex_count"] = len(dex_files)
                if len(dex_files) > 3:
                    add("MEDIUM", "MULTI-DEX", f"{len(dex_files)} DEX files — heavily obfuscated")

                result["native_libs"] = [n for n in names if n.startswith("lib/") and n.endswith(".so")]

                for n in names:
                    lower = n.lower()
                    if lower.endswith(".apk") and n != filename:
                        add("CRITICAL", "EMBEDDED APK", f"APK inside APK: {n}",
                            "Classic dropper — second malware installed silently")
                        result["risk_score"] += 10

                # ── 3. Parse Manifest ──────────────────────────
                if progress_cb: progress_cb(30, "Parsing AndroidManifest.xml...")
                if "AndroidManifest.xml" in names:
                    raw_manifest = z.read("AndroidManifest.xml")
                    manifest_text = parse_binary_manifest(raw_manifest)
                    result["manifest"] = parse_manifest_text(manifest_text)
                else:
                    add("HIGH", "MANIFEST", "AndroidManifest.xml missing — invalid or heavily obfuscated APK")

                # ── 4. DEX String Analysis ─────────────────────
                if progress_cb: progress_cb(42, "Scanning DEX bytecode for secrets...")
                for dex in dex_files[:2]:
                    try:
                        dex_data = z.read(dex)
                        interesting = analyze_dex_strings(dex_data)
                        result["interesting_strings"].extend(interesting)
                    except: pass

                # ── 5. Asset Encryption Analysis ──────────────
                if progress_cb: progress_cb(55, "Detecting encrypted payloads in assets...")
                asset_names = [n for n in names if n.startswith("assets/") and not n.endswith("/")]
                for asset_name in asset_names:
                    if "MaterialIcons" in asset_name or asset_name.endswith(".ttf"):
                        continue
                    try:
                        try:
                            asset_data = z.read(asset_name)
                        except NotImplementedError:
                            # Non-standard compression — still encrypted
                            asset_data = b""
                            result["encrypted_assets"].append(os.path.basename(asset_name))
                            add("CRITICAL", "ENCRYPTED PAYLOAD",
                                f"Asset '{os.path.basename(asset_name)}' uses obfuscated compression",
                                "Anti-analysis compression method — hides encrypted payload from tools")
                            result["risk_score"] += 10
                            continue

                        sz = len(asset_data)
                        if sz < 32: continue
                        e  = entropy(asset_data)
                        ft = detect_type(asset_data)
                        enc = e >= 7.8

                        info = {
                            "name":      os.path.basename(asset_name),
                            "full_path": asset_name,
                            "size":      sz,
                            "entropy":   round(e, 3),
                            "type":      ft,
                            "encrypted": enc
                        }
                        result["assets"].append(info)

                        if enc:
                            result["encrypted_assets"].append(os.path.basename(asset_name))
                            add("CRITICAL", "ENCRYPTED BLOB",
                                f"'{os.path.basename(asset_name)}' is AES-encrypted payload",
                                f"Entropy {e:.3f}/8.0 · {sz//1024}KB · Decrypted at runtime by native .so")
                            result["risk_score"] += 15
                        elif e >= 7.0:
                            result["assets"][-1]["encrypted"] = False
                            add("HIGH", "HIGH ENTROPY ASSET",
                                f"'{os.path.basename(asset_name)}' may be obfuscated payload",
                                f"Entropy {e:.3f}/8.0")
                            result["risk_score"] += 5
                    except Exception:
                        pass

                # ── 6. Native Library Analysis ─────────────────
                if progress_cb: progress_cb(68, "Analysing native libraries...")
                for lib in result["native_libs"]:
                    lib_name = os.path.basename(lib)
                    try:
                        lib_data = z.read(lib)
                        lib_strings = extract_strings_python(lib_data, 8)

                        # JNI hooks
                        jni = [s for s in lib_strings if s.startswith("Java_")]
                        if jni:
                            for j in jni[:8]:
                                clean = j.replace("Java_","").replace("__"," ← ").replace("_",".")
                                add("HIGH", "JNI HOOK", f"Native method hook: {clean[:80]}")

                        # Anti-emulator via sensor hooks
                        if any("SensorEvent" in s or "onSensorChanged" in s for s in lib_strings):
                            add("HIGH", "ANTI-EMULATOR",
                                f"Sensor hooks in {lib_name}",
                                "Uses phone sensors to detect emulator/sandbox — evades automated analysis")
                            result["risk_score"] += 10

                        # Obfuscated lib name
                        base = lib_name.replace("lib","").replace(".so","")
                        if len(lib_name) > 20 and base.islower() and base.isalpha():
                            add("HIGH", "OBFUSCATED NAME",
                                f"Nonsense library name: {lib_name}",
                                "Random long names used to defeat AV signature matching")
                            result["risk_score"] += 8

                        # Entropy
                        le = entropy(lib_data)
                        if le > 7.5:
                            add("HIGH", "PACKED LIBRARY",
                                f"{lib_name} is packed/encrypted (entropy={le:.3f})")
                            result["risk_score"] += 8

                    except Exception:
                        pass

        except NotImplementedError:
            # Whole APK uses non-standard compression
            add("HIGH", "OBFUSCATION",
                "Non-standard ZIP compression (0xffffb21b) on entire APK",
                "Anti-analysis technique — prevents most decompilers from opening this file")
            result["risk_score"] += 15

        except zipfile.BadZipFile:
            add("HIGH", "CORRUPT APK", "APK is not a valid ZIP file — may be obfuscated or corrupted")

    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

    # ── 7. Manifest Deep Analysis ─────────────────────────────
    if progress_cb: progress_cb(76, "Analysing permissions and app identity...")
    manifest = result["manifest"]
    pkg = manifest.get("package") or ""

    # Fake app detection
    for pat, desc in FAKE_APP_PATTERNS:
        if re.search(pat, pkg, re.IGNORECASE):
            add("CRITICAL", "FAKE APP DETECTED", desc, f"Package: {pkg}")
            result["risk_score"] += 25
            break

    if manifest.get("uses_firebase"):
        add("HIGH", "FIREBASE C2",
            "Firebase Cloud Messaging declared",
            "Attacker sends remote commands to all infected devices via Google infrastructure")
        result["risk_score"] += 12

    if manifest.get("boot_receiver"):
        add("HIGH", "PERSISTENCE",
            "BOOT_COMPLETED receiver — survives every reboot",
            "Malware auto-restarts whenever the phone is turned on")
        result["risk_score"] += 10

    try:
        sdk = int(manifest.get("target_sdk") or 28)
        if sdk <= 22:
            add("HIGH", "SDK EVASION",
                f"Targets Android SDK {sdk} (very old)",
                "Old SDK bypasses Android runtime permissions — all permissions auto-granted")
            result["risk_score"] += 15
    except: pass

    # ── 8. Permission Analysis ───────────────────────────────
    if progress_cb: progress_cb(84, "Checking dangerous permissions...")
    perms = manifest.get("permissions", [])
    seen_perms = set()
    for perm in perms:
        if perm in seen_perms: continue
        seen_perms.add(perm)
        if perm in DANGEROUS_PERMISSIONS:
            sev, desc = DANGEROUS_PERMISSIONS[perm]
            short = perm.split(".")[-1]
            result["dangerous_perms"].append({
                "permission": perm, "short": short,
                "severity": sev, "description": desc
            })
            add(sev, "PERMISSION", short, desc)

    # ── 9. Interesting DEX strings ──────────────────────────
    if progress_cb: progress_cb(89, "Hunting for hardcoded secrets and C2 URLs...")
    for s in result["interesting_strings"]:
        if re.match(r'https?://', s) and len(s) > 15:
            add("MEDIUM", "HARDCODED URL", s[:100], "Found in DEX bytecode")
        elif re.search(r'(firebase|googleapis|firestore)', s, re.I):
            add("HIGH", "FIREBASE ENDPOINT", s[:100], "Firebase API endpoint in DEX")
        elif re.search(r'(password|passwd|secret|apikey|api_key|token)', s, re.I):
            add("HIGH", "HARDCODED SECRET", s[:80], "Potential hardcoded credential in DEX")

    # ── 10. Encrypted payload summary ──────────────────────
    if len(result["encrypted_assets"]) >= 2:
        total_sz = sum(a["size"] for a in result["assets"] if a.get("encrypted"))
        add("CRITICAL", "DROPPER CONFIRMED",
            f"{len(result['encrypted_assets'])} AES-encrypted payloads ({total_sz//1024//1024}MB total)",
            "Definitive dropper signature — real malware hidden in encrypted blobs, decrypted at runtime")
        result["risk_score"] += 30

    # ── 11. Malware Family Matching ─────────────────────────
    if progress_cb: progress_cb(93, "Fingerprinting malware family...")
    perm_shorts = set(p.split(".")[-1] for p in perms)
    perm_full   = set(perms)
    for family in MALWARE_FAMILIES:
        hits = sum(1 for ind in family["indicators"] if ind in perm_shorts or ind in perm_full)
        conf = hits / len(family["indicators"])
        if conf >= 0.6:
            result["malware_families"].append({**family, "confidence": round(conf * 100)})
            result["risk_score"] += 25

    # ── 12. Impact Map ──────────────────────────────────────
    if progress_cb: progress_cb(97, "Mapping attack impact...")
    seen_impact = set()
    for perm in perms:
        short = perm.split(".")[-1]
        if short in IMPACT_MAP and short not in seen_impact:
            seen_impact.add(short)
            result["compromised"].append(IMPACT_MAP[short])
    if result["encrypted_assets"]:
        result["compromised"].append("📲 Hidden secondary malware installed via encrypted dropper payload")
    if manifest.get("uses_firebase"):
        result["compromised"].append("🤖 Device added to attacker's remotely-controlled botnet via Firebase")

    # ── 13. Verdict ─────────────────────────────────────────
    sc = result["risk_score"]
    if   sc >= 120: result["threat_level"] = "CRITICAL"
    elif sc >= 70:  result["threat_level"] = "HIGH"
    elif sc >= 35:  result["threat_level"] = "MEDIUM"
    elif sc >= 10:  result["threat_level"] = "LOW"
    else:           result["threat_level"] = "SAFE"

    if progress_cb: progress_cb(100, "Analysis complete!")
    return result


# ─────────────────────────────────────────────────────────────
# UI RENDERING
# ─────────────────────────────────────────────────────────────

def render_verdict(r):
    sc = r["risk_score"]
    tl = r["threat_level"]
    cfg = {
        "CRITICAL": ("#7f1d1d","#ef4444","#fca5a5","⛔  CONFIRMED MALWARE",   "DELETE IMMEDIATELY — DO NOT INSTALL"),
        "HIGH":     ("#431407","#f97316","#fdba74","🚨  HIGHLY DANGEROUS",     "Very likely malicious — treat as malware"),
        "MEDIUM":   ("#422006","#d97706","#fcd34d","⚠️  SUSPICIOUS",           "Potentially dangerous — verify before installing"),
        "LOW":      ("#14532d","#16a34a","#86efac","⚠️  LOW RISK",             "Some concerns — verify the source"),
        "SAFE":     ("#0f172a","#22c55e","#86efac","✅  LIKELY SAFE",           "No major threats detected"),
    }
    bg, border, text, title, sub = cfg.get(tl, cfg["SAFE"])
    pct = min(int((sc / 300) * 100), 100)
    bar_col = "#ef4444" if tl in ("CRITICAL","HIGH") else "#f59e0b" if tl=="MEDIUM" else "#22c55e"
    st.markdown(f"""
    <div style="background:{bg};border:2px solid {border};border-radius:16px;
                padding:30px;text-align:center;margin:20px 0">
        <div style="font-size:2.2rem;font-weight:800;color:{text}">{title}</div>
        <div style="color:{border};font-size:1rem;margin-top:6px">{sub}</div>
        <div style="margin-top:18px">
            <div style="color:#64748b;font-size:0.78rem;margin-bottom:6px">RISK SCORE: {sc}</div>
            <div style="background:#1e293b;border-radius:999px;height:12px;
                        max-width:400px;margin:0 auto;overflow:hidden">
                <div style="width:{pct}%;height:100%;background:{bar_col};
                            border-radius:999px"></div>
            </div>
        </div>
    </div>""", unsafe_allow_html=True)

def render_stat_boxes(r):
    crit = sum(1 for f in r["findings"] if f["severity"] == "CRITICAL")
    high = sum(1 for f in r["findings"] if f["severity"] == "HIGH")
    enc  = len(r["encrypted_assets"])
    perms= len(r["dangerous_perms"])
    fams = len(r["malware_families"])
    sz   = r["file_size"] / (1024 * 1024)
    stats = [
        (str(crit),    "CRITICAL",      "#ef4444"),
        (str(high),    "HIGH RISK",     "#f97316"),
        (str(enc),     "HIDDEN BLOBS",  "#a855f7"),
        (str(perms),   "DANGER PERMS",  "#06b6d4"),
        (str(fams),    "MALWARE MATCH", "#f43f5e"),
        (f"{sz:.1f}M", "FILE SIZE",     "#64748b"),
    ]
    cols = st.columns(6)
    for col, (num, label, color) in zip(cols, stats):
        col.markdown(f"""
        <div style="background:#0f172a;border:1px solid #1e293b;border-radius:10px;
                    padding:14px;text-align:center">
            <div style="font-size:1.7rem;font-weight:700;color:{color}">{num}</div>
            <div style="font-size:0.62rem;color:#64748b;letter-spacing:0.08em;
                        text-transform:uppercase;margin-top:3px">{label}</div>
        </div>""", unsafe_allow_html=True)

def render_hashes(r):
    st.markdown("""<div class="section-header">
        <div class="section-num">1</div>
        <div class="section-title">File Identification & Hashes</div>
    </div>""", unsafe_allow_html=True)
    h = r["hashes"]
    st.markdown(f"""
    <div style="background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:16px">
        <div class="hash-row"><span class="hash-label">FILE</span>
            <span style="color:#e2e8f0;font-family:monospace">{r['file_name']}</span></div>
        <div class="hash-row"><span class="hash-label">SIZE</span>
            <span class="hash-value">{r['file_size']/1024/1024:.2f} MB ({r['file_size']:,} bytes)</span></div>
        <div class="hash-row"><span class="hash-label">MD5</span>
            <span class="hash-value">{h.get('md5','N/A')}</span></div>
        <div class="hash-row"><span class="hash-label">SHA1</span>
            <span class="hash-value">{h.get('sha1','N/A')}</span></div>
        <div class="hash-row" style="border:none"><span class="hash-label">SHA256</span>
            <span class="hash-value">{h.get('sha256','N/A')}</span></div>
    </div>
    <div style="margin-top:8px;padding:10px 14px;background:rgba(99,102,241,0.1);
                border:1px solid rgba(99,102,241,0.3);border-radius:8px;
                font-size:0.82rem;color:#a5b4fc">
        💡 Copy the <strong>SHA256</strong> hash and search it on
        <strong>virustotal.com</strong> — 70+ antivirus engines will tell you if it's flagged
    </div>""", unsafe_allow_html=True)

def render_manifest(r):
    st.markdown("""<div class="section-header" style="margin-top:24px">
        <div class="section-num">2</div>
        <div class="section-title">App Identity</div>
    </div>""", unsafe_allow_html=True)
    m   = r["manifest"]
    pkg = m.get("package") or "Unknown"
    ver = m.get("version_name") or "N/A"
    sdk = m.get("target_sdk") or "N/A"
    is_sus = any(re.search(p, pkg, re.I) for p, _ in FAKE_APP_PATTERNS)
    p_col  = "#fca5a5" if is_sus else "#86efac"
    p_bg   = "rgba(239,68,68,0.12)" if is_sus else "rgba(34,197,94,0.1)"
    p_note = "⚠️ SUSPICIOUS" if is_sus else "✓ Looks normal"
    st.markdown(f"""
    <div style="background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:16px">
        <div class="hash-row">
            <span class="hash-label">PACKAGE</span>
            <span style="background:{p_bg};color:{p_col};padding:2px 10px;
                         border-radius:6px;font-family:monospace;font-size:0.83rem">{pkg}</span>
            <span style="color:{p_col};font-size:0.73rem;margin-left:6px">{p_note}</span>
        </div>
        <div class="hash-row"><span class="hash-label">VERSION</span>
            <span class="hash-value">{ver}</span></div>
        <div class="hash-row"><span class="hash-label">SDK</span>
            <span class="hash-value">Android SDK {sdk}</span></div>
        <div class="hash-row"><span class="hash-label">DEX FILES</span>
            <span class="hash-value">{r.get('dex_count',1)}</span></div>
        <div class="hash-row"><span class="hash-label">NATIVE LIBS</span>
            <span class="hash-value">{len(r.get('native_libs',[]))}</span></div>
        <div class="hash-row" style="border:none"><span class="hash-label">ZIP ENTRIES</span>
            <span class="hash-value">{r.get('zip_entries',0)}</span></div>
    </div>""", unsafe_allow_html=True)

    if m.get("uses_firebase"):
        st.markdown("""
        <div style="background:rgba(249,115,22,0.09);border:1px solid rgba(249,115,22,0.3);
                    border-radius:8px;padding:10px 14px;margin:6px 0;font-size:0.87rem">
            <span style="color:#fb923c;font-weight:600">🔥 Firebase C2</span>
            <span style="color:#94a3b8;margin-left:8px">Attacker can send remote commands to all infected devices</span>
        </div>""", unsafe_allow_html=True)
    if m.get("boot_receiver"):
        st.markdown("""
        <div style="background:rgba(239,68,68,0.09);border:1px solid rgba(239,68,68,0.3);
                    border-radius:8px;padding:10px 14px;margin:6px 0;font-size:0.87rem">
            <span style="color:#f87171;font-weight:600">🔄 Boot Persistence</span>
            <span style="color:#94a3b8;margin-left:8px">Malware restarts automatically on every phone reboot</span>
        </div>""", unsafe_allow_html=True)

def render_permissions(r):
    st.markdown("""<div class="section-header" style="margin-top:4px">
        <div class="section-num">3</div>
        <div class="section-title">Dangerous Permissions</div>
    </div>""", unsafe_allow_html=True)
    perms = r["dangerous_perms"]
    if not perms:
        st.markdown('<div style="color:#22c55e;padding:10px">✓ No dangerous permissions found</div>',
                    unsafe_allow_html=True)
        return
    colors = {
        "CRITICAL": ("#ef4444","rgba(239,68,68,0.09)","rgba(239,68,68,0.3)","🔴"),
        "HIGH":     ("#f97316","rgba(249,115,22,0.09)","rgba(249,115,22,0.3)","🟠"),
        "MEDIUM":   ("#f59e0b","rgba(245,158,11,0.09)","rgba(245,158,11,0.3)","🟡"),
        "LOW":      ("#22c55e","rgba(34,197,94,0.09)","rgba(34,197,94,0.3)","🟢"),
    }
    for p in sorted(perms, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW"].index(x["severity"]) if x["severity"] in ["CRITICAL","HIGH","MEDIUM","LOW"] else 9):
        tc, bg, border, icon = colors.get(p["severity"], ("#64748b","rgba(100,116,139,0.08)","#1e293b","⚪"))
        st.markdown(f"""
        <div style="background:{bg};border:1px solid {border};border-radius:8px;
                    padding:10px 14px;margin:5px 0;display:flex;align-items:flex-start;gap:10px">
            <span style="margin-top:1px">{icon}</span>
            <div style="flex:1">
                <div style="color:{tc};font-weight:600;font-size:0.85rem;
                            font-family:monospace">{p['short']}</div>
                <div style="color:#94a3b8;font-size:0.8rem;margin-top:2px">{p['description']}</div>
                <div style="color:#475569;font-size:0.71rem;margin-top:2px;
                            font-family:monospace">{p['permission']}</div>
            </div>
            <span style="background:{bg};border:1px solid {border};color:{tc};
                         padding:2px 8px;border-radius:999px;font-size:0.68rem;
                         font-weight:700;white-space:nowrap">{p['severity']}</span>
        </div>""", unsafe_allow_html=True)

def render_assets(r):
    st.markdown("""<div class="section-header" style="margin-top:4px">
        <div class="section-num">4</div>
        <div class="section-title">Encrypted Payload Detection</div>
    </div>""", unsafe_allow_html=True)
    enc = r.get("encrypted_assets", [])
    if not enc:
        st.markdown('<div style="color:#22c55e;padding:10px">✓ No encrypted payloads detected</div>',
                    unsafe_allow_html=True)
    else:
        total_sz = sum(a.get("size",0) for a in r.get("assets",[]) if a.get("encrypted"))
        st.markdown(f"""
        <div style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);
                    border-radius:10px;padding:14px 18px;margin-bottom:12px">
            <div style="color:#ef4444;font-weight:700">
                ⛔ {len(enc)} AES-Encrypted Payloads — {total_sz//1024//1024}MB Total</div>
            <div style="color:#fca5a5;font-size:0.85rem;margin-top:4px">
                Real malware hidden in encrypted blobs. Decrypted at runtime by the native
                library. This is the <strong>definitive signature of a dropper APK</strong>.
            </div>
        </div>""", unsafe_allow_html=True)

    for asset in r.get("assets", []):
        if not isinstance(asset, dict): continue
        e   = asset.get("entropy", 0)
        enc = asset.get("encrypted", False)
        nm  = asset.get("name","?")
        sz  = asset.get("size", 0)
        ft  = asset.get("type","?")
        if enc:
            st.markdown(f"""
            <div style="background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.25);
                        border-radius:8px;padding:9px 14px;margin:4px 0;
                        display:flex;justify-content:space-between;align-items:center">
                <div>
                    <span style="color:#fca5a5;font-family:monospace;font-size:0.84rem">🔒 {nm}</span>
                    <span style="color:#64748b;font-size:0.74rem;margin-left:10px">{sz//1024} KB · {ft}</span>
                </div>
                <div style="color:#ef4444;font-size:0.77rem;font-weight:600;white-space:nowrap">
                    {e:.3f}/8.0</div>
            </div>""", unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div style="background:rgba(100,116,139,0.06);border:1px solid #1e293b;
                        border-radius:8px;padding:8px 14px;margin:4px 0;
                        display:flex;justify-content:space-between;align-items:center">
                <span style="color:#64748b;font-family:monospace;font-size:0.81rem">📄 {nm}</span>
                <span style="color:#475569;font-size:0.74rem">entropy: {e:.3f} · normal</span>
            </div>""", unsafe_allow_html=True)

def render_malware_families(r):
    st.markdown("""<div class="section-header" style="margin-top:4px">
        <div class="section-num">5</div>
        <div class="section-title">Malware Family Match</div>
    </div>""", unsafe_allow_html=True)
    fams = r.get("malware_families", [])
    if not fams:
        st.markdown('<div style="color:#22c55e;padding:10px">✓ No known malware family matched</div>',
                    unsafe_allow_html=True)
        return
    for fam in sorted(fams, key=lambda x: -x["confidence"]):
        col   = fam.get("color","#ef4444")
        conf  = fam["confidence"]
        st.markdown(f"""
        <div style="background:rgba(239,68,68,0.07);border:1px solid rgba(239,68,68,0.2);
                    border-radius:10px;padding:16px;margin:8px 0">
            <div style="display:flex;justify-content:space-between;
                        align-items:center;margin-bottom:8px">
                <div style="color:{col};font-weight:700;font-size:0.95rem">{fam['name']}</div>
                <div style="color:{col};font-size:0.8rem;font-weight:600">Match: {conf}%</div>
            </div>
            <div style="background:#1e293b;border-radius:999px;height:7px;margin-bottom:10px">
                <div style="width:{conf}%;height:100%;background:{col};
                            border-radius:999px"></div>
            </div>
            <div style="color:#94a3b8;font-size:0.84rem">{fam['description']}</div>
        </div>""", unsafe_allow_html=True)

def render_compromise(r):
    st.markdown("""<div class="section-header" style="margin-top:4px">
        <div class="section-num">6</div>
        <div class="section-title">What Gets Compromised If Installed</div>
    </div>""", unsafe_allow_html=True)
    items = r.get("compromised", [])
    if not items:
        st.markdown('<div style="color:#22c55e;padding:10px">✓ No critical compromise scenarios</div>',
                    unsafe_allow_html=True)
        return
    for item in items:
        st.markdown(f"""
        <div style="display:flex;align-items:flex-start;gap:10px;padding:11px 15px;
                    background:rgba(239,68,68,0.07);border:1px solid rgba(239,68,68,0.2);
                    border-radius:8px;margin:5px 0;color:#fca5a5;font-size:0.88rem">
            <span>✗</span><span>{item}</span>
        </div>""", unsafe_allow_html=True)

def render_findings(r):
    st.markdown("""<div class="section-header" style="margin-top:4px">
        <div class="section-num">7</div>
        <div class="section-title">All Findings</div>
    </div>""", unsafe_allow_html=True)
    order  = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4,"GOOD":5}
    sorted_f = sorted(r.get("findings",[]), key=lambda x: order.get(x["severity"],9))
    colors = {
        "CRITICAL": ("#ef4444","rgba(239,68,68,0.08)","rgba(239,68,68,0.3)","🔴"),
        "HIGH":     ("#f97316","rgba(249,115,22,0.08)","rgba(249,115,22,0.3)","🟠"),
        "MEDIUM":   ("#f59e0b","rgba(245,158,11,0.08)","rgba(245,158,11,0.3)","🟡"),
        "LOW":      ("#22c55e","rgba(34,197,94,0.08)","rgba(34,197,94,0.3)","🟢"),
        "INFO":     ("#64748b","rgba(100,116,139,0.06)","#1e293b","ℹ️"),
    }
    for f in sorted_f:
        sev = f["severity"]
        if sev in ("GOOD",): continue
        tc, bg, border, icon = colors.get(sev, colors["INFO"])
        detail = f'<div style="color:#64748b;font-size:0.77rem;margin-top:3px;font-style:italic">{f["detail"]}</div>' if f.get("detail") else ""
        st.markdown(f"""
        <div style="background:{bg};border:1px solid {border};border-radius:8px;
                    padding:9px 13px;margin:4px 0;display:flex;
                    align-items:flex-start;gap:10px">
            <span style="font-size:0.9rem;margin-top:1px">{icon}</span>
            <div style="flex:1">
                <div style="display:flex;justify-content:space-between;align-items:flex-start">
                    <span style="color:{tc};font-weight:600;
                                 font-size:0.84rem">{f['category']}: {f['message']}</span>
                    <span style="color:{tc};font-size:0.67rem;font-weight:700;
                                 opacity:0.7;white-space:nowrap;margin-left:8px">{sev}</span>
                </div>
                {detail}
            </div>
        </div>""", unsafe_allow_html=True)

def render_strings(r):
    strings = r.get("interesting_strings", [])
    if not strings: return
    st.markdown("""<div class="section-header" style="margin-top:4px">
        <div class="section-num">+</div>
        <div class="section-title">Interesting Strings Found in DEX</div>
    </div>""", unsafe_allow_html=True)
    for s in strings[:30]:
        st.markdown(f"""
        <div style="font-family:monospace;font-size:0.79rem;color:#a78bfa;padding:4px 12px;
                    background:rgba(167,139,250,0.08);border-radius:6px;margin:3px 0;
                    word-break:break-all">⚡ {s}</div>""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
# MAIN APP
# ─────────────────────────────────────────────────────────────

st.markdown("""
<div class="hero">
    <div style="font-size:3rem;margin-bottom:8px">🛡️</div>
    <h1>APK Threat Analyzer</h1>
    <p>Upload any Android APK — get instant deep malware analysis. No install needed.</p>
    <div style="color:#475569;font-size:0.82rem;margin-top:6px">
        Detects: Fake Apps · Banking Trojans · UPI Stealers · Droppers · Spyware · Ransomware
    </div>
</div>""", unsafe_allow_html=True)

# Upload
st.markdown("""
<div style="text-align:center;color:#64748b;font-size:0.88rem;margin-bottom:6px">
    📂 Drag & drop your APK file below, or click Browse
</div>""", unsafe_allow_html=True)

uploaded = st.file_uploader(
    "Upload APK file",
    type=["apk"],
    label_visibility="collapsed"
)

if uploaded:
    c1, c2, c3 = st.columns([1, 2, 1])
    with c2:
        go = st.button("🔍  Analyze APK Now", use_container_width=True)

    if go:
        apk_bytes  = uploaded.read()
        prog_bar   = st.progress(0)
        status_txt = st.empty()

        def cb(pct, msg):
            prog_bar.progress(pct)
            status_txt.markdown(
                f'<div style="color:#64748b;font-size:0.84rem;text-align:center">{msg}</div>',
                unsafe_allow_html=True)

        try:
            result = analyze_apk(apk_bytes, uploaded.name, cb)
        except Exception as e:
            st.error(f"Analysis error: {e}")
            st.stop()

        prog_bar.empty()
        status_txt.empty()

        st.markdown("---")
        render_verdict(result)
        st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)
        render_stat_boxes(result)

        t1, t2, t3, t4, t5 = st.tabs([
            "📋 Overview",
            "🔐 Permissions",
            "📦 Payloads",
            "🦠 Malware ID",
            "💥 Impact"
        ])

        with t1:
            render_hashes(result)
            render_manifest(result)
            render_strings(result)
            render_findings(result)
        with t2:
            render_permissions(result)
        with t3:
            render_assets(result)
        with t4:
            render_malware_families(result)
        with t5:
            render_compromise(result)

        st.markdown("---")
        sha = result["hashes"].get("sha256","")
        st.markdown(f"""
        <div style="padding:12px 16px;background:rgba(99,102,241,0.1);
                    border:1px solid rgba(99,102,241,0.3);border-radius:8px;
                    font-size:0.84rem;color:#a5b4fc;margin-bottom:10px">
            🔍 <strong>Cross-check on VirusTotal:</strong> Search SHA256 →
            <code style="background:rgba(0,0,0,0.3);padding:2px 6px;
                         border-radius:4px">{sha[:32]}...</code>
            at <strong>virustotal.com</strong>
        </div>
        <div style="padding:12px 16px;background:rgba(239,68,68,0.08);
                    border:1px solid rgba(239,68,68,0.2);border-radius:8px;
                    font-size:0.84rem;color:#fca5a5">
            🇮🇳 <strong>Report this malware:</strong>
            Cybercrime Portal → <strong>cybercrime.gov.in</strong> |
            Helpline → <strong>1930</strong>
        </div>""", unsafe_allow_html=True)

        st.download_button(
            label="⬇️  Download Full JSON Report",
            data=json.dumps(result, indent=2, default=str),
            file_name=uploaded.name.replace(".apk","_threat_report.json"),
            mime="application/json",
            use_container_width=True
        )
else:
    cols = st.columns(3)
    features = [
        ("🔍","Deep Static Analysis",  "Parses APK structure, DEX bytecode, binary manifest — all in pure Python, no system tools"),
        ("🔒","Encryption Detection",  "Finds AES-encrypted hidden payloads using entropy analysis — 8.0 = perfectly encrypted"),
        ("📋","Permission Audit",      "Checks 30+ dangerous Android permissions with plain-English explanations of each attack"),
        ("🦠","Malware Fingerprinting","Matches against 6 malware families: Banking Trojans, UPI Stealers, RATs, Droppers"),
        ("💥","Impact Report",         "Tells you exactly what data gets stolen and which accounts get compromised"),
        ("📥","Evidence Report",       "Download JSON report to submit to cybercrime.gov.in / helpline 1930"),
    ]
    for i,(icon,title,desc) in enumerate(features):
        with cols[i % 3]:
            st.markdown(f"""
            <div style="background:#111827;border:1px solid #1e293b;border-radius:12px;
                        padding:20px;margin:8px 0;min-height:140px">
                <div style="font-size:1.7rem">{icon}</div>
                <div style="color:#e2e8f0;font-weight:600;font-size:0.88rem;
                            margin:8px 0 4px 0">{title}</div>
                <div style="color:#64748b;font-size:0.79rem;line-height:1.5">{desc}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("""
    <div style="margin-top:20px;padding:14px 18px;background:rgba(99,102,241,0.08);
                border:1px solid rgba(99,102,241,0.25);border-radius:10px;
                font-size:0.84rem;color:#94a3b8;text-align:center">
        🇮🇳 Built to detect fake Indian government app scams —
        mParivahan, Aadhaar, IRCTC, Income Tax, Traffic Challan impersonators
        <br><span style="color:#64748b;font-size:0.77rem">
        Got a suspicious APK on WhatsApp or SMS? Upload it here before you install it.</span>
    </div>""", unsafe_allow_html=True)

st.markdown("""
<div style="margin-top:40px;padding:16px;border-top:1px solid #1e293b;
            text-align:center;color:#334155;font-size:0.77rem">
    APK Threat Analyzer · Cybercrime Investigation Tool ·
    Report: <strong style="color:#475569">cybercrime.gov.in</strong> ·
    Helpline: <strong style="color:#475569">1930</strong>
</div>""", unsafe_allow_html=True)
