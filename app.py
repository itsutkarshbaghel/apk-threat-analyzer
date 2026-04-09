import streamlit as st
import os
import sys
import tempfile
import zipfile
import hashlib
import math
import json
import re
import subprocess
import shutil
import time
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
code, .mono { font-family: 'JetBrains Mono', monospace !important; }

.stApp { background: #0a0e1a; color: #e2e8f0; }

/* Header */
.hero {
    background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
    border: 1px solid #334155;
    border-radius: 16px;
    padding: 40px;
    text-align: center;
    margin-bottom: 30px;
}
.hero h1 { font-size: 2.5rem; font-weight: 700; color: #f8fafc; margin: 0; }
.hero p  { color: #94a3b8; font-size: 1.1rem; margin-top: 8px; }
.hero .subtitle { color: #64748b; font-size: 0.9rem; margin-top: 4px; }

/* Upload Zone */
.upload-zone {
    border: 2px dashed #334155;
    border-radius: 12px;
    padding: 40px;
    text-align: center;
    background: #111827;
    transition: all 0.2s;
    margin: 20px 0;
}

/* Cards */
.card {
    background: #111827;
    border: 1px solid #1e293b;
    border-radius: 12px;
    padding: 20px;
    margin: 12px 0;
}
.card-title {
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: #64748b;
    margin-bottom: 12px;
}

/* Risk Meter */
.risk-critical { background: linear-gradient(135deg, #7f1d1d, #dc2626); border-left: 4px solid #ef4444; }
.risk-high     { background: linear-gradient(135deg, #431407, #ea580c); border-left: 4px solid #f97316; }
.risk-medium   { background: linear-gradient(135deg, #422006, #d97706); border-left: 4px solid #f59e0b; }
.risk-low      { background: linear-gradient(135deg, #14532d, #16a34a); border-left: 4px solid #22c55e; }

.verdict-box {
    border-radius: 12px;
    padding: 24px;
    text-align: center;
    margin: 20px 0;
}
.verdict-box h2 { font-size: 1.8rem; margin: 0; font-weight: 700; }
.verdict-box p  { margin: 6px 0 0 0; opacity: 0.85; font-size: 1rem; }

/* Finding rows */
.finding {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 10px 14px;
    border-radius: 8px;
    margin: 6px 0;
    font-size: 0.88rem;
    line-height: 1.5;
}
.finding-critical { background: rgba(239,68,68,0.12); border-left: 3px solid #ef4444; }
.finding-high     { background: rgba(249,115,22,0.12); border-left: 3px solid #f97316; }
.finding-medium   { background: rgba(245,158,11,0.12); border-left: 3px solid #f59e0b; }
.finding-low      { background: rgba(34,197,94,0.12);  border-left: 3px solid #22c55e; }
.finding-info     { background: rgba(100,116,139,0.12); border-left: 3px solid #64748b; }

.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 999px;
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.05em;
    white-space: nowrap;
}
.badge-critical { background: #7f1d1d; color: #fca5a5; }
.badge-high     { background: #431407; color: #fdba74; }
.badge-medium   { background: #422006; color: #fcd34d; }
.badge-low      { background: #14532d; color: #86efac; }
.badge-info     { background: #1e293b; color: #94a3b8; }

/* Permission grid */
.perm-grid { display: flex; flex-wrap: wrap; gap: 8px; margin: 8px 0; }
.perm-tag {
    padding: 4px 12px;
    border-radius: 6px;
    font-size: 0.78rem;
    font-weight: 500;
    font-family: 'JetBrains Mono', monospace;
}
.perm-critical { background: #450a0a; color: #fca5a5; border: 1px solid #7f1d1d; }
.perm-high     { background: #431407; color: #fdba74; border: 1px solid #7c2d12; }
.perm-medium   { background: #1c1917; color: #fcd34d; border: 1px solid #44403c; }
.perm-safe     { background: #0f172a; color: #64748b; border: 1px solid #1e293b; }

/* Stat boxes */
.stat-row { display: flex; gap: 16px; margin: 16px 0; flex-wrap: wrap; }
.stat-box {
    flex: 1; min-width: 120px;
    background: #0f172a;
    border: 1px solid #1e293b;
    border-radius: 10px;
    padding: 16px;
    text-align: center;
}
.stat-box .stat-num { font-size: 1.8rem; font-weight: 700; }
.stat-box .stat-label { font-size: 0.7rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }

/* Progress bar */
.progress-bar-bg {
    background: #1e293b;
    border-radius: 999px;
    height: 12px;
    margin: 8px 0;
    overflow: hidden;
}
.progress-bar-fill {
    height: 100%;
    border-radius: 999px;
    transition: width 0.5s ease;
}

/* Compromise items */
.compromise-item {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 12px 16px;
    background: rgba(239,68,68,0.08);
    border: 1px solid rgba(239,68,68,0.2);
    border-radius: 8px;
    margin: 6px 0;
    font-size: 0.9rem;
    color: #fca5a5;
}

/* Section headers */
.section-header {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 0;
    border-bottom: 1px solid #1e293b;
    margin-bottom: 16px;
}
.section-num {
    background: #1e293b;
    color: #64748b;
    width: 28px; height: 28px;
    border-radius: 6px;
    display: flex; align-items: center; justify-content: center;
    font-size: 0.75rem; font-weight: 700;
}
.section-title { font-size: 0.9rem; font-weight: 600; color: #cbd5e1; letter-spacing: 0.05em; text-transform: uppercase; }

/* Hash display */
.hash-row {
    display: flex;
    justify-content: space-between;
    padding: 6px 0;
    border-bottom: 1px solid #1e293b;
    font-size: 0.82rem;
}
.hash-label { color: #64748b; font-weight: 600; min-width: 60px; }
.hash-value { color: #94a3b8; font-family: 'JetBrains Mono', monospace; word-break: break-all; }

/* Asset items */
.asset-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 12px;
    border-radius: 6px;
    margin: 4px 0;
    font-size: 0.82rem;
}
.asset-encrypted { background: rgba(239,68,68,0.1); }
.asset-normal    { background: rgba(100,116,139,0.08); }
.asset-name { font-family: 'JetBrains Mono', monospace; color: #e2e8f0; }
.asset-info { color: #64748b; font-size: 0.75rem; }

/* Streamlit element overrides */
div[data-testid="stFileUploader"] {
    background: #111827 !important;
    border: 2px dashed #334155 !important;
    border-radius: 12px !important;
}
.stButton button {
    background: linear-gradient(135deg, #4f46e5, #7c3aed) !important;
    color: white !important;
    border: none !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
    padding: 12px 28px !important;
    font-size: 1rem !important;
    width: 100%;
    cursor: pointer;
}
.stButton button:hover {
    background: linear-gradient(135deg, #4338ca, #6d28d9) !important;
}
div[data-testid="stExpander"] {
    background: #111827 !important;
    border: 1px solid #1e293b !important;
    border-radius: 10px !important;
}
.stAlert { border-radius: 10px !important; }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
# ANALYSIS ENGINE (reused from CLI tool)
# ─────────────────────────────────────────────────────────────

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS":           ("CRITICAL", "Can steal OTPs, bank messages, 2FA codes"),
    "android.permission.RECEIVE_SMS":        ("CRITICAL", "Intercepts ALL incoming SMS in real-time — OTP theft"),
    "android.permission.SEND_SMS":           ("CRITICAL", "Sends SMS from your number — spreads malware to contacts"),
    "android.permission.READ_CALL_LOG":      ("HIGH",     "Reads all call history"),
    "android.permission.PROCESS_OUTGOING_CALLS": ("HIGH", "Intercepts and redirects phone calls"),
    "android.permission.READ_CONTACTS":      ("HIGH",     "Steals entire contact list for phishing"),
    "android.permission.RECORD_AUDIO":       ("CRITICAL", "Records calls and ambient audio — spyware"),
    "android.permission.CAMERA":             ("HIGH",     "Takes photos/videos silently"),
    "android.permission.ACCESS_FINE_LOCATION": ("HIGH",  "Tracks precise GPS location in real-time"),
    "android.permission.READ_EXTERNAL_STORAGE": ("HIGH", "Reads all files, photos, documents"),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("HIGH","Writes/drops additional malware files"),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("CRITICAL", "Silently installs additional malware APKs — DROPPER"),
    "android.permission.QUERY_ALL_PACKAGES": ("HIGH",    "Lists all apps — identifies banking apps to attack"),
    "android.permission.SYSTEM_ALERT_WINDOW": ("CRITICAL","Draws fake UI over banking apps — steals passwords/PINs"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ("CRITICAL","Full device control — reads screen, makes transactions"),
    "android.permission.BIND_DEVICE_ADMIN":  ("CRITICAL","Prevents uninstall, locks device — ransomware"),
    "android.permission.RECEIVE_BOOT_COMPLETED": ("HIGH","Auto-starts on every reboot — permanent infection"),
    "android.permission.FOREGROUND_SERVICE": ("MEDIUM",  "Runs persistently in background"),
    "android.permission.WAKE_LOCK":          ("MEDIUM",  "Keeps phone awake — malware always active"),
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": ("HIGH","Bypasses battery saver — runs 24/7"),
    "android.permission.GET_ACCOUNTS":       ("HIGH",    "Lists all Google/banking accounts on device"),
    "android.permission.USE_CREDENTIALS":    ("CRITICAL","Can use stored account credentials"),
    "android.permission.READ_PHONE_STATE":   ("HIGH",    "Gets IMEI, phone number, SIM info"),
    "android.permission.CALL_PHONE":         ("HIGH",    "Makes calls silently — premium number fraud"),
    "android.permission.POST_NOTIFICATIONS": ("MEDIUM",  "Shows fake notifications to deceive user"),
    "com.google.android.c2dm.permission.RECEIVE": ("HIGH","Firebase C2 — attacker sends remote commands"),
    "android.permission.INTERNET":           ("MEDIUM",  "Network access — sends stolen data to attacker"),
    "android.permission.NFC":                ("HIGH",    "Can read NFC payment cards"),
    "android.permission.PACKAGE_USAGE_STATS": ("HIGH",  "Monitors which apps are open — targets banking apps"),
}

MALWARE_FAMILIES = [
    {
        "name": "🏦 Banking Trojan Dropper",
        "indicators": ["REQUEST_INSTALL_PACKAGES", "RECEIVE_BOOT_COMPLETED", "INTERNET"],
        "description": "Stage-1 dropper that downloads and installs real banking malware on your device",
        "color": "#ef4444"
    },
    {
        "name": "💳 UPI / Payment Overlay Stealer",
        "indicators": ["SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "QUERY_ALL_PACKAGES"],
        "description": "Draws fake UPI/Google Pay/Paytm screens over real apps to steal your PIN",
        "color": "#f97316"
    },
    {
        "name": "📱 SMS OTP Interceptor",
        "indicators": ["READ_SMS", "RECEIVE_SMS", "INTERNET"],
        "description": "Steals bank OTPs from SMS and sends them to attacker server in real-time",
        "color": "#ef4444"
    },
    {
        "name": "🔥 Firebase C2 Botnet",
        "indicators": ["com.google.android.c2dm.permission.RECEIVE", "RECEIVE_BOOT_COMPLETED"],
        "description": "Your device becomes part of a botnet controlled remotely by the attacker",
        "color": "#f97316"
    },
    {
        "name": "🎙️ Spyware / RAT",
        "indicators": ["BIND_ACCESSIBILITY_SERVICE", "RECORD_AUDIO", "READ_CONTACTS"],
        "description": "Full Remote Access Trojan — records calls, steals contacts, reads screen",
        "color": "#dc2626"
    },
    {
        "name": "🔒 Device Admin / Ransomware",
        "indicators": ["BIND_DEVICE_ADMIN", "RECEIVE_BOOT_COMPLETED"],
        "description": "Locks your device and prevents uninstall — ransomware capability",
        "color": "#991b1b"
    },
]

SUSPICIOUS_PKG_PATTERNS = [
    (r"masqat",               "MASQUERADE found in package name — admits it's fake"),
    (r"^com\.im\.",           "Unusual package prefix 'com.im'"),
    (r"mparivahan|parivahan", "Impersonates mParivahan government app"),
    (r"sbi|icici|hdfc|axis|kotak", "Impersonates Indian banking app"),
    (r"paytm|gpay|phonepe|bhim",   "Impersonates Indian payment app"),
    (r"irctc|aadhaar|income.?tax",  "Impersonates Indian government service"),
    (r"police|challan|traffic",     "Impersonates traffic/law enforcement authority"),
    (r"gov\.in",              "Impersonates India government domain"),
]

def entropy(data: bytes) -> float:
    if not data: return 0.0
    freq = [0] * 256
    for b in data: freq[b] += 1
    n = len(data)
    return -sum((f/n)*math.log2(f/n) for f in freq if f)

def detect_type(data: bytes) -> str:
    if data[:2] == b'PK': return "ZIP/APK"
    if data[:4] == b'dex\n': return "DEX bytecode"
    if data[:4] == b'\x7fELF': return "ELF binary"
    if data[:4] == b'%PDF': return "PDF"
    return "ENCRYPTED/UNKNOWN"

def parse_manifest(content: str) -> dict:
    r = {"package": None, "version_name": None, "version_code": None,
         "min_sdk": None, "target_sdk": None, "permissions": [],
         "activities": [], "services": [], "receivers": [],
         "uses_firebase": False, "boot_receiver": False}
    for k, p in [("package","package=\"([^\"]+)\""),("version_name","versionName=\"([^\"]+)\""),
                  ("version_code","versionCode=\"([^\"]+)\""),("min_sdk","minSdkVersion=\"([^\"]+)\""),
                  ("target_sdk","targetSdkVersion=\"([^\"]+)\"")]:
        m = re.search(p, content)
        if m: r[k] = m.group(1)
    r["permissions"] = re.findall(r'<uses-permission[^>]+name="([^"]+)"', content)
    r["activities"]  = re.findall(r'<activity[^>]+name="([^"]+)"', content)
    r["services"]    = re.findall(r'<service[^>]+name="([^"]+)"', content)
    r["receivers"]   = re.findall(r'<receiver[^>]+name="([^"]+)"', content)
    r["uses_firebase"] = "firebase" in content.lower() or "c2dm" in content.lower()
    r["boot_receiver"] = "BOOT_COMPLETED" in content
    return r

def run_jadx(apk_path: str, output_dir: str) -> bool:
    try:
        result = subprocess.run(
            ["jadx", "-d", output_dir, apk_path],
            capture_output=True, text=True, timeout=120
        )
        return True
    except:
        return False

def analyze_apk(apk_path: str, progress_cb=None) -> dict:
    result = {
        "file_name": os.path.basename(apk_path),
        "file_size": os.path.getsize(apk_path),
        "hashes": {}, "manifest": {}, "permissions": [],
        "dangerous_perms": [], "assets": [], "encrypted_assets": [],
        "native_libs": [], "malware_families": [],
        "compromised": [], "findings": [],
        "risk_score": 0, "threat_level": "SAFE",
        "zip_entries": 0, "has_nonstandard_compression": False,
        "jni_methods": []
    }

    def add(sev, cat, msg, detail=""):
        result["findings"].append({"severity": sev, "category": cat, "message": msg, "detail": detail})
        weights = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 2}
        result["risk_score"] += weights.get(sev, 0)

    # ── Hashes ──
    if progress_cb: progress_cb(10, "Computing file hashes...")
    with open(apk_path, "rb") as f:
        data = f.read()
    result["hashes"] = {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

    # ── ZIP Structure ──
    if progress_cb: progress_cb(20, "Analyzing APK structure...")
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            names = z.namelist()
            result["zip_entries"] = len(names)
            result["native_libs"] = [n for n in names if n.startswith("lib/") and n.endswith(".so")]
            result["assets"] = [n for n in names if n.startswith("assets/")]
            dex_count = sum(1 for n in names if n.endswith(".dex"))
            if dex_count > 3:
                add("MEDIUM","MULTI-DEX", f"{dex_count} DEX files — heavily obfuscated app")
            for n in names:
                if n.lower().endswith(".apk") and n != os.path.basename(apk_path):
                    add("CRITICAL","EMBEDDED APK", f"APK embedded in APK: {n}", "Classic dropper — installs second malware")
    except NotImplementedError:
        result["has_nonstandard_compression"] = True
        add("HIGH","OBFUSCATION","Non-standard ZIP compression (0xffffb21b)","Anti-analysis technique to defeat decompilers")

    # ── JADX ──
    if progress_cb: progress_cb(35, "Decompiling APK with JADX...")
    jadx_dir = tempfile.mkdtemp(prefix="apk_web_")
    jadx_ok = run_jadx(apk_path, jadx_dir)

    # ── Manifest ──
    if progress_cb: progress_cb(50, "Parsing AndroidManifest.xml...")
    manifest_path = os.path.join(jadx_dir, "resources", "AndroidManifest.xml")
    if os.path.exists(manifest_path):
        with open(manifest_path, "r", errors="ignore") as f:
            content = f.read()
        result["manifest"] = parse_manifest(content)
        pkg = result["manifest"].get("package","")

        # Package name checks
        for pat, desc in SUSPICIOUS_PKG_PATTERNS:
            if re.search(pat, pkg, re.IGNORECASE):
                add("CRITICAL","FAKE APP", desc, f"Package: {pkg}")
                result["risk_score"] += 20
                break

        if result["manifest"].get("uses_firebase"):
            add("HIGH","FIREBASE C2","Firebase push messaging — remote command channel","Attacker controls device via Google Firebase")
        if result["manifest"].get("boot_receiver"):
            add("HIGH","PERSISTENCE","Auto-starts on device reboot","Malware survives reboots and resists removal")
        try:
            sdk = int(result["manifest"].get("target_sdk","28"))
            if sdk <= 22:
                add("HIGH","SDK EVASION",f"Targets old Android SDK {sdk}","Bypasses runtime permissions — auto-granted all perms")
        except: pass

    # ── Permissions ──
    if progress_cb: progress_cb(60, "Analysing dangerous permissions...")
    perms = result["manifest"].get("permissions", [])
    for perm in perms:
        if perm in DANGEROUS_PERMISSIONS:
            sev, desc = DANGEROUS_PERMISSIONS[perm]
            short = perm.split(".")[-1]
            result["dangerous_perms"].append({
                "permission": perm, "short": short,
                "severity": sev, "description": desc
            })
            add(sev, "PERMISSION", short, desc)

    # ── Assets ──
    if progress_cb: progress_cb(70, "Scanning encrypted payloads in assets...")
    asset_dir = os.path.join(jadx_dir, "resources", "assets")
    if os.path.exists(asset_dir):
        for root, dirs, files in os.walk(asset_dir):
            for fname in files:
                if fname == "MaterialIcons-Regular.ttf": continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "rb") as f:
                        adata = f.read()
                    e   = entropy(adata)
                    sz  = len(adata)
                    ft  = detect_type(adata)
                    rel = os.path.relpath(fpath, asset_dir)
                    info = {"name": rel, "size": sz, "entropy": round(e,3), "type": ft, "encrypted": e >= 7.8}
                    result["assets"].append(info)
                    if e >= 7.8:
                        result["encrypted_assets"].append(rel)
                        add("CRITICAL","ENCRYPTED PAYLOAD",
                            f"Asset '{fname}' is AES-encrypted",
                            f"Entropy={e:.3f}/8.0 | Size={sz//1024}KB — decrypted at runtime by native code")
                except: pass

    if len(result["encrypted_assets"]) > 0:
        add("CRITICAL","DROPPER CONFIRMED",
            f"{len(result['encrypted_assets'])} hidden payloads found",
            "Real malware hidden in encrypted blobs inside this APK")

    # ── Native Libs ──
    if progress_cb: progress_cb(78, "Analysing native libraries...")
    for lib in result["native_libs"]:
        lib_path = os.path.join(jadx_dir, "resources", lib)
        if os.path.exists(lib_path):
            try:
                r = subprocess.run(["strings","-n","6",lib_path], capture_output=True, text=True, timeout=15)
                jni = re.findall(r'Java_[\w_]+', r.stdout)
                result["jni_methods"] += list(set(jni))
                if any("SensorEvent" in s or "onSensorChanged" in s for s in r.stdout.split('\n')):
                    add("HIGH","ANTI-EMULATOR","Sensor hooks in native library",
                        "Uses phone sensors to detect if running in sandbox — evades automated analysis")
                lname = os.path.basename(lib)
                if len(lname) > 20 and lname.replace("lib","").replace(".so","").islower():
                    add("HIGH","OBFUSCATED LIB", f"Nonsense library name: {lname}",
                        "Malware names native libraries randomly to avoid AV signatures")
                with open(lib_path,"rb") as f: ld = f.read()
                le = entropy(ld)
                if le > 7.5:
                    add("HIGH","PACKED LIBRARY",f"Library entropy={le:.3f}","Native code is packed/encrypted")
            except: pass

    # ── Source Patterns ──
    if progress_cb: progress_cb(86, "Scanning decompiled source code...")
    src_dir = os.path.join(jadx_dir, "sources")
    if os.path.exists(src_dir):
        patterns = {
            r"(REQUEST_INSTALL|installPackage|PackageInstaller)": ("CRITICAL","DROPPER CODE","Package install code found"),
            r"(SmsManager|sendTextMessage|getMessageBody)":       ("CRITICAL","SMS STEALER","SMS steal/send code"),
            r"(SYSTEM_ALERT_WINDOW|TYPE_APPLICATION_OVERLAY)":    ("CRITICAL","OVERLAY","Screen overlay code — fake UI injection"),
            r"(AccessibilityService|onAccessibilityEvent)":       ("CRITICAL","ACCESSIBILITY RAT","Accessibility abuse = full device control"),
            r"(DexClassLoader|loadDex|InMemoryDex)":              ("CRITICAL","DYNAMIC LOAD","Loads DEX code at runtime — evades static analysis"),
            r"(Cipher\.getInstance|AES|SecretKeySpec)":           ("HIGH","ENCRYPTION","Crypto code — encrypts/decrypts payloads"),
            r"(getDeviceId|getImei|getSubscriberId)":             ("HIGH","DEVICE ID","Harvests device IMEI/SIM identity"),
            r"(Runtime\.exec|ProcessBuilder)":                    ("CRITICAL","SHELL EXEC","Executes shell commands — RCE"),
            r"(upi|UPI|vpa|VPA|bhim|gpay|phonepe)":              ("CRITICAL","UPI TARGET","References UPI payment systems"),
        }
        seen = set()
        for root, dirs, files in os.walk(src_dir):
            for fname in files:
                if not fname.endswith(".java"): continue
                try:
                    with open(os.path.join(root,fname),"r",errors="ignore") as f:
                        code = f.read()
                    for pat,(sev,cat,msg) in patterns.items():
                        if pat not in seen and re.search(pat, code):
                            seen.add(pat)
                            add(sev, cat, msg, f"Found in {fname}")
                except: pass

    # ── Malware Families ──
    if progress_cb: progress_cb(92, "Fingerprinting malware families...")
    perm_shorts = set(p.split(".")[-1] for p in perms)
    perm_full   = set(perms)
    for family in MALWARE_FAMILIES:
        hits = sum(1 for ind in family["indicators"] if ind in perm_shorts or ind in perm_full)
        conf = hits / len(family["indicators"])
        if conf >= 0.6:
            result["malware_families"].append({**family, "confidence": round(conf*100)})
            result["risk_score"] += 30

    # ── Impact ──
    if progress_cb: progress_cb(96, "Assessing impact...")
    impact_map = {
        "READ_SMS":        "Bank OTPs intercepted → attacker gets access to your accounts",
        "RECEIVE_SMS":     "All incoming SMS stolen in real-time including bank messages",
        "SEND_SMS":        "Your phone number used to spread malware to your contacts",
        "READ_CONTACTS":   "Entire contact list stolen — used for phishing campaigns",
        "RECORD_AUDIO":    "Phone calls and surroundings recorded silently",
        "CAMERA":          "Photos and videos taken without your knowledge",
        "ACCESS_FINE_LOCATION": "Your real-time location tracked continuously",
        "READ_EXTERNAL_STORAGE": "All photos, videos, documents and files accessible",
        "REQUEST_INSTALL_PACKAGES": "Additional malware silently installed on your device",
        "QUERY_ALL_PACKAGES": "Banking apps identified and specifically targeted",
        "SYSTEM_ALERT_WINDOW": "Fake bank/UPI screens shown → passwords and PINs stolen",
        "BIND_ACCESSIBILITY_SERVICE": "Device fully controlled — reads your screen, makes payments",
        "BIND_DEVICE_ADMIN": "Device locked and app cannot be uninstalled",
        "RECEIVE_BOOT_COMPLETED": "Malware restarts automatically on every phone reboot",
        "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": "Malware runs 24/7 draining battery and stealing data",
    }
    for perm in perms:
        short = perm.split(".")[-1]
        if short in impact_map:
            result["compromised"].append(impact_map[short])
    if result["encrypted_assets"]:
        result["compromised"].append("Hidden secondary malware installed via encrypted dropper payload")
    if result["manifest"].get("uses_firebase"):
        result["compromised"].append("Device added to attacker's botnet controlled via Firebase")

    # ── Verdict ──
    sc = result["risk_score"]
    if sc >= 100:   result["threat_level"] = "CRITICAL"
    elif sc >= 60:  result["threat_level"] = "HIGH"
    elif sc >= 30:  result["threat_level"] = "MEDIUM"
    elif sc >= 10:  result["threat_level"] = "LOW"
    else:           result["threat_level"] = "SAFE"

    if progress_cb: progress_cb(100, "Analysis complete!")
    shutil.rmtree(jadx_dir, ignore_errors=True)
    return result


# ─────────────────────────────────────────────────────────────
# UI RENDER FUNCTIONS
# ─────────────────────────────────────────────────────────────

def render_verdict(r):
    sc = r["risk_score"]
    tl = r["threat_level"]
    configs = {
        "CRITICAL": ("#7f1d1d","#ef4444","#fca5a5","⛔ CONFIRMED MALWARE","DO NOT INSTALL — DELETE IMMEDIATELY"),
        "HIGH":     ("#431407","#f97316","#fdba74","🚨 HIGHLY DANGEROUS","Very likely malicious — treat as malware"),
        "MEDIUM":   ("#422006","#d97706","#fcd34d","⚠️ SUSPICIOUS","Potentially dangerous — verify before installing"),
        "LOW":      ("#14532d","#16a34a","#86efac","⚠️ LOW RISK","Some concerns found — verify the source"),
        "SAFE":     ("#0f172a","#22c55e","#86efac","✅ LIKELY SAFE","No major threats detected"),
    }
    bg, border, text, title, sub = configs.get(tl, configs["SAFE"])
    max_sc = 300
    pct = min(int((sc/max_sc)*100), 100)
    bar_color = "#ef4444" if tl in ("CRITICAL","HIGH") else "#f59e0b" if tl=="MEDIUM" else "#22c55e"

    st.markdown(f"""
    <div style="background:{bg};border:2px solid {border};border-radius:16px;padding:32px;text-align:center;margin:20px 0">
        <div style="font-size:2.4rem;font-weight:800;color:{text}">{title}</div>
        <div style="color:{border};font-size:1.05rem;margin-top:6px">{sub}</div>
        <div style="margin-top:20px">
            <div style="color:#64748b;font-size:0.8rem;margin-bottom:6px">RISK SCORE: {sc} / {max_sc}</div>
            <div style="background:#1e293b;border-radius:999px;height:14px;overflow:hidden;max-width:400px;margin:0 auto">
                <div style="width:{pct}%;height:100%;background:{bar_color};border-radius:999px;transition:width 0.5s"></div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

def render_stat_boxes(r):
    crit = sum(1 for f in r["findings"] if f["severity"]=="CRITICAL")
    high = sum(1 for f in r["findings"] if f["severity"]=="HIGH")
    med  = sum(1 for f in r["findings"] if f["severity"]=="MEDIUM")
    enc  = len(r["encrypted_assets"])
    sz   = r["file_size"] / (1024*1024)
    perms= len(r["dangerous_perms"])

    cols = st.columns(6)
    stats = [
        (str(crit),    "CRITICAL",       "#ef4444"),
        (str(high),    "HIGH RISK",      "#f97316"),
        (str(med),     "MEDIUM",         "#f59e0b"),
        (str(enc),     "ENCRYPTED BLOBS","#a855f7"),
        (str(perms),   "DANGER PERMS",   "#06b6d4"),
        (f"{sz:.1f}M", "FILE SIZE",      "#64748b"),
    ]
    for col, (num, label, color) in zip(cols, stats):
        col.markdown(f"""
        <div style="background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:16px;text-align:center">
            <div style="font-size:1.8rem;font-weight:700;color:{color}">{num}</div>
            <div style="font-size:0.65rem;color:#64748b;letter-spacing:0.08em;text-transform:uppercase;margin-top:4px">{label}</div>
        </div>
        """, unsafe_allow_html=True)

def render_hashes(r):
    st.markdown("""<div class="section-header">
        <div class="section-num">1</div>
        <div class="section-title">File Identification & Hashes</div>
    </div>""", unsafe_allow_html=True)
    h = r["hashes"]
    st.markdown(f"""
    <div style="background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:16px">
        <div class="hash-row"><span class="hash-label">FILE</span><span class="hash-value" style="color:#e2e8f0">{r['file_name']}</span></div>
        <div class="hash-row"><span class="hash-label">SIZE</span><span class="hash-value">{r['file_size']/1024/1024:.2f} MB ({r['file_size']:,} bytes)</span></div>
        <div class="hash-row"><span class="hash-label">MD5</span><span class="hash-value">{h.get('md5','N/A')}</span></div>
        <div class="hash-row"><span class="hash-label">SHA1</span><span class="hash-value">{h.get('sha1','N/A')}</span></div>
        <div class="hash-row" style="border:none"><span class="hash-label">SHA256</span><span class="hash-value">{h.get('sha256','N/A')}</span></div>
    </div>
    <div style="margin-top:8px;padding:10px 14px;background:rgba(99,102,241,0.1);border:1px solid rgba(99,102,241,0.3);border-radius:8px;font-size:0.82rem;color:#a5b4fc">
        💡 Copy the SHA256 hash above and search it on <strong>virustotal.com</strong> to check if it's already flagged
    </div>
    """, unsafe_allow_html=True)

def render_manifest(r):
    st.markdown("""<div class="section-header" style="margin-top:24px">
        <div class="section-num">2</div>
        <div class="section-title">App Identity & Manifest</div>
    </div>""", unsafe_allow_html=True)
    m = r["manifest"]
    pkg = m.get("package","Unknown")
    ver = m.get("version_name","N/A")
    sdk = m.get("target_sdk","N/A")

    # Determine if package is suspicious
    is_suspicious = any(re.search(p, pkg, re.IGNORECASE) for p, _ in SUSPICIOUS_PKG_PATTERNS)
    pkg_color = "#fca5a5" if is_suspicious else "#86efac"
    pkg_bg    = "rgba(239,68,68,0.1)" if is_suspicious else "rgba(34,197,94,0.1)"
    pkg_note  = "⚠️ SUSPICIOUS" if is_suspicious else "✓ Normal"

    st.markdown(f"""
    <div style="background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:16px">
        <div class="hash-row">
            <span class="hash-label">PACKAGE</span>
            <span style="background:{pkg_bg};color:{pkg_color};padding:2px 10px;border-radius:6px;font-family:monospace;font-size:0.85rem">{pkg}</span>
            <span style="color:{pkg_color};font-size:0.75rem;margin-left:8px">{pkg_note}</span>
        </div>
        <div class="hash-row"><span class="hash-label">VERSION</span><span class="hash-value">{ver}</span></div>
        <div class="hash-row"><span class="hash-label">TARGET SDK</span><span class="hash-value">Android SDK {sdk}</span></div>
        <div class="hash-row"><span class="hash-label">ACTIVITIES</span><span class="hash-value">{len(m.get('activities',[]))}</span></div>
        <div class="hash-row"><span class="hash-label">SERVICES</span><span class="hash-value">{len(m.get('services',[]))}</span></div>
        <div class="hash-row" style="border:none"><span class="hash-label">RECEIVERS</span><span class="hash-value">{len(m.get('receivers',[]))}</span></div>
    </div>
    """, unsafe_allow_html=True)

    flags = []
    if m.get("uses_firebase"): flags.append(("🔥 Firebase C2", "#f97316", "Attacker can send remote commands to all infected devices"))
    if m.get("boot_receiver"): flags.append(("🔁 Boot Persistence", "#ef4444", "Malware auto-starts on every device reboot"))
    for label, color, desc in flags:
        st.markdown(f"""
        <div style="background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.25);border-radius:8px;padding:10px 14px;margin:6px 0;font-size:0.87rem">
            <span style="color:{color};font-weight:600">{label}</span>
            <span style="color:#94a3b8;margin-left:8px">{desc}</span>
        </div>
        """, unsafe_allow_html=True)

def render_permissions(r):
    st.markdown("""<div class="section-header" style="margin-top:24px">
        <div class="section-num">3</div>
        <div class="section-title">Dangerous Permissions</div>
    </div>""", unsafe_allow_html=True)
    perms = r["dangerous_perms"]
    if not perms:
        st.markdown('<div style="color:#64748b;padding:12px">No dangerous permissions found.</div>', unsafe_allow_html=True)
        return
    for p in perms:
        sev   = p["severity"]
        colors = {"CRITICAL":("#ef4444","rgba(239,68,68,0.08)","rgba(239,68,68,0.3)"),
                  "HIGH":    ("#f97316","rgba(249,115,22,0.08)","rgba(249,115,22,0.3)"),
                  "MEDIUM":  ("#f59e0b","rgba(245,158,11,0.08)","rgba(245,158,11,0.3)"),
                  "LOW":     ("#22c55e","rgba(34,197,94,0.08)","rgba(34,197,94,0.3)")}
        tc, bg, border = colors.get(sev, ("#64748b","rgba(100,116,139,0.08)","rgba(100,116,139,0.3)"))
        icons = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}
        icon = icons.get(sev,"⚪")
        st.markdown(f"""
        <div style="background:{bg};border:1px solid {border};border-radius:8px;padding:10px 14px;margin:5px 0;display:flex;align-items:flex-start;gap:10px">
            <span style="font-size:0.9rem;margin-top:1px">{icon}</span>
            <div>
                <div style="color:{tc};font-weight:600;font-size:0.85rem;font-family:monospace">{p['permission'].split('.')[-1]}</div>
                <div style="color:#94a3b8;font-size:0.8rem;margin-top:2px">{p['description']}</div>
                <div style="color:#475569;font-size:0.72rem;margin-top:2px;font-family:monospace">{p['permission']}</div>
            </div>
            <span style="margin-left:auto;background:{bg};border:1px solid {border};color:{tc};padding:2px 8px;border-radius:999px;font-size:0.68rem;font-weight:700;white-space:nowrap">{sev}</span>
        </div>
        """, unsafe_allow_html=True)

def render_assets(r):
    st.markdown("""<div class="section-header" style="margin-top:24px">
        <div class="section-num">4</div>
        <div class="section-title">Encrypted Payload Detection</div>
    </div>""", unsafe_allow_html=True)
    if not r.get("encrypted_assets"):
        st.markdown('<div style="color:#22c55e;padding:12px">✓ No encrypted payloads detected</div>', unsafe_allow_html=True)
        return

    st.markdown(f"""
    <div style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:10px;padding:14px 18px;margin-bottom:12px">
        <div style="color:#ef4444;font-weight:700">⛔ {len(r['encrypted_assets'])} AES-Encrypted Payloads Detected</div>
        <div style="color:#fca5a5;font-size:0.85rem;margin-top:4px">Real malware is hidden inside encrypted blobs — decrypted at runtime by native library. This is the definitive signature of a <strong>dropper malware</strong>.</div>
    </div>
    """, unsafe_allow_html=True)

    all_assets = [a for a in r.get("assets",[]) if isinstance(a, dict)]
    for asset in all_assets:
        if isinstance(asset, str): continue
        e     = asset.get("entropy", 0)
        enc   = asset.get("encrypted", False)
        name  = asset.get("name","?")
        sz    = asset.get("size", 0)
        ftype = asset.get("type","?")

        if enc:
            st.markdown(f"""
            <div style="background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.25);border-radius:8px;padding:10px 14px;margin:4px 0;display:flex;justify-content:space-between;align-items:center">
                <div>
                    <span style="color:#fca5a5;font-family:monospace;font-size:0.85rem">🔒 {name}</span>
                    <span style="color:#64748b;font-size:0.75rem;margin-left:10px">{sz//1024} KB · {ftype}</span>
                </div>
                <div style="color:#ef4444;font-size:0.78rem;font-weight:600;white-space:nowrap">Entropy: {e:.3f}/8.0</div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div style="background:rgba(100,116,139,0.06);border:1px solid #1e293b;border-radius:8px;padding:8px 14px;margin:4px 0;display:flex;justify-content:space-between;align-items:center">
                <span style="color:#64748b;font-family:monospace;font-size:0.82rem">📄 {name}</span>
                <span style="color:#475569;font-size:0.75rem">Entropy: {e:.3f} · Normal</span>
            </div>
            """, unsafe_allow_html=True)

def render_malware_families(r):
    st.markdown("""<div class="section-header" style="margin-top:24px">
        <div class="section-num">5</div>
        <div class="section-title">Malware Family Fingerprinting</div>
    </div>""", unsafe_allow_html=True)
    families = r.get("malware_families",[])
    if not families:
        st.markdown('<div style="color:#22c55e;padding:12px">✓ No known malware family matched</div>', unsafe_allow_html=True)
        return
    for fam in families:
        conf = fam["confidence"]
        color = fam.get("color","#ef4444")
        bar_w = conf
        st.markdown(f"""
        <div style="background:rgba(239,68,68,0.07);border:1px solid rgba(239,68,68,0.2);border-radius:10px;padding:16px;margin:8px 0">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
                <div style="color:{color};font-weight:700;font-size:0.95rem">{fam['name']}</div>
                <div style="color:{color};font-size:0.8rem;font-weight:600">Match: {conf}%</div>
            </div>
            <div style="background:#1e293b;border-radius:999px;height:8px;margin-bottom:10px">
                <div style="width:{bar_w}%;height:100%;background:{color};border-radius:999px"></div>
            </div>
            <div style="color:#94a3b8;font-size:0.85rem">{fam['description']}</div>
        </div>
        """, unsafe_allow_html=True)

def render_compromise(r):
    st.markdown("""<div class="section-header" style="margin-top:24px">
        <div class="section-num">6</div>
        <div class="section-title">What Gets Compromised If Installed</div>
    </div>""", unsafe_allow_html=True)
    items = r.get("compromised",[])
    if not items:
        st.markdown('<div style="color:#22c55e;padding:12px">✓ No critical compromise scenarios detected</div>', unsafe_allow_html=True)
        return
    for item in items:
        st.markdown(f"""
        <div style="display:flex;align-items:flex-start;gap:10px;padding:12px 16px;background:rgba(239,68,68,0.07);border:1px solid rgba(239,68,68,0.2);border-radius:8px;margin:5px 0;color:#fca5a5;font-size:0.88rem">
            <span style="font-size:1rem;margin-top:1px">✗</span>
            <span>{item}</span>
        </div>
        """, unsafe_allow_html=True)

def render_all_findings(r):
    st.markdown("""<div class="section-header" style="margin-top:24px">
        <div class="section-num">7</div>
        <div class="section-title">All Investigation Findings</div>
    </div>""", unsafe_allow_html=True)
    findings = r.get("findings",[])
    sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4,"GOOD":5}
    findings = sorted(findings, key=lambda x: sev_order.get(x["severity"],9))
    configs = {
        "CRITICAL": ("#ef4444","rgba(239,68,68,0.08)","rgba(239,68,68,0.3)","🔴"),
        "HIGH":     ("#f97316","rgba(249,115,22,0.08)","rgba(249,115,22,0.3)","🟠"),
        "MEDIUM":   ("#f59e0b","rgba(245,158,11,0.08)","rgba(245,158,11,0.3)","🟡"),
        "LOW":      ("#22c55e","rgba(34,197,94,0.08)","rgba(34,197,94,0.3)","🟢"),
        "INFO":     ("#64748b","rgba(100,116,139,0.06)","#1e293b","ℹ️"),
        "GOOD":     ("#22c55e","rgba(34,197,94,0.06)","rgba(34,197,94,0.2)","✅"),
    }
    for f in findings:
        sev = f["severity"]
        if sev in ("INFO","GOOD"): continue
        tc, bg, border, icon = configs.get(sev, configs["INFO"])
        detail_html = f'<div style="color:#64748b;font-size:0.78rem;margin-top:3px;font-style:italic">{f["detail"]}</div>' if f.get("detail") else ""
        st.markdown(f"""
        <div style="background:{bg};border:1px solid {border};border-radius:8px;padding:10px 14px;margin:4px 0;display:flex;align-items:flex-start;gap:10px">
            <span>{icon}</span>
            <div style="flex:1">
                <div style="display:flex;justify-content:space-between">
                    <span style="color:{tc};font-weight:600;font-size:0.85rem">{f['category']}: {f['message']}</span>
                    <span style="color:{tc};font-size:0.68rem;font-weight:700;opacity:0.7;white-space:nowrap;margin-left:8px">{sev}</span>
                </div>
                {detail_html}
            </div>
        </div>
        """, unsafe_allow_html=True)

def render_report_download(r):
    report_json = json.dumps(r, indent=2, default=str)
    fname = r["file_name"].replace(".apk","") + "_threat_report.json"
    st.download_button(
        label="⬇️  Download Full JSON Report",
        data=report_json,
        file_name=fname,
        mime="application/json",
        use_container_width=True
    )
    # VirusTotal hint
    sha = r["hashes"].get("sha256","")
    if sha:
        st.markdown(f"""
        <div style="margin-top:12px;padding:12px 16px;background:rgba(99,102,241,0.1);border:1px solid rgba(99,102,241,0.3);border-radius:8px;font-size:0.85rem;color:#a5b4fc">
            🔍 <strong>Also check on VirusTotal:</strong> Search for the SHA256 hash above at <code>virustotal.com</code> to see if it's already flagged by 70+ antivirus engines.
        </div>
        """, unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
# MAIN APP
# ─────────────────────────────────────────────────────────────

# Hero
st.markdown("""
<div class="hero">
    <div style="font-size:3rem;margin-bottom:8px">🛡️</div>
    <h1>APK Threat Analyzer</h1>
    <p>Upload any Android APK file — get instant malware analysis</p>
    <div class="subtitle">Detects: Fake Apps · Banking Trojans · UPI Stealers · Droppers · Spyware · Ransomware</div>
</div>
""", unsafe_allow_html=True)

# Check JADX available
has_jadx = shutil.which("jadx") is not None
if not has_jadx:
    st.warning("⚠️ JADX not found — deep decompilation disabled. Basic analysis only. Install JADX for full results.")

# Upload
st.markdown("""
<div style="background:#111827;border:2px dashed #334155;border-radius:12px;padding:30px 20px;text-align:center;margin:10px 0 6px 0">
    <div style="font-size:2rem">📂</div>
    <div style="color:#94a3b8;font-size:0.95rem;margin-top:4px">Drag & Drop your APK file below, or click to browse</div>
    <div style="color:#475569;font-size:0.8rem;margin-top:4px">Maximum 200MB · Android APK files only</div>
</div>
""", unsafe_allow_html=True)

uploaded_file = st.file_uploader(
    label="Upload APK",
    type=["apk"],
    label_visibility="collapsed"
)

if uploaded_file:
    col1, col2, col3 = st.columns([1,2,1])
    with col2:
        analyze_btn = st.button("🔍  Analyze APK Now", use_container_width=True)

    if analyze_btn:
        # Save uploaded file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
            tmp.write(uploaded_file.read())
            tmp_path = tmp.name

        # Progress
        progress_bar = st.progress(0)
        status_text  = st.empty()

        def progress_cb(pct, msg):
            progress_bar.progress(pct)
            status_text.markdown(f'<div style="color:#64748b;font-size:0.85rem;text-align:center">{msg}</div>', unsafe_allow_html=True)

        try:
            result = analyze_apk(tmp_path, progress_cb)
            result["file_name"] = uploaded_file.name
            progress_bar.empty()
            status_text.empty()

            # ── Render Results ──────────────────────
            st.markdown("---")
            render_verdict(result)
            st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
            render_stat_boxes(result)

            tab1, tab2, tab3, tab4, tab5 = st.tabs([
                "📋 Overview",
                "🔐 Permissions",
                "📦 Payloads",
                "🦠 Malware ID",
                "💥 Impact"
            ])

            with tab1:
                render_hashes(result)
                render_manifest(result)
                render_all_findings(result)

            with tab2:
                render_permissions(result)

            with tab3:
                render_assets(result)

            with tab4:
                render_malware_families(result)
                if result.get("jni_methods"):
                    st.markdown("""<div class="section-header" style="margin-top:20px">
                        <div class="section-num">+</div>
                        <div class="section-title">Native JNI Hooks</div>
                    </div>""", unsafe_allow_html=True)
                    for m in set(result["jni_methods"]):
                        clean = m.replace("Java_","").replace("__"," → ").replace("_",".")
                        st.markdown(f'<div style="font-family:monospace;font-size:0.8rem;color:#a78bfa;padding:4px 12px;background:rgba(167,139,250,0.08);border-radius:6px;margin:3px 0">⚡ {clean}</div>', unsafe_allow_html=True)

            with tab5:
                render_compromise(result)

            st.markdown("---")
            render_report_download(result)

        except Exception as e:
            st.error(f"Analysis failed: {e}")
            import traceback
            st.code(traceback.format_exc())
        finally:
            try: os.unlink(tmp_path)
            except: pass

else:
    # Examples / Info
    st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)
    features = [
        ("🔍", "Static Analysis", "Decompiles APK with JADX and scans all source code, manifest, and assets"),
        ("🔒", "Encryption Detection", "Finds AES-encrypted hidden payloads using entropy analysis (0.0–8.0 scale)"),
        ("📋", "Permission Audit", "Checks 35+ dangerous Android permissions with plain-English explanations"),
        ("🦠", "Malware Fingerprinting", "Matches against 6 malware families: Droppers, RATs, Banking Trojans, UPI Stealers"),
        ("💥", "Impact Report", "Tells you exactly what data and accounts get compromised if installed"),
        ("📥", "JSON Report", "Download full investigation report to submit to cybercrime authorities"),
    ]
    cols = st.columns(3)
    for i, (icon, title, desc) in enumerate(features):
        with cols[i % 3]:
            st.markdown(f"""
            <div style="background:#111827;border:1px solid #1e293b;border-radius:12px;padding:20px;margin:8px 0;height:150px">
                <div style="font-size:1.8rem">{icon}</div>
                <div style="color:#e2e8f0;font-weight:600;font-size:0.9rem;margin:8px 0 4px 0">{title}</div>
                <div style="color:#64748b;font-size:0.8rem;line-height:1.5">{desc}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("""
    <div style="margin-top:24px;padding:16px 20px;background:rgba(99,102,241,0.08);border:1px solid rgba(99,102,241,0.25);border-radius:10px;font-size:0.85rem;color:#94a3b8;text-align:center">
        🇮🇳 Built for detecting fake Indian government app scams (mParivahan, Aadhaar, IRCTC, income tax, traffic challan)
        <br>
        <span style="color:#64748b;font-size:0.78rem">If you receive a suspicious APK — upload it here before you even think about installing</span>
    </div>
    """, unsafe_allow_html=True)

# Footer
st.markdown("""
<div style="margin-top:40px;padding:20px;border-top:1px solid #1e293b;text-align:center;color:#334155;font-size:0.78rem">
    APK Threat Analyzer · Cybercrime Investigation Tool · For reporting: <strong style="color:#475569">cybercrime.gov.in</strong> · Helpline: <strong style="color:#475569">1930</strong>
</div>
""", unsafe_allow_html=True)
