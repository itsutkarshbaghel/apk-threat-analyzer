import streamlit as st
import os, sys, tempfile, hashlib, math, json, re, logging, warnings

# Suppress androguard verbose logging
logging.disable(logging.CRITICAL)
warnings.filterwarnings("ignore")

# ── Page Config ───────────────────────────────────────────────
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
    display: flex; justify-content: space-between; align-items: flex-start;
    padding: 7px 0; border-bottom: 1px solid #1e293b; font-size: 0.83rem;
}
.hash-label { color: #64748b; font-weight: 600; min-width: 80px; flex-shrink: 0; }
.hash-value { color: #94a3b8; font-family: 'JetBrains Mono', monospace;
              word-break: break-all; text-align: right; }
.section-header {
    display: flex; align-items: center; gap: 10px;
    padding: 12px 0; border-bottom: 1px solid #1e293b; margin-bottom: 16px;
}
.section-num {
    background: #1e293b; color: #64748b; width: 28px; height: 28px;
    border-radius: 6px; display: flex; align-items: center; justify-content: center;
    font-size: 0.75rem; font-weight: 700; flex-shrink: 0;
}
.section-title { font-size: 0.88rem; font-weight: 600; color: #cbd5e1;
    letter-spacing: 0.05em; text-transform: uppercase; }
div[data-testid="stFileUploader"] > div {
    background: #111827 !important; border: 2px dashed #334155 !important;
    border-radius: 12px !important;
}
.stButton button {
    background: linear-gradient(135deg, #4f46e5, #7c3aed) !important;
    color: white !important; border: none !important; border-radius: 8px !important;
    font-weight: 600 !important; padding: 12px 28px !important;
    font-size: 1rem !important; width: 100%;
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
        ("CRITICAL", "Sends SMS from your number — spreads malware to contacts"),
    "android.permission.READ_CALL_LOG":
        ("HIGH",     "Reads all call history"),
    "android.permission.PROCESS_OUTGOING_CALLS":
        ("HIGH",     "Intercepts and redirects your phone calls"),
    "android.permission.READ_CONTACTS":
        ("HIGH",     "Steals your entire contact list for phishing"),
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
        ("HIGH",     "Bypasses battery optimization — runs 24/7"),
    "android.permission.GET_ACCOUNTS":
        ("HIGH",     "Lists all Google and banking accounts on your device"),
    "android.permission.USE_CREDENTIALS":
        ("CRITICAL", "Uses your stored account credentials"),
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
        ("HIGH",     "Monitors which apps you open — waits to attack banking apps"),
    "android.permission.ACCESS_NETWORK_STATE":
        ("LOW",      "Checks network connectivity"),
}

MALWARE_FAMILIES = [
    {
        "name":  "🏦 Banking Trojan Dropper",
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
        "description": "Steals bank OTPs from SMS messages and sends them to attacker's server",
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
    (r"masqat",                          "Word 'masqat' (masquerade) found in package name"),
    (r"^com\.im\.",                       "Unusual package prefix 'com.im' — not a real developer namespace"),
    (r"mparivahan|parivahan",             "Impersonates official NIC mParivahan government app"),
    (r"sbi|icici|hdfc|axis|kotak",        "Impersonates Indian banking app"),
    (r"paytm|gpay|phonepe|bhim",          "Impersonates Indian payment app"),
    (r"irctc|aadhaar|income.?tax|epfo",   "Impersonates Indian government service"),
    (r"police|challan|traffic|echallan",  "Impersonates traffic police / law enforcement"),
    (r"gov\.in",                          "Package name spoofs India government domain"),
    (r"\.fake\.|\.clone\.",               "Contains 'fake' or 'clone' in package name"),
]

IMPACT_MAP = {
    "READ_SMS":         "💸 Bank OTPs stolen → attacker logs into your bank accounts",
    "RECEIVE_SMS":      "💸 All incoming SMS intercepted → real-time OTP theft",
    "SEND_SMS":         "📤 Your phone spreads malware SMS to all your contacts",
    "READ_CONTACTS":    "👥 Entire contact list stolen → used for phishing campaigns",
    "RECORD_AUDIO":     "🎙️ Phone calls and conversations recorded without you knowing",
    "CAMERA":           "📸 Photos and videos taken silently",
    "ACCESS_FINE_LOCATION": "📍 Your location tracked 24/7",
    "READ_EXTERNAL_STORAGE": "📁 All photos, documents and private files stolen",
    "REQUEST_INSTALL_PACKAGES": "📲 More malware silently installed on your device",
    "QUERY_ALL_PACKAGES": "🏦 Your banking apps identified and specifically targeted",
    "SYSTEM_ALERT_WINDOW": "🎭 Fake bank/UPI login screens shown → passwords and PINs stolen",
    "BIND_ACCESSIBILITY_SERVICE": "🤖 Device fully controlled — makes payments on your behalf",
    "BIND_DEVICE_ADMIN": "🔒 Device locked, app cannot be uninstalled without factory reset",
    "RECEIVE_BOOT_COMPLETED": "🔄 Malware restarts automatically on every phone reboot",
    "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": "⚡ Malware runs 24/7 — constant data theft",
    "GET_ACCOUNTS":     "🔑 All Google and banking accounts on device enumerated",
    "USE_CREDENTIALS":  "🔑 Your stored account credentials used by attacker",
    "READ_PHONE_STATE": "📱 Your IMEI and phone identity stolen — SIM swap fraud risk",
}

# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

def entropy(data: bytes) -> float:
    if not data: return 0.0
    freq = [0] * 256
    for b in data: freq[b] += 1
    n = len(data)
    return -sum((f/n)*math.log2(f/n) for f in freq if f)

def detect_type(data: bytes) -> str:
    if len(data) < 4: return "UNKNOWN"
    m = data[:4]
    if m[:2] == b'PK':      return "ZIP/APK"
    if m == b'dex\n':       return "DEX bytecode"
    if m == b'\x7fELF':     return "ELF native binary"
    if m[:4] == b'%PDF':    return "PDF"
    if m[:2] == b'MZ':      return "Windows EXE"
    if m[:2] == b'\x1f\x8b':return "GZIP archive"
    return "ENCRYPTED"

def extract_strings(data: bytes, min_len=8) -> list:
    """Pure-Python string extractor (replaces system 'strings' command)."""
    result, cur = [], []
    for b in data:
        if 0x20 <= b <= 0x7e:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                result.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        result.append("".join(cur))
    return result

# ─────────────────────────────────────────────────────────────
# CORE ANALYSIS — uses androguard as primary parser
# ─────────────────────────────────────────────────────────────

def analyze_apk(apk_bytes: bytes, filename: str, progress_cb=None) -> dict:
    result = {
        "file_name": filename,
        "file_size": len(apk_bytes),
        "hashes": {},
        "package": None,
        "version": None,
        "min_sdk": None,
        "target_sdk": None,
        "activities": [],
        "services": [],
        "receivers": [],
        "permissions": [],
        "dangerous_perms": [],
        "assets": [],
        "encrypted_assets": [],
        "native_libs": [],
        "all_files": [],
        "malware_families": [],
        "compromised": [],
        "findings": [],
        "risk_score": 0,
        "threat_level": "SAFE",
        "interesting_strings": [],
        "uses_firebase": False,
        "boot_receiver": False,
    }

    WEIGHTS = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 2}

    def add(sev, cat, msg, detail=""):
        result["findings"].append({
            "severity": sev, "category": cat, "message": msg, "detail": detail
        })
        result["risk_score"] += WEIGHTS.get(sev, 0)

    # ── 1. Hashes ─────────────────────────────────────────────
    if progress_cb: progress_cb(5, "Computing file hashes...")
    result["hashes"] = {
        "md5":    hashlib.md5(apk_bytes).hexdigest(),
        "sha1":   hashlib.sha1(apk_bytes).hexdigest(),
        "sha256": hashlib.sha256(apk_bytes).hexdigest(),
    }

    # ── 2. Save to temp file & load with androguard ───────────
    if progress_cb: progress_cb(12, "Loading APK with androguard parser...")
    tmp_path = None
    apk = None
    try:
        from androguard.core.apk import APK as AndroAPK
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as t:
            t.write(apk_bytes)
            tmp_path = t.name
        apk = AndroAPK(tmp_path)
    except Exception as e:
        add("HIGH", "PARSE ERROR", f"Could not fully parse APK: {e}",
            "APK may use heavy obfuscation — partial results only")

    # ── 3. Manifest & Identity ────────────────────────────────
    if progress_cb: progress_cb(25, "Extracting app identity from manifest...")
    if apk:
        result["package"]    = apk.get_package() or "Unknown"
        result["version"]    = apk.get_androidversion_name() or "N/A"
        result["min_sdk"]    = apk.get_min_sdk_version() or "N/A"
        result["target_sdk"] = apk.get_target_sdk_version() or "N/A"
        result["activities"] = apk.get_activities() or []
        result["services"]   = apk.get_services() or []
        result["receivers"]  = apk.get_receivers() or []
        result["all_files"]  = apk.get_files() or []
        result["permissions"]= apk.get_permissions() or []

        # Firebase / C2
        rcvrs_str = " ".join(result["receivers"])
        if re.search(r"firebase|c2dm|FCM", rcvrs_str + result["package"], re.I):
            result["uses_firebase"] = True
        if any("BOOT_COMPLETED" in str(r) for r in result["receivers"]):
            result["boot_receiver"] = True
        # check services too
        if any("firebase" in s.lower() or "Gallipot" in s for s in result["services"]):
            result["uses_firebase"] = True
        if "com.google.firebase.iid.FirebaseInstanceIdReceiver" in rcvrs_str:
            result["uses_firebase"] = True
        if any("WarmerCommixes" in r or "RedbugsSummarizer" in r for r in result["receivers"]):
            result["boot_receiver"] = True

        # Package fake-app checks
        pkg = result["package"] or ""
        for pat, desc in FAKE_APP_PATTERNS:
            if re.search(pat, pkg, re.IGNORECASE):
                add("CRITICAL", "FAKE APP DETECTED", desc, f"Package: {pkg}")
                result["risk_score"] += 25
                break

        if result["uses_firebase"]:
            add("HIGH", "FIREBASE C2",
                "Firebase Cloud Messaging receiver detected",
                "Attacker can send remote commands to all infected devices via Google Firebase")
            result["risk_score"] += 12

        if result["boot_receiver"]:
            add("HIGH", "PERSISTENCE",
                "BOOT_COMPLETED receiver — malware survives every reboot",
                "App auto-restarts whenever the phone is turned on")
            result["risk_score"] += 10

        try:
            sdk = int(result["target_sdk"])
            if sdk <= 22:
                add("HIGH", "SDK EVASION",
                    f"Targets very old Android SDK {sdk}",
                    "All permissions granted automatically without user prompt")
                result["risk_score"] += 15
        except: pass

        # Suspicious component names (obfuscated)
        all_components = result["activities"] + result["services"] + result["receivers"]
        obf = [c for c in all_components
               if re.search(r'[A-Z][a-z]{8,}[A-Z][a-z]{5,}', c.split(".")[-1])]
        if obf:
            add("HIGH", "OBFUSCATED COMPONENTS",
                f"{len(obf)} components with randomly-generated names",
                f"e.g. {obf[0].split('.')[-1]} — nonsense names hide malware classes")
            result["risk_score"] += 10

        # Native libs
        result["native_libs"] = [f for f in result["all_files"]
                                  if f.startswith("lib/") and f.endswith(".so")]
        for lib in result["native_libs"]:
            lib_name = lib.split("/")[-1]
            base = lib_name.replace("lib","").replace(".so","")
            if len(lib_name) > 18 and base.isalpha() and base.islower():
                add("HIGH", "OBFUSCATED LIBRARY NAME",
                    f"Nonsense native library: {lib_name}",
                    "Random names used to bypass AV signature matching — hides malware in native code")
                result["risk_score"] += 10

    # ── 4. Permission Analysis ────────────────────────────────
    if progress_cb: progress_cb(40, "Analysing dangerous permissions...")
    seen = set()
    for perm in result["permissions"]:
        if perm in seen: continue
        seen.add(perm)
        if perm in DANGEROUS_PERMISSIONS:
            sev, desc = DANGEROUS_PERMISSIONS[perm]
            result["dangerous_perms"].append({
                "permission": perm,
                "short": perm.split(".")[-1],
                "severity": sev,
                "description": desc
            })
            add(sev, "PERMISSION", perm.split(".")[-1], desc)

    # ── 5. Asset Entropy Analysis ─────────────────────────────
    if progress_cb: progress_cb(55, "Detecting encrypted payloads in assets...")
    if apk:
        asset_files = [f for f in result["all_files"]
                       if f.startswith("assets/") and not f.endswith("/")
                       and "MaterialIcons" not in f and not f.endswith(".ttf")]
        for asset_path in asset_files:
            try:
                asset_data = apk.get_file(asset_path)
                sz  = len(asset_data)
                if sz < 64: continue
                e   = entropy(asset_data)
                ft  = detect_type(asset_data)
                enc = e >= 7.8
                name = asset_path.split("/")[-1]
                info = {"name": name, "path": asset_path,
                        "size": sz, "entropy": round(e,3),
                        "type": ft, "encrypted": enc}
                result["assets"].append(info)
                if enc:
                    result["encrypted_assets"].append(name)
                    add("CRITICAL", "ENCRYPTED PAYLOAD",
                        f"'{name}' — AES-encrypted hidden payload",
                        f"Entropy {e:.3f}/8.0 · {sz//1024}KB · Decrypted at runtime by native .so")
                    result["risk_score"] += 12
                elif e >= 7.0:
                    add("HIGH", "HIGH ENTROPY ASSET",
                        f"'{name}' may be obfuscated", f"Entropy {e:.3f}/8.0")
                    result["risk_score"] += 5
            except Exception:
                pass

        if len(result["encrypted_assets"]) >= 2:
            total_sz = sum(a["size"] for a in result["assets"] if a.get("encrypted"))
            add("CRITICAL", "DROPPER CONFIRMED",
                f"{len(result['encrypted_assets'])} AES-encrypted payloads "
                f"({total_sz//1024//1024}MB total)",
                "Real malware hidden inside encrypted blobs — definitive dropper signature")
            result["risk_score"] += 30

    # ── 6. Native Library Analysis ────────────────────────────
    if progress_cb: progress_cb(68, "Analysing native libraries...")
    if apk:
        for lib_path in result["native_libs"]:
            try:
                lib_data = apk.get_file(lib_path)
                lib_name = lib_path.split("/")[-1]

                # JNI hooks via string extraction
                lib_strings = extract_strings(lib_data, 8)
                jni_methods  = [s for s in lib_strings if s.startswith("Java_")]
                for jni in jni_methods[:6]:
                    clean = jni.replace("Java_","").replace("__","(").replace("_",".")
                    add("HIGH", "JNI NATIVE HOOK",
                        f"{clean[:90]}", f"Native method in {lib_name}")

                if any("SensorEvent" in s or "onSensorChanged" in s for s in lib_strings):
                    add("HIGH", "ANTI-EMULATOR",
                        f"Sensor hooks found in {lib_name}",
                        "Uses phone accelerometer/gyroscope to detect sandbox analysis — evades automated scanning")
                    result["risk_score"] += 10

                le = entropy(lib_data)
                if le > 7.5:
                    add("HIGH", "PACKED LIBRARY",
                        f"{lib_name} entropy={le:.3f} — packed or encrypted native code")
                    result["risk_score"] += 8
            except Exception:
                pass

    # ── 7. DEX String Hunt for C2 / secrets ──────────────────
    if progress_cb: progress_cb(78, "Scanning DEX bytecode for secrets and C2 URLs...")
    if apk:
        dex_files = [f for f in result["all_files"] if f.endswith(".dex")]
        for dex_name in dex_files[:2]:
            try:
                dex_data = apk.get_file(dex_name)
                strs = extract_strings(dex_data, 10)
                for s in strs:
                    sl = s.lower()
                    if re.match(r'https?://', s) and len(s) > 20:
                        result["interesting_strings"].append(s)
                        add("MEDIUM", "HARDCODED URL", s[:100], f"Found in {dex_name}")
                    elif any(x in sl for x in ["firebase","googleapis","firestore"]):
                        result["interesting_strings"].append(s)
                    elif re.search(r'(password|passwd|secret|apikey|api_key)', sl):
                        result["interesting_strings"].append(s)
                        add("HIGH", "HARDCODED SECRET", s[:80], f"Potential credential in {dex_name}")
            except Exception:
                pass

    # ── 8. Malware Family Matching ────────────────────────────
    if progress_cb: progress_cb(87, "Fingerprinting malware family...")
    perm_shorts = set(p.split(".")[-1] for p in result["permissions"])
    perm_full   = set(result["permissions"])
    for family in MALWARE_FAMILIES:
        hits = sum(1 for ind in family["indicators"]
                   if ind in perm_shorts or ind in perm_full)
        conf = hits / len(family["indicators"])
        if conf >= 0.6:
            result["malware_families"].append({**family, "confidence": round(conf*100)})
            result["risk_score"] += 25

    # ── 9. Impact Mapping ─────────────────────────────────────
    if progress_cb: progress_cb(94, "Mapping attack impact...")
    seen_impact = set()
    for perm in result["permissions"]:
        short = perm.split(".")[-1]
        if short in IMPACT_MAP and short not in seen_impact:
            seen_impact.add(short)
            result["compromised"].append(IMPACT_MAP[short])
    if result["encrypted_assets"]:
        result["compromised"].append(
            "📲 Hidden secondary malware installed via encrypted dropper payloads")
    if result["uses_firebase"]:
        result["compromised"].append(
            "🤖 Device added to attacker's remotely-controlled botnet via Firebase")

    # ── 10. Final Verdict ─────────────────────────────────────
    sc = result["risk_score"]
    if   sc >= 120: result["threat_level"] = "CRITICAL"
    elif sc >= 70:  result["threat_level"] = "HIGH"
    elif sc >= 35:  result["threat_level"] = "MEDIUM"
    elif sc >= 10:  result["threat_level"] = "LOW"
    else:           result["threat_level"] = "SAFE"

    if progress_cb: progress_cb(100, "Analysis complete!")
    if tmp_path and os.path.exists(tmp_path):
        os.unlink(tmp_path)
    return result


# ─────────────────────────────────────────────────────────────
# UI
# ─────────────────────────────────────────────────────────────

def sev_color(sev):
    return {
        "CRITICAL": ("#ef4444","rgba(239,68,68,0.09)","rgba(239,68,68,0.3)","🔴"),
        "HIGH":     ("#f97316","rgba(249,115,22,0.09)","rgba(249,115,22,0.3)","🟠"),
        "MEDIUM":   ("#f59e0b","rgba(245,158,11,0.09)","rgba(245,158,11,0.3)","🟡"),
        "LOW":      ("#22c55e","rgba(34,197,94,0.09)","rgba(34,197,94,0.3)","🟢"),
        "INFO":     ("#64748b","rgba(100,116,139,0.07)","#1e293b","ℹ️"),
    }.get(sev, ("#64748b","rgba(100,116,139,0.07)","#1e293b","ℹ️"))

def render_verdict(r):
    sc, tl = r["risk_score"], r["threat_level"]
    cfg = {
        "CRITICAL": ("#7f1d1d","#ef4444","#fca5a5","⛔  CONFIRMED MALWARE","DELETE IMMEDIATELY — DO NOT INSTALL"),
        "HIGH":     ("#431407","#f97316","#fdba74","🚨  HIGHLY DANGEROUS","Very likely malicious"),
        "MEDIUM":   ("#422006","#d97706","#fcd34d","⚠️  SUSPICIOUS","Potentially dangerous — verify before installing"),
        "LOW":      ("#14532d","#16a34a","#86efac","⚠️  LOW RISK","Some concerns — verify the source"),
        "SAFE":     ("#0f172a","#22c55e","#86efac","✅  LIKELY SAFE","No major threats detected"),
    }
    bg, border, text, title, sub = cfg.get(tl, cfg["SAFE"])
    pct = min(int((sc/300)*100), 100)
    bar = "#ef4444" if tl in ("CRITICAL","HIGH") else "#f59e0b" if tl=="MEDIUM" else "#22c55e"
    st.markdown(f"""
    <div style="background:{bg};border:2px solid {border};border-radius:16px;
                padding:30px;text-align:center;margin:20px 0">
        <div style="font-size:2.2rem;font-weight:800;color:{text}">{title}</div>
        <div style="color:{border};font-size:1rem;margin-top:6px">{sub}</div>
        <div style="margin-top:18px">
            <div style="color:#64748b;font-size:0.78rem;margin-bottom:6px">RISK SCORE: {sc}</div>
            <div style="background:#1e293b;border-radius:999px;height:12px;
                        max-width:400px;margin:0 auto;overflow:hidden">
                <div style="width:{pct}%;height:100%;background:{bar};border-radius:999px"></div>
            </div>
        </div>
    </div>""", unsafe_allow_html=True)

def render_stat_boxes(r):
    crit  = sum(1 for f in r["findings"] if f["severity"]=="CRITICAL")
    high  = sum(1 for f in r["findings"] if f["severity"]=="HIGH")
    enc   = len(r["encrypted_assets"])
    perms = len(r["dangerous_perms"])
    fams  = len(r["malware_families"])
    sz    = r["file_size"]/1024/1024
    stats = [
        (str(crit), "CRITICAL",      "#ef4444"),
        (str(high), "HIGH RISK",     "#f97316"),
        (str(enc),  "HIDDEN BLOBS",  "#a855f7"),
        (str(perms),"DANGER PERMS",  "#06b6d4"),
        (str(fams), "MALWARE MATCH", "#f43f5e"),
        (f"{sz:.1f}M","FILE SIZE",   "#64748b"),
    ]
    cols = st.columns(6)
    for col,(num,label,color) in zip(cols,stats):
        col.markdown(f"""
        <div style="background:#0f172a;border:1px solid #1e293b;border-radius:10px;
                    padding:14px;text-align:center">
            <div style="font-size:1.7rem;font-weight:700;color:{color}">{num}</div>
            <div style="font-size:0.62rem;color:#64748b;letter-spacing:0.08em;
                        text-transform:uppercase;margin-top:3px">{label}</div>
        </div>""", unsafe_allow_html=True)

def render_overview(r):
    # Hashes
    st.markdown('<div class="section-header"><div class="section-num">1</div>'
                '<div class="section-title">File Identification & Hashes</div></div>',
                unsafe_allow_html=True)
    h = r["hashes"]
    st.markdown(f"""
    <div style="background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:16px">
        <div class="hash-row"><span class="hash-label">FILE</span>
            <span style="color:#e2e8f0;font-family:monospace;font-size:0.83rem">{r['file_name']}</span></div>
        <div class="hash-row"><span class="hash-label">SIZE</span>
            <span class="hash-value">{r['file_size']/1024/1024:.2f} MB</span></div>
        <div class="hash-row"><span class="hash-label">MD5</span>
            <span class="hash-value">{h.get('md5','N/A')}</span></div>
        <div class="hash-row"><span class="hash-label">SHA1</span>
            <span class="hash-value">{h.get('sha1','N/A')}</span></div>
        <div class="hash-row" style="border:none"><span class="hash-label">SHA256</span>
            <span class="hash-value">{h.get('sha256','N/A')}</span></div>
    </div>
    <div style="margin-top:8px;padding:10px 14px;background:rgba(99,102,241,0.1);
                border:1px solid rgba(99,102,241,0.3);border-radius:8px;font-size:0.82rem;color:#a5b4fc">
        💡 Copy the <strong>SHA256</strong> hash and search it on <strong>virustotal.com</strong> — 70+ AV engines will check it
    </div>""", unsafe_allow_html=True)

    # Identity
    st.markdown('<div class="section-header" style="margin-top:24px"><div class="section-num">2</div>'
                '<div class="section-title">App Identity</div></div>',
                unsafe_allow_html=True)
    pkg    = r.get("package") or "Unknown"
    is_sus = any(re.search(p,pkg,re.I) for p,_ in FAKE_APP_PATTERNS)
    p_col  = "#fca5a5" if is_sus else "#86efac"
    p_bg   = "rgba(239,68,68,0.12)" if is_sus else "rgba(34,197,94,0.1)"
    p_note = "⚠️ SUSPICIOUS" if is_sus else "✓ Normal"
    st.markdown(f"""
    <div style="background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:16px">
        <div class="hash-row">
            <span class="hash-label">PACKAGE</span>
            <span style="background:{p_bg};color:{p_col};padding:2px 10px;border-radius:6px;
                         font-family:monospace;font-size:0.82rem">{pkg}</span>
            <span style="color:{p_col};font-size:0.72rem;margin-left:6px">{p_note}</span>
        </div>
        <div class="hash-row"><span class="hash-label">VERSION</span>
            <span class="hash-value">{r.get('version','N/A')}</span></div>
        <div class="hash-row"><span class="hash-label">MIN SDK</span>
            <span class="hash-value">{r.get('min_sdk','N/A')}</span></div>
        <div class="hash-row"><span class="hash-label">TARGET SDK</span>
            <span class="hash-value">{r.get('target_sdk','N/A')}</span></div>
        <div class="hash-row"><span class="hash-label">ACTIVITIES</span>
            <span class="hash-value">{len(r.get('activities',[]))}</span></div>
        <div class="hash-row"><span class="hash-label">SERVICES</span>
            <span class="hash-value">{len(r.get('services',[]))}</span></div>
        <div class="hash-row" style="border:none"><span class="hash-label">RECEIVERS</span>
            <span class="hash-value">{len(r.get('receivers',[]))}</span></div>
    </div>""", unsafe_allow_html=True)

    flags = []
    if r.get("uses_firebase"):
        flags.append(("🔥 Firebase C2","#fb923c","Attacker can send remote commands to all infected devices via Firebase"))
    if r.get("boot_receiver"):
        flags.append(("🔄 Boot Persistence","#f87171","Malware auto-restarts on every phone reboot"))
    for label,color,desc in flags:
        st.markdown(f"""
        <div style="background:rgba(239,68,68,0.09);border:1px solid rgba(239,68,68,0.3);
                    border-radius:8px;padding:10px 14px;margin:6px 0;font-size:0.87rem">
            <span style="color:{color};font-weight:600">{label}</span>
            <span style="color:#94a3b8;margin-left:8px">{desc}</span>
        </div>""", unsafe_allow_html=True)

    # All findings
    st.markdown('<div class="section-header" style="margin-top:24px"><div class="section-num">3</div>'
                '<div class="section-title">All Findings</div></div>',
                unsafe_allow_html=True)
    order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    sorted_f = sorted(r.get("findings",[]), key=lambda x: order.get(x["severity"],9))
    for f in sorted_f:
        sev = f["severity"]
        if sev == "GOOD": continue
        tc,bg,border,icon = sev_color(sev)
        detail = (f'<div style="color:#64748b;font-size:0.77rem;margin-top:3px;'
                  f'font-style:italic">{f["detail"]}</div>') if f.get("detail") else ""
        st.markdown(f"""
        <div style="background:{bg};border:1px solid {border};border-radius:8px;
                    padding:9px 13px;margin:4px 0;display:flex;align-items:flex-start;gap:10px">
            <span style="font-size:0.88rem;margin-top:1px">{icon}</span>
            <div style="flex:1">
                <div style="display:flex;justify-content:space-between;align-items:flex-start">
                    <span style="color:{tc};font-weight:600;font-size:0.84rem">
                        {f['category']}: {f['message']}</span>
                    <span style="color:{tc};font-size:0.67rem;font-weight:700;
                                 opacity:0.7;white-space:nowrap;margin-left:8px">{sev}</span>
                </div>
                {detail}
            </div>
        </div>""", unsafe_allow_html=True)

def render_permissions(r):
    st.markdown('<div class="section-header"><div class="section-num">4</div>'
                '<div class="section-title">Dangerous Permissions</div></div>',
                unsafe_allow_html=True)
    perms = r["dangerous_perms"]
    if not perms:
        st.markdown('<div style="color:#22c55e;padding:10px">✓ No dangerous permissions found</div>',
                    unsafe_allow_html=True)
        return
    sev_order = ["CRITICAL","HIGH","MEDIUM","LOW"]
    for p in sorted(perms, key=lambda x: sev_order.index(x["severity"]) if x["severity"] in sev_order else 9):
        tc,bg,border,icon = sev_color(p["severity"])
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
    st.markdown('<div class="section-header"><div class="section-num">5</div>'
                '<div class="section-title">Encrypted Payload Detection</div></div>',
                unsafe_allow_html=True)
    enc_list = r.get("encrypted_assets",[])
    if not enc_list:
        st.markdown('<div style="color:#22c55e;padding:10px">✓ No encrypted payloads found</div>',
                    unsafe_allow_html=True)
    else:
        total_sz = sum(a.get("size",0) for a in r.get("assets",[]) if a.get("encrypted"))
        st.markdown(f"""
        <div style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);
                    border-radius:10px;padding:14px 18px;margin-bottom:12px">
            <div style="color:#ef4444;font-weight:700">
                ⛔ {len(enc_list)} AES-Encrypted Payloads — {total_sz//1024//1024}MB Total</div>
            <div style="color:#fca5a5;font-size:0.85rem;margin-top:4px">
                Real malware is hidden in encrypted blobs — decrypted at runtime by the native library.
                This is the <strong>definitive signature of a dropper APK</strong>.
            </div>
        </div>""", unsafe_allow_html=True)
    for a in r.get("assets",[]):
        if not isinstance(a,dict): continue
        e,enc,nm,sz,ft = a.get("entropy",0),a.get("encrypted",False),a.get("name","?"),a.get("size",0),a.get("type","?")
        if enc:
            st.markdown(f"""
            <div style="background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.25);
                        border-radius:8px;padding:9px 14px;margin:4px 0;
                        display:flex;justify-content:space-between;align-items:center">
                <div>
                    <span style="color:#fca5a5;font-family:monospace;font-size:0.84rem">🔒 {nm}</span>
                    <span style="color:#64748b;font-size:0.74rem;margin-left:10px">{sz//1024}KB · {ft}</span>
                </div>
                <div style="color:#ef4444;font-size:0.77rem;font-weight:600;white-space:nowrap">
                    entropy {e:.3f}/8.0</div>
            </div>""", unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div style="background:rgba(100,116,139,0.06);border:1px solid #1e293b;
                        border-radius:8px;padding:8px 14px;margin:4px 0;
                        display:flex;justify-content:space-between">
                <span style="color:#64748b;font-family:monospace;font-size:0.81rem">📄 {nm}</span>
                <span style="color:#475569;font-size:0.74rem">entropy {e:.3f}</span>
            </div>""", unsafe_allow_html=True)

def render_malware(r):
    st.markdown('<div class="section-header"><div class="section-num">6</div>'
                '<div class="section-title">Malware Family Fingerprinting</div></div>',
                unsafe_allow_html=True)
    fams = r.get("malware_families",[])
    if not fams:
        st.markdown('<div style="color:#22c55e;padding:10px">✓ No known malware family matched</div>',
                    unsafe_allow_html=True)
        return
    for fam in sorted(fams, key=lambda x:-x["confidence"]):
        col,conf = fam.get("color","#ef4444"),fam["confidence"]
        st.markdown(f"""
        <div style="background:rgba(239,68,68,0.07);border:1px solid rgba(239,68,68,0.2);
                    border-radius:10px;padding:16px;margin:8px 0">
            <div style="display:flex;justify-content:space-between;margin-bottom:8px">
                <div style="color:{col};font-weight:700;font-size:0.95rem">{fam['name']}</div>
                <div style="color:{col};font-size:0.8rem;font-weight:600">Match: {conf}%</div>
            </div>
            <div style="background:#1e293b;border-radius:999px;height:7px;margin-bottom:10px">
                <div style="width:{conf}%;height:100%;background:{col};border-radius:999px"></div>
            </div>
            <div style="color:#94a3b8;font-size:0.84rem">{fam['description']}</div>
        </div>""", unsafe_allow_html=True)

def render_impact(r):
    st.markdown('<div class="section-header"><div class="section-num">7</div>'
                '<div class="section-title">What Gets Compromised If Installed</div></div>',
                unsafe_allow_html=True)
    items = r.get("compromised",[])
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


# ─────────────────────────────────────────────────────────────
# MAIN
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

st.markdown('<div style="text-align:center;color:#64748b;font-size:0.88rem;margin-bottom:6px">'
            '📂 Drag & drop your APK file below, or click Browse</div>',
            unsafe_allow_html=True)

uploaded = st.file_uploader("Upload APK", type=["apk"], label_visibility="collapsed")

if uploaded:
    c1,c2,c3 = st.columns([1,2,1])
    with c2:
        go = st.button("🔍  Analyze APK Now", use_container_width=True)

    if go:
        apk_bytes = uploaded.read()
        prog      = st.progress(0)
        status    = st.empty()
        def cb(pct, msg):
            prog.progress(pct)
            status.markdown(f'<div style="color:#64748b;font-size:0.84rem;text-align:center">{msg}</div>',
                            unsafe_allow_html=True)
        try:
            result = analyze_apk(apk_bytes, uploaded.name, cb)
        except Exception as e:
            st.error(f"Analysis error: {e}")
            st.stop()

        prog.empty(); status.empty()
        st.markdown("---")
        render_verdict(result)
        st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)
        render_stat_boxes(result)

        t1,t2,t3,t4,t5 = st.tabs(["📋 Overview","🔐 Permissions","📦 Payloads","🦠 Malware ID","💥 Impact"])
        with t1: render_overview(result)
        with t2: render_permissions(result)
        with t3: render_assets(result)
        with t4: render_malware(result)
        with t5: render_impact(result)

        st.markdown("---")
        sha = result["hashes"].get("sha256","")
        st.markdown(f"""
        <div style="padding:12px 16px;background:rgba(99,102,241,0.1);border:1px solid rgba(99,102,241,0.3);
                    border-radius:8px;font-size:0.84rem;color:#a5b4fc;margin-bottom:10px">
            🔍 <strong>Cross-check on VirusTotal:</strong> Search SHA256
            <code style="background:rgba(0,0,0,0.3);padding:2px 6px;border-radius:4px">{sha[:32]}...</code>
            at <strong>virustotal.com</strong>
        </div>
        <div style="padding:12px 16px;background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.2);
                    border-radius:8px;font-size:0.84rem;color:#fca5a5">
            🇮🇳 <strong>Report this malware:</strong>
            <strong>cybercrime.gov.in</strong> · Helpline <strong>1930</strong>
        </div>""", unsafe_allow_html=True)

        st.download_button(
            "⬇️  Download Full JSON Report",
            data=json.dumps(result, indent=2, default=str),
            file_name=uploaded.name.replace(".apk","_threat_report.json"),
            mime="application/json",
            use_container_width=True
        )
else:
    cols = st.columns(3)
    for i,(icon,title,desc) in enumerate([
        ("🔍","Deep Static Analysis","Parses APK structure, DEX bytecode, binary manifest using androguard — works even on obfuscated APKs"),
        ("🔒","Encryption Detection","Finds AES-encrypted hidden payloads using entropy analysis — 8.0/8.0 = fully encrypted"),
        ("📋","Permission Audit","Checks 30+ dangerous Android permissions with plain-English explanations"),
        ("🦠","Malware Fingerprinting","Matches against 6 malware families: Banking Trojans, UPI Stealers, RATs, Droppers, Ransomware"),
        ("💥","Impact Report","Tells you exactly what data gets stolen and which accounts get compromised"),
        ("📥","Evidence Report","Download full JSON report to submit to cybercrime.gov.in or helpline 1930"),
    ]):
        with cols[i%3]:
            st.markdown(f"""
            <div style="background:#111827;border:1px solid #1e293b;border-radius:12px;
                        padding:20px;margin:8px 0;min-height:140px">
                <div style="font-size:1.7rem">{icon}</div>
                <div style="color:#e2e8f0;font-weight:600;font-size:0.88rem;margin:8px 0 4px">{title}</div>
                <div style="color:#64748b;font-size:0.79rem;line-height:1.5">{desc}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("""
    <div style="margin-top:20px;padding:14px 18px;background:rgba(99,102,241,0.08);
                border:1px solid rgba(99,102,241,0.25);border-radius:10px;
                font-size:0.84rem;color:#94a3b8;text-align:center">
        🇮🇳 Built to detect fake Indian government app scams —
        mParivahan, Aadhaar, IRCTC, Income Tax, Traffic Challan impersonators<br>
        <span style="color:#64748b;font-size:0.77rem">
        Got a suspicious APK on WhatsApp or SMS? Upload it here before you install it.</span>
    </div>""", unsafe_allow_html=True)

st.markdown("""
<div style="margin-top:40px;padding:16px;border-top:1px solid #1e293b;
            text-align:center;color:#334155;font-size:0.77rem">
    APK Threat Analyzer · Cybercrime Investigation Tool ·
    Report: <strong style="color:#475569">cybercrime.gov.in</strong> ·
    Helpline: <strong style="color:#475569">1930</strong>
</div>""", unsafe_allow_html=True)
