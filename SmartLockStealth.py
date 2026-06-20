import os
import json
import shutil
import threading
import time
import hashlib
import subprocess
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import wmi
import joblib
import numpy as np
from cryptography.fernet import Fernet

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    yara = None
    YARA_AVAILABLE = False

# -----------------------------
# CONFIG
# -----------------------------
APP_NAME = "SmartLock Stealth"
LOG_FILE = "smartlock_events.log"
CONFIG_FILE = "protected_items.json"

APPDATA_DIR = os.environ.get("APPDATA", os.getcwd())
VAULT_DIR = os.path.join(APPDATA_DIR, "SmartLockStealthVault")
VAULT_MAP_FILE = os.path.join(VAULT_DIR, "vault_map.json")
QUARANTINE_DIR = os.path.join(APPDATA_DIR, "SmartLockStealthQuarantine")

KEY_FILE = os.path.join(APPDATA_DIR, "smartlock_secret.key")
YARA_RULE_FILE = "malware_rules.yar"
MODEL_FILE = "ember_model.pkl"

PASSWORD_FILE = os.path.join(APPDATA_DIR, "smartlock_auth.json")
SALT_FILE = os.path.join(APPDATA_DIR, "smartlock_salt.bin")

MAX_SCAN_FILE_SIZE_MB = 50
MAX_SCAN_FILE_SIZE = MAX_SCAN_FILE_SIZE_MB * 1024 * 1024

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".vbs", ".js", ".jse", ".ps1", ".scr",
    ".com", ".pif", ".hta", ".wsf", ".wsh", ".msi", ".dll"
}

SUSPICIOUS_FILENAMES = {
    "autorun.inf", "run.vbs", "payload.exe", "malware.exe", "virus.exe"
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".jse",
    ".ps1", ".hta", ".wsf", ".wsh", ".com", ".pif", ".msi"
}

TROJAN_KEYWORDS = [
    "powershell",
    "cmd.exe",
    "wscript",
    "cscript",
    "invoke-expression",
    "frombase64string",
    "downloadstring",
    "start-process",
    "reg add",
    "schtasks",
    "temp",
    "appdata",
    "http://",
    "https://"
]

KNOWN_MALWARE_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f": "EICAR-Test-File"
}

ML_MODEL = None

COLORS = {
    "bg_main": "#0b1220",
    "bg_panel": "#0f172a",
    "text_main": "#e5e7eb",
    "text_soft": "#cbd5e1",

    "blue": "#2563eb",
    "blue_soft": "#dbeafe",

    "green": "#059669",
    "green_soft": "#d1fae5",

    "orange": "#d97706",
    "orange_soft": "#fef3c7",

    "red": "#dc2626",
    "red_soft": "#fecaca",

    "gray": "#475569",
    "gray_soft": "#e2e8f0",

    "purple": "#7c3aed",
    "purple_soft": "#ede9fe",
}


# -----------------------------
# UTILITIES
# -----------------------------
def now_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def ensure_dirs():
    os.makedirs(VAULT_DIR, exist_ok=True)
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    try:
        os.system(f'attrib +h "{VAULT_DIR}"')
        os.system(f'attrib +h "{QUARANTINE_DIR}"')
    except Exception:
        pass


def log_to_file(msg: str):
    line = f"[{now_ts()}] {msg}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line)


def unique_name(path: str):
    base = os.path.basename(path.rstrip("\\/"))
    name, ext = os.path.splitext(base)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    return f"{name}_{stamp}{ext}"


def file_md5(path: str):
    md5 = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            md5.update(chunk)
    return md5.hexdigest()


def read_file_head(path: str, max_bytes: int = 4096):
    with open(path, "rb") as f:
        return f.read(max_bytes)


def is_pe_file(path: str):
    try:
        return read_file_head(path, 2) == b"MZ"
    except Exception:
        return False


def normalize_drive_for_walk(drive: str):
    return drive if drive.endswith("\\") else drive + "\\"


# -----------------------------
# PASSWORD / AUTH
# -----------------------------
def generate_salt():
    if not os.path.exists(SALT_FILE):
        with open(SALT_FILE, "wb") as f:
            f.write(os.urandom(16))


def load_salt():
    generate_salt()
    with open(SALT_FILE, "rb") as f:
        return f.read()


def hash_password(password: str, salt: bytes):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000).hex()


def password_exists():
    return os.path.exists(PASSWORD_FILE)


def save_master_password(password: str):
    salt = load_salt()
    password_hash = hash_password(password, salt)
    data = {"password_hash": password_hash}
    with open(PASSWORD_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def verify_master_password(password: str):
    if not password_exists():
        return False
    salt = load_salt()
    with open(PASSWORD_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    stored_hash = data.get("password_hash", "")
    return hash_password(password, salt) == stored_hash


def setup_or_verify_password():
    root = tk.Tk()
    root.withdraw()

    if not password_exists():
        pw1 = simpledialog.askstring(
            "Create Password",
            "Set a master password for SmartLock Stealth:",
            show="*",
            parent=root
        )
        if not pw1:
            messagebox.showerror("Password Required", "Master password setup is required.", parent=root)
            root.destroy()
            return False

        pw2 = simpledialog.askstring(
            "Confirm Password",
            "Re-enter your master password:",
            show="*",
            parent=root
        )
        if pw1 != pw2:
            messagebox.showerror("Password Error", "Passwords do not match.", parent=root)
            root.destroy()
            return False

        save_master_password(pw1)
        messagebox.showinfo("Password Set", "Master password created successfully.", parent=root)
        root.destroy()
        return True

    password = simpledialog.askstring(
        "Login Required",
        "Enter master password to open SmartLock Stealth:",
        show="*",
        parent=root
    )
    if not password:
        messagebox.showerror("Access Denied", "Password is required.", parent=root)
        root.destroy()
        return False

    if not verify_master_password(password):
        messagebox.showerror("Access Denied", "Incorrect password.", parent=root)
        root.destroy()
        return False

    root.destroy()
    return True


# -----------------------------
# ENCRYPTION
# -----------------------------
def generate_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)


def load_key():
    if not os.path.exists(KEY_FILE):
        generate_key()
    with open(KEY_FILE, "rb") as f:
        return f.read()


def get_cipher():
    return Fernet(load_key())


def encrypt_file_to_path(source_path: str, dest_path: str):
    cipher = get_cipher()
    with open(source_path, "rb") as f:
        data = f.read()
    encrypted_data = cipher.encrypt(data)
    with open(dest_path, "wb") as f:
        f.write(encrypted_data)
    os.remove(source_path)


def decrypt_file_to_path(source_path: str, dest_path: str):
    cipher = get_cipher()
    with open(source_path, "rb") as f:
        encrypted_data = f.read()
    decrypted_data = cipher.decrypt(encrypted_data)
    with open(dest_path, "wb") as f:
        f.write(decrypted_data)
    os.remove(source_path)


def encrypt_folder_to_archive(source_folder: str, dest_archive_path: str):
    temp_zip_base = dest_archive_path + "_temp"
    zip_path = shutil.make_archive(temp_zip_base, "zip", source_folder)
    encrypt_file_to_path(zip_path, dest_archive_path)
    shutil.rmtree(source_folder, ignore_errors=True)


def decrypt_archive_to_folder(source_archive_path: str, dest_folder_path: str):
    temp_zip_path = source_archive_path + "_temp.zip"
    decrypt_file_to_path(source_archive_path, temp_zip_path)
    os.makedirs(dest_folder_path, exist_ok=True)
    shutil.unpack_archive(temp_zip_path, dest_folder_path, "zip")
    os.remove(temp_zip_path)


# -----------------------------
# MODEL
# -----------------------------
def load_ml_model():
    global ML_MODEL
    if os.path.exists(MODEL_FILE):
        try:
            ML_MODEL = joblib.load(MODEL_FILE)
            return True
        except Exception:
            ML_MODEL = None
            return False
    ML_MODEL = None
    return False


# -----------------------------
# PROTECTED ITEMS CONFIG
# -----------------------------
def load_protected_items():
    if not os.path.exists(CONFIG_FILE):
        return []

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
    except Exception:
        pass

    return []


def save_protected_items(items):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(items, f, indent=2)


# -----------------------------
# USB DETECTION
# -----------------------------
def get_usb_storage_drives():
    c = wmi.WMI()
    result = {}

    for disk in c.Win32_DiskDrive(InterfaceType="USB"):
        for partition in disk.associators("Win32_DiskDriveToDiskPartition"):
            for logical in partition.associators("Win32_LogicalDiskToPartition"):
                drive = logical.DeviceID
                label = logical.VolumeName if logical.VolumeName else "Unknown"
                fs = logical.FileSystem if logical.FileSystem else "Unknown"
                result[drive] = {
                    "model": disk.Model,
                    "label": label,
                    "fs": fs
                }

    return result


# -----------------------------
# VAULT MAP
# -----------------------------
def read_vault_map():
    if not os.path.exists(VAULT_MAP_FILE):
        return {}

    try:
        with open(VAULT_MAP_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except Exception:
        pass

    return {}


def write_vault_map(mapping: dict):
    ensure_dirs()
    with open(VAULT_MAP_FILE, "w", encoding="utf-8") as f:
        json.dump(mapping, f, indent=2)


# -----------------------------
# PROTECTION
# -----------------------------
def protect_items(items: list):
    ensure_dirs()
    mapping = read_vault_map()

    moved_count = 0
    skipped = []

    for item in items:
        p = item.get("path", "")
        use_encryption = item.get("encrypted", False)
        item_type = item.get("type", "file")

        if not p or not os.path.exists(p):
            skipped.append(f"Not found: {p}")
            continue

        if p in mapping and os.path.exists(mapping[p]["vault_path"]):
            skipped.append(f"Already protected: {p}")
            continue

        try:
            if item_type == "folder":
                if use_encryption:
                    dest = os.path.join(VAULT_DIR, unique_name(p) + ".enc")
                    encrypt_folder_to_archive(p, dest)
                else:
                    dest = os.path.join(VAULT_DIR, unique_name(p))
                    shutil.move(p, dest)
            else:
                if use_encryption:
                    dest = os.path.join(VAULT_DIR, unique_name(p) + ".enc")
                    encrypt_file_to_path(p, dest)
                else:
                    dest = os.path.join(VAULT_DIR, unique_name(p))
                    shutil.move(p, dest)

            mapping[p] = {
                "vault_path": dest,
                "encrypted": use_encryption,
                "type": item_type
            }
            moved_count += 1

        except Exception as e:
            skipped.append(f"Failed: {p} ({e})")

    write_vault_map(mapping)
    return moved_count, skipped


def restore_items():
    mapping = read_vault_map()
    restored = 0
    failed = []

    for orig, info in list(mapping.items()):
        vaultp = info.get("vault_path", "")
        encrypted = info.get("encrypted", False)
        item_type = info.get("type", "file")

        if not os.path.exists(vaultp):
            failed.append(f"Vault missing: {orig}")
            mapping.pop(orig, None)
            continue

        try:
            parent = os.path.dirname(orig)
            if parent:
                os.makedirs(parent, exist_ok=True)

            dest = orig
            if os.path.exists(dest):
                if item_type == "folder":
                    dest = dest + "_restored"
                else:
                    base, ext = os.path.splitext(dest)
                    dest = f"{base}_restored{ext}"

            if item_type == "folder":
                if encrypted:
                    decrypt_archive_to_folder(vaultp, dest)
                else:
                    shutil.move(vaultp, dest)
            else:
                if encrypted:
                    decrypt_file_to_path(vaultp, dest)
                else:
                    shutil.move(vaultp, dest)

            mapping.pop(orig, None)
            restored += 1

        except Exception as e:
            failed.append(f"Failed restore: {orig} ({e})")

    write_vault_map(mapping)
    return restored, failed


# -----------------------------
# QUARANTINE
# -----------------------------
def quarantine_file(file_path: str):
    ensure_dirs()
    if not os.path.exists(file_path):
        return None
    dest = os.path.join(QUARANTINE_DIR, unique_name(file_path))
    shutil.move(file_path, dest)
    return dest


# -----------------------------
# YARA
# -----------------------------
def load_yara_rules():
    if not YARA_AVAILABLE:
        return None
    if not os.path.exists(YARA_RULE_FILE):
        return None
    try:
        return yara.compile(filepath=YARA_RULE_FILE)
    except Exception:
        return None


def scan_file_with_yara(file_path: str, yara_rules):
    if not yara_rules:
        return []
    try:
        matches = yara_rules.match(file_path)
        return [f"YARA match: {m.rule}" for m in matches]
    except Exception:
        return []

def trojan_risk_scan(file_path: str):
    reasons = []
    risk_score = 0

    if not os.path.isfile(file_path):
        return reasons, risk_score

    filename = os.path.basename(file_path).lower()
    ext = os.path.splitext(filename)[1].lower()

    if ext in DANGEROUS_EXTENSIONS:
        reasons.append(f"Trojan risk: dangerous executable/script type ({ext})")
        risk_score += 2

    if filename == "autorun.inf":
        reasons.append("Trojan risk: autorun file detected")
        risk_score += 5

    if filename in SUSPICIOUS_FILENAMES:
        reasons.append(f"Trojan risk: suspicious filename ({filename})")
        risk_score += 3

    if ext in {".bat", ".cmd", ".vbs", ".js", ".jse", ".ps1", ".hta", ".wsf", ".wsh"}:
        try:
            content = read_file_head(file_path, 8192).decode(errors="ignore").lower()

            for keyword in TROJAN_KEYWORDS:
                if keyword in content:
                    reasons.append(f"Trojan risk: suspicious script keyword ({keyword})")
                    risk_score += 3

            if "frombase64string" in content or "invoke-expression" in content:
                reasons.append("Trojan risk: encoded/obfuscated PowerShell command")
                risk_score += 5

        except Exception:
            pass

    if ext in {".exe", ".dll", ".scr", ".com"} and is_pe_file(file_path):
        reasons.append("Trojan risk: Windows executable detected on USB")
        risk_score += 2

    return reasons, risk_score

# -----------------------------
# HEURISTIC
# -----------------------------
def heuristic_scan_file(file_path: str):
    reasons = []

    if not os.path.isfile(file_path):
        return reasons

    name = os.path.basename(file_path).lower()
    ext = os.path.splitext(name)[1].lower()

    try:
        size = os.path.getsize(file_path)
    except Exception:
        size = 0

    trojan_reasons, trojan_score = trojan_risk_scan(file_path)
    reasons.extend(trojan_reasons)

    if trojan_score >= 5:
        reasons.append(f"High Trojan risk score: {trojan_score}")

    if name in SUSPICIOUS_FILENAMES:
        reasons.append(f"Suspicious filename: {name}")

    if ext in SUSPICIOUS_EXTENSIONS:
        reasons.append(f"Suspicious extension: {ext}")

    try:
        md5 = file_md5(file_path)
        if md5 in KNOWN_MALWARE_HASHES:
            reasons.append(f"Known malware hash match: {KNOWN_MALWARE_HASHES[md5]}")
    except Exception:
        pass

    if name == "autorun.inf":
        try:
            content = read_file_head(file_path, 4096).decode(errors="ignore").lower()
            if "open=" in content or "shellexecute=" in content:
                reasons.append("Autorun command found")
        except Exception:
            pass

    if ext in {".bat", ".cmd", ".vbs", ".js", ".jse", ".ps1", ".wsf", ".wsh"}:
        try:
            content = read_file_head(file_path, 4096).decode(errors="ignore").lower()
            keywords = [
                "powershell", "cmd.exe", "wscript", "cscript",
                "createobject", "frombase64string", "invoke-expression",
                "downloadstring", "start-process", "reg add", "schtasks"
            ]

            for kw in keywords:
                if kw in content:
                    reasons.append(f"Script keyword detected: {kw}")
                    break
        except Exception:
            pass

    if ext in {".exe", ".dll", ".scr", ".com"} and is_pe_file(file_path):
        reasons.append("Portable Executable (PE) file detected")

    if ext in {".exe", ".dll", ".scr"} and size > 5 * 1024 * 1024:
        reasons.append("Large executable on removable media")

    return reasons


# -----------------------------
# ML FEATURES
# -----------------------------
def calculate_entropy(data: bytes):
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * np.log2(p)
    return float(entropy)


def extract_features(file_path: str):
    try:
        size = os.path.getsize(file_path)
        ext = os.path.splitext(file_path)[1].lower()

        is_exe = 1 if ext == ".exe" else 0
        is_dll = 1 if ext == ".dll" else 0
        is_script = 1 if ext in {".bat", ".cmd", ".vbs", ".js", ".jse", ".ps1", ".wsf", ".wsh"} else 0
        is_autorun = 1 if os.path.basename(file_path).lower() == "autorun.inf" else 0
        has_mz = 1 if is_pe_file(file_path) else 0

        head = read_file_head(file_path, 4096)
        entropy = calculate_entropy(head)

        suspicious_name = 1 if os.path.basename(file_path).lower() in SUSPICIOUS_FILENAMES else 0
        suspicious_ext = 1 if ext in SUSPICIOUS_EXTENSIONS else 0

        return np.array([[
            size, is_exe, is_dll, is_script, is_autorun,
            has_mz, entropy, suspicious_name, suspicious_ext
        ]])
    except Exception:
        return None


def ml_scan_file(file_path: str):
    if ML_MODEL is None:
        return []

    features = extract_features(file_path)
    if features is None:
        return []

    try:
        pred = ML_MODEL.predict(features)[0]
        reasons = []

        if int(pred) == 1:
            if hasattr(ML_MODEL, "predict_proba"):
                probs = ML_MODEL.predict_proba(features)[0]
                score = round(float(probs[1]) * 100, 2)
                reasons.append(f"ML model flagged as suspicious ({score}%)")
            else:
                reasons.append("ML model flagged as suspicious")
        return reasons
    except Exception:
        return []


# -----------------------------
# USB BLOCK / AUTO EJECT
# -----------------------------
def eject_usb_drive(drive_letter: str):
    """Safely eject a USB drive after malicious files are detected."""
    try:
        drive_letter = drive_letter.replace("\\", "").strip()

        powershell_script = (
            f'$drive = "{drive_letter}"; '
            '$shell = New-Object -ComObject Shell.Application; '
            '$shell.Namespace(17).ParseName($drive).InvokeVerb("Eject")'
        )

        completed = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", powershell_script],
            capture_output=True,
            text=True,
            timeout=10
        )

        if completed.returncode == 0:
            return True, "USB device ejected/blocked successfully."

        return False, completed.stderr.strip() or "USB eject command completed but Windows did not confirm eject."

    except Exception as e:
        return False, f"USB eject failed: {e}"


# -----------------------------
# USB SCAN
# -----------------------------
def scan_usb_drive(drive: str):
    yara_rules = load_yara_rules()

    result = {
        "drive": drive,
        "scanned": 0,
        "suspicious": [],
        "quarantined": [],
        "errors": [],
        "used_yara": bool(yara_rules),
        "used_ml": ML_MODEL is not None
    }

    root_drive = normalize_drive_for_walk(drive)

    for root, dirs, files in os.walk(root_drive):
        for file in files:
            file_path = os.path.join(root, file)

            try:
                if not os.path.exists(file_path):
                    continue

                if os.path.getsize(file_path) > MAX_SCAN_FILE_SIZE:
                    continue

                result["scanned"] += 1
                reasons = []

                reasons.extend(heuristic_scan_file(file_path))
                reasons.extend(scan_file_with_yara(file_path, yara_rules))
                reasons.extend(ml_scan_file(file_path))

                if reasons:
                    item = {
                        "path": file_path,
                        "reasons": reasons
                    }
                    result["suspicious"].append(item)

                    try:
                        quarantined_path = quarantine_file(file_path)

                        if quarantined_path:
                            result["quarantined"].append({
                                "original": file_path,
                                "quarantine": quarantined_path,
                                "reasons": reasons
                            })

                    except Exception as qe:
                        result["errors"].append(
                            f"Quarantine failed: {file_path} ({qe})"
                        )

            except Exception as e:
                result["errors"].append(f"{file_path} ({e})")

    return result

# -----------------------------
# UI
# -----------------------------
class SmartLockApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1160x760")
        self.resizable(False, False)

        self.running = False
        self.thread = None
        self.prev_usb = {}
        self.items = load_protected_items()
        self.suspicious_files = []
        # Active threat flag: blocks restore until suspicious USB is removed
        self.active_threat = False
        self._set_style()
        self._build_ui()
        self.after(350, self.initial_usb_scan)

    def require_password(self, action_name="this action"):
        password = simpledialog.askstring(
            "Password Required",
            f"Enter master password to continue {action_name}:",
            show="*",
            parent=self
        )
        if not password:
            return False
        if not verify_master_password(password):
            messagebox.showerror("Access Denied", "Incorrect password.", parent=self)
            return False
        return True

    def _set_style(self):
        self.configure(bg=COLORS["bg_main"])

        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure("TFrame", background=COLORS["bg_main"])
        style.configure("TLabel", background=COLORS["bg_main"], foreground=COLORS["text_main"])
        style.configure("Title.TLabel", font=("Segoe UI", 20, "bold"), foreground="#ffffff")
        style.configure("Sub.TLabel", font=("Segoe UI", 10), foreground=COLORS["text_soft"])

        style.configure("Card.TLabelframe", background=COLORS["bg_main"], foreground=COLORS["text_main"])
        style.configure(
            "Card.TLabelframe.Label",
            background=COLORS["bg_main"],
            foreground="#93c5fd",
            font=("Segoe UI", 10, "bold")
        )

        style.configure(
            "Primary.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=(10, 6),
            background="#3b82f6",
            foreground="#ffffff",
            borderwidth=0,
            relief="flat"
        )
        style.map(
            "Primary.TButton",
            background=[("active", "#2563eb"), ("pressed", "#1d4ed8"), ("disabled", "#334155")],
            foreground=[("disabled", "#cbd5e1")]
        )

        style.configure(
            "Ghost.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=(10, 6),
            background="#475569",
            foreground="#ffffff",
            borderwidth=0,
            relief="flat"
        )
        style.map(
            "Ghost.TButton",
            background=[("active", "#334155"), ("pressed", "#1e293b"), ("disabled", "#1f2937")],
            foreground=[("disabled", "#94a3b8")]
        )

        style.configure(
            "Danger.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=(10, 6),
            background="#ef4444",
            foreground="#ffffff",
            borderwidth=0,
            relief="flat"
        )
        style.map(
            "Danger.TButton",
            background=[("active", "#dc2626"), ("pressed", "#b91c1c"), ("disabled", "#334155")],
            foreground=[("disabled", "#fecaca")]
        )

        style.configure(
            "Ok.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=(10, 6),
            background="#10b981",
            foreground="#ffffff",
            borderwidth=0,
            relief="flat"
        )
        style.map(
            "Ok.TButton",
            background=[("active", "#059669"), ("pressed", "#047857"), ("disabled", "#334155")],
            foreground=[("disabled", "#d1fae5")]
        )

    def _build_ui(self):
        header = ttk.Frame(self)
        header.pack(fill="x", padx=18, pady=(14, 10))

        ttk.Label(header, text="SmartLock Stealth", style="Title.TLabel").grid(row=0, column=0, sticky="w")

        self.status_var = tk.StringVar(value="READY")
        self.status_badge = tk.Label(
            header,
            textvariable=self.status_var,
            font=("Segoe UI", 10, "bold"),
            bg=COLORS["gray"],
            fg=COLORS["blue_soft"],
            padx=14,
            pady=7
        )
        self.status_badge.grid(row=0, column=1, sticky="e")
        header.columnconfigure(0, weight=1)

        main = ttk.Frame(self)
        main.pack(fill="both", expand=True, padx=18, pady=(0, 14))

        left = ttk.Frame(main)
        right = ttk.Frame(main)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        right.grid(row=0, column=1, sticky="nsew")

        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=1)
        main.rowconfigure(0, weight=1)

        ctrl_card = ttk.Labelframe(left, text="Controls", style="Card.TLabelframe")
        ctrl_card.pack(fill="x", pady=(0, 12))

        btn_row = ttk.Frame(ctrl_card)
        btn_row.pack(anchor="w", padx=12, pady=12)

        self.start_btn = ttk.Button(btn_row, text="▶ Start Monitoring", style="Primary.TButton", command=self.start_monitoring)
        self.stop_btn = ttk.Button(btn_row, text="■ Stop", style="Danger.TButton", command=self.stop_monitoring, state="disabled")
        self.restore_btn = ttk.Button(btn_row, text="↺ Restore Files", style="Ok.TButton", command=self.manual_restore)
        self.save_btn = ttk.Button(btn_row, text="💾 Save List", style="Ghost.TButton", command=self.save_list)

        self.start_btn.pack(side="left", padx=(0, 8))
        self.stop_btn.pack(side="left", padx=(0, 8))
        self.restore_btn.pack(side="left", padx=(0, 8))
        self.save_btn.pack(side="left")

        usb_card = ttk.Labelframe(left, text="USB Storage Detection", style="Card.TLabelframe")
        usb_card.pack(fill="x", pady=(0, 12))

        self.usb_var = tk.StringVar(value="Scanning USB devices...")
        usb_text = tk.Label(
            usb_card,
            textvariable=self.usb_var,
            font=("Consolas", 10),
            bg=COLORS["bg_panel"],
            fg=COLORS["text_main"],
            justify="left",
            anchor="w",
            padx=12,
            pady=10
        )
        usb_text.pack(fill="x", padx=12, pady=12)

        items_card = ttk.Labelframe(left, text="Protected Items", style="Card.TLabelframe")
        items_card.pack(fill="both", expand=True)

        items_btns = ttk.Frame(items_card)
        items_btns.pack(anchor="w", padx=12, pady=(12, 8))

        ttk.Button(items_btns, text="📄 Add File", style="Ghost.TButton", command=self.add_file).pack(side="left", padx=(0, 8))
        ttk.Button(items_btns, text="📁 Add Folder", style="Ghost.TButton", command=self.add_folder).pack(side="left", padx=(0, 8))
        ttk.Button(items_btns, text="🔐 Encryption", style="Ok.TButton", command=self.toggle_selected_encryption).pack(side="left", padx=(0, 8))
        ttk.Button(items_btns, text="🗑 Remove Selected", style="Danger.TButton", command=self.remove_selected).pack(side="left")

        self.listbox = tk.Listbox(
            items_card,
            height=12,
            font=("Consolas", 10),
            bg=COLORS["bg_panel"],
            fg=COLORS["text_main"],
            selectbackground=COLORS["blue"],
            selectforeground="#ffffff",
            highlightthickness=0,
            relief="flat"
        )
        self.listbox.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.refresh_listbox()

        suspicious_card = ttk.Labelframe(left, text="Suspicious Files", style="Card.TLabelframe")
        suspicious_card.pack(fill="both", expand=True, pady=(0, 12))

        suspicious_btns = ttk.Frame(suspicious_card)
        suspicious_btns.pack(anchor="w", padx=12, pady=(12, 8))
        ttk.Button(suspicious_btns, text="🗑 Clear List", style="Danger.TButton", command=self.clear_suspicious).pack(side="left")

        self.suspicious_listbox = tk.Listbox(
            suspicious_card,
            height=8,
            font=("Consolas", 10),
            bg=COLORS["bg_panel"],
            fg=COLORS["text_main"],
            selectbackground=COLORS["red"],
            selectforeground="#ffffff",
            highlightthickness=0,
            relief="flat"
        )
        self.suspicious_listbox.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.refresh_suspicious_listbox()

        log_card = ttk.Labelframe(right, text="Activity Log", style="Card.TLabelframe")
        log_card.pack(fill="both", expand=True)

        self.logbox = tk.Text(
            log_card,
            height=26,
            wrap="word",
            font=("Consolas", 10),
            bg=COLORS["bg_panel"],
            fg=COLORS["text_main"],
            insertbackground=COLORS["text_main"],
            relief="flat",
            highlightthickness=0
        )
        self.logbox.pack(fill="both", expand=True, padx=12, pady=12)
        self.logbox.configure(state="disabled")

        self.logbox.tag_config("info", foreground=COLORS["text_main"])
        self.logbox.tag_config("success", foreground="#22c55e")
        self.logbox.tag_config("warning", foreground="#f59e0b")
        self.logbox.tag_config("danger", foreground="#ef4444")
        self.logbox.tag_config("highlight", foreground="#60a5fa")

        bottom = ttk.Frame(self)
        bottom.pack(fill="x", padx=18, pady=(0, 12))

        ttk.Button(bottom, text="Open Log File", style="Ghost.TButton", command=self.open_log_file).pack(side="right")
        ttk.Button(bottom, text="Clear Log View", style="Ghost.TButton", command=self.clear_log_view).pack(side="right", padx=(0, 8))

        self.ui_log("Application launched.", "highlight")
        if ML_MODEL is not None:
            self.ui_log("ML model loaded successfully.", "success")
        else:
            self.ui_log("ML model not found. Scanning will use heuristic/YARA only.", "warning")
        self.set_status_ready()

    def set_status(self, text, bg, fg):
        self.status_var.set(text)
        self.status_badge.configure(bg=bg, fg=fg)

    def set_status_ready(self):
        self.set_status("READY", COLORS["gray"], COLORS["blue_soft"])

    def set_status_monitoring(self):
        self.set_status("MONITORING", COLORS["blue"], COLORS["blue_soft"])

    def set_status_scanning(self):
        self.set_status("SCANNING", COLORS["orange"], COLORS["orange_soft"])

    def set_status_clean(self):
        self.set_status("SCAN CLEAN", COLORS["green"], COLORS["green_soft"])

    def set_status_threat(self):
        self.set_status("THREAT FOUND", COLORS["red"], COLORS["red_soft"])

    def set_status_stopped(self):
        self.set_status("STOPPED", COLORS["gray"], COLORS["gray_soft"])

    def set_status_usb_detected(self):
        self.set_status("USB DETECTED", COLORS["purple"], COLORS["purple_soft"])

    def ui_log(self, msg: str, level="info"):
        line = f"[{now_ts()}] {msg}\n"
        self.logbox.configure(state="normal")
        self.logbox.insert("end", line, level)
        self.logbox.see("end")
        self.logbox.configure(state="disabled")
        log_to_file(msg)

    def clear_log_view(self):
        self.logbox.configure(state="normal")
        self.logbox.delete("1.0", "end")
        self.logbox.configure(state="disabled")
        self.ui_log("Log view cleared.", "highlight")

    def open_log_file(self):
        try:
            if not os.path.exists(LOG_FILE):
                with open(LOG_FILE, "w", encoding="utf-8") as f:
                    f.write("")
            os.startfile(LOG_FILE)
        except Exception as e:
            messagebox.showerror("Error", f"Cannot open log file.\n\n{e}")

    def update_usb_view(self, usb_dict):
        if not usb_dict:
            self.usb_var.set("No USB storage detected.")
            return

        lines = []
        for drive, info in usb_dict.items():
            lines.append(f"{drive} | Label: {info['label']} | FS: {info['fs']} | Model: {info['model']}")
        self.usb_var.set("\n".join(lines))

    def initial_usb_scan(self):
        try:
            self.prev_usb = get_usb_storage_drives()
            self.update_usb_view(self.prev_usb)

            if self.prev_usb:
                self.set_status_usb_detected()
                first = next(iter(self.prev_usb.keys()))
                info = self.prev_usb[first]
                self.ui_log(f"Initial Scan: USB detected at {first} (Label={info['label']}).", "warning")
            else:
                self.set_status_stopped()
                self.ui_log("Initial Scan: No USB storage detected.", "info")
        except Exception as e:
            self.set_status_threat()
            self.ui_log(f"ERROR: Initial USB scan failed: {e}", "danger")

    def refresh_listbox(self):
        self.listbox.delete(0, "end")
        for item in self.items:
            mode = "ENCRYPTED" if item.get("encrypted", False) else "NORMAL"
            item_type = item.get("type", "file").upper()
            display = f"[{item_type}] [{mode}] {item.get('path', '')}"
            self.listbox.insert("end", display)

    def refresh_suspicious_listbox(self):
        self.suspicious_listbox.delete(0, "end")
        for item in self.suspicious_files:
            display = item["path"]
            self.suspicious_listbox.insert("end", display)

    def clear_suspicious(self):
        self.suspicious_files = []
        self.refresh_suspicious_listbox()
        self.ui_log("Suspicious files list cleared.", "highlight")

    def ask_encryption_choice(self):
        return messagebox.askyesno(
            "Encryption Option",
            "Do you want to enable encryption for this item?"
        )

    def add_file(self):
        path = filedialog.askopenfilename(title="Select a file to protect")
        if not path:
            return

        for item in self.items:
            if item.get("path") == path:
                messagebox.showinfo("Duplicate", "This file is already in the list.")
                return

        use_encryption = self.ask_encryption_choice()
        self.items.append({
            "path": path,
            "encrypted": use_encryption,
            "type": "file"
        })
        self.refresh_listbox()
        self.ui_log(f"Added file: {path} | encryption={use_encryption}", "highlight")

    def add_folder(self):
        path = filedialog.askdirectory(title="Select a folder to protect")
        if not path:
            return

        for item in self.items:
            if item.get("path") == path:
                messagebox.showinfo("Duplicate", "This folder is already in the list.")
                return

        use_encryption = self.ask_encryption_choice()
        self.items.append({
            "path": path,
            "encrypted": use_encryption,
            "type": "folder"
        })
        self.refresh_listbox()
        self.ui_log(f"Added folder: {path} | encryption={use_encryption}", "highlight")

    def toggle_selected_encryption(self):
        if not self.require_password("with encryption settings"):
            return

        sel = list(self.listbox.curselection())
        if not sel:
            messagebox.showinfo("Encryption", "Please select an item first.")
            return

        mapping = read_vault_map()

        for idx in sel:
            item = self.items[idx]
            path = item.get("path")
            current_state = item.get("encrypted", False)
            new_state = not current_state
            item_type = item.get("type", "file")

            item["encrypted"] = new_state

            if path in mapping:
                vault_info = mapping[path]
                vault_path = vault_info.get("vault_path", "")
                vault_encrypted = vault_info.get("encrypted", False)
                vault_type = vault_info.get("type", item_type)

                if os.path.exists(vault_path):
                    try:
                        if new_state and not vault_encrypted:
                            if vault_type == "folder":
                                new_vault_path = vault_path + ".enc"
                                encrypt_folder_to_archive(vault_path, new_vault_path)
                            else:
                                new_vault_path = vault_path + ".enc"
                                encrypt_file_to_path(vault_path, new_vault_path)

                            mapping[path]["vault_path"] = new_vault_path
                            mapping[path]["encrypted"] = True
                            self.ui_log(f"Encryption applied to vault item: {path}", "success")

                        elif not new_state and vault_encrypted:
                            if vault_path.endswith(".enc"):
                                new_vault_path = vault_path[:-4]
                            else:
                                new_vault_path = vault_path + "_decrypted"

                            if vault_type == "folder":
                                temp_folder = new_vault_path
                                decrypt_archive_to_folder(vault_path, temp_folder)
                                mapping[path]["vault_path"] = temp_folder
                            else:
                                decrypt_file_to_path(vault_path, new_vault_path)
                                mapping[path]["vault_path"] = new_vault_path

                            mapping[path]["encrypted"] = False
                            self.ui_log(f"Encryption removed from vault item: {path}", "warning")

                    except Exception as e:
                        self.ui_log(f"Failed to apply encryption change for {path}: {e}", "danger")
                        messagebox.showerror("Encryption Error", f"Failed to update encryption for:\n{path}\n\n{e}")

            self.ui_log(f"Encryption changed: {path} -> {new_state}", "warning")

        write_vault_map(mapping)
        save_protected_items(self.items)
        self.refresh_listbox()

    def remove_selected(self):
        sel = list(self.listbox.curselection())
        if not sel:
            messagebox.showinfo("Remove", "Please select an item to remove.")
            return

        for idx in reversed(sel):
            removed = self.items.pop(idx)
            self.ui_log(f"Removed: {removed.get('path')}", "danger")

        save_protected_items(self.items)
        self.refresh_listbox()

    def save_list(self):
        save_protected_items(self.items)
        self.ui_log("Protected items list saved.", "success")
        messagebox.showinfo("Saved", "Protected items saved successfully.")

    def manual_restore(self):
        if self.active_threat:
            messagebox.showwarning(
                "Restore Blocked",
                "Restore is blocked because an active USB threat was detected.\n\n"
                "Please remove the suspicious USB device before restoring protected files.",
                parent=self
            )
            self.ui_log("RESTORE BLOCKED: Active USB threat still detected.", "danger")
            return

        if not self.require_password("with restore"):
            return

        mapping_before = read_vault_map().copy()
        restored, failed = restore_items()

        if restored > 0:
            mapping_after = read_vault_map()
            restored_paths = []

            for orig_path in mapping_before.keys():
                if orig_path not in mapping_after:
                    restored_paths.append(orig_path)

            self.items = [item for item in self.items if item.get("path") not in restored_paths]
            save_protected_items(self.items)
            self.refresh_listbox()

        self.ui_log(
            f"Restore: restored {restored} item(s). Failed: {len(failed)}",
            "success" if restored > 0 else "warning"
        )
        messagebox.showinfo("Restore Result", f"Restored: {restored}\nFailed: {len(failed)}")

    def start_monitoring(self):
        if self.running:
            return

        self.running = True
        self.set_status_monitoring()
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")

        self.prev_usb = get_usb_storage_drives()
        self.update_usb_view(self.prev_usb)

        self.ui_log("USB monitoring started.", "highlight")
        self.thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.thread.start()

    def stop_monitoring(self):
        if not self.require_password("to stop monitoring"):
            return

        self.running = False
        self.set_status_stopped()
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.ui_log("USB monitoring stopped.", "warning")

    def monitor_loop(self):
        while self.running:
            time.sleep(1)
            try:
                current = get_usb_storage_drives()
            except Exception as e:
                self.after(0, lambda e=e: self.ui_log(f"ERROR: USB scan failed: {e}", "danger"))
                continue

            inserted = set(current.keys()) - set(self.prev_usb.keys())
            removed = set(self.prev_usb.keys()) - set(current.keys())

            for d in inserted:
                info = current[d]
                self.after(0, lambda d=d, info=info: self.handle_usb_inserted(d, info))

            for d in removed:
                self.after(0, lambda d=d: self.handle_usb_removed(d))

            self.prev_usb = current
            self.after(0, lambda cur=current: self.update_usb_view(cur))

    def handle_usb_inserted(self, drive, info):
        self.ui_log(f"USB INSERTED: {drive} | Label={info['label']} | Model={info['model']}", "warning")
        self.set_status_usb_detected()

        if self.items:
            moved, skipped = protect_items(self.items)
            level = "success" if moved > 0 else "warning"
            self.ui_log(f"AUTO PROTECT: moved {moved} item(s). Skipped/Failed: {len(skipped)}", level)
        else:
            self.ui_log("AUTO PROTECT: No protected items selected yet.", "warning")

        self.ui_log(f"AUTO SCAN: Starting scan on {drive}", "highlight")
        self.set_status_scanning()

        scan_thread = threading.Thread(target=self.run_scan_background, args=(drive,), daemon=True)
        scan_thread.start()

    def handle_usb_removed(self, drive):
        self.ui_log(f"USB REMOVED: {drive}", "info")
        self.active_threat = False
        self.ui_log("ACTIVE THREAT CLEARED: USB removed. Restore is now allowed.", "success")
        current_usb = get_usb_storage_drives()
        self.update_usb_view(current_usb)
        self.set_status_stopped()

    def run_scan_background(self, drive):
        result = scan_usb_drive(drive)
        self.after(0, lambda result=result: self.show_scan_result(result))

    def show_scan_result(self, result):
        scanned = result["scanned"]
        suspicious = result["suspicious"]
        quarantined = result["quarantined"]
        errors = result["errors"]
        drive = result["drive"]

        engine_parts = ["Heuristic"]
        if result["used_yara"]:
            engine_parts.append("YARA")
        if result["used_ml"]:
            engine_parts.append("ML")
        engine = " + ".join(engine_parts)

        self.ui_log(
            f"SCAN COMPLETE: {drive} | Engine={engine} | "
            f"Scanned={scanned} | Suspicious={len(suspicious)} | Quarantined={len(quarantined)}",
            "highlight"
        )

        if suspicious:
            self.set_status_threat()
            self.active_threat = True
            self.ui_log("ACTIVE THREAT ENABLED: Restore is blocked until USB is removed.", "danger")

            eject_success, eject_msg = eject_usb_drive(drive)
            self.ui_log(f"USB BLOCK ACTION: {eject_msg}", "warning" if eject_success else "danger")

            for item in suspicious:
                self.ui_log(f"SUSPICIOUS FILE: {item['path']}", "danger")
                for reason in item["reasons"]:
                    self.ui_log(f"  -> {reason}", "danger")

            for q in quarantined:
                self.ui_log(f"QUARANTINED: {q['original']} -> {q['quarantine']}", "danger")

            self.suspicious_files.extend(suspicious)
            self.refresh_suspicious_listbox()

            for err in errors[:10]:
                self.ui_log(f"SCAN ERROR: {err}", "warning")

            messagebox.showwarning(
                "Threat Detected - USB Blocked",
                f"Suspicious files were detected on {drive}.\n\n"
                f"Scanned: {scanned}\n"
                f"Suspicious: {len(suspicious)}\n"
                f"Quarantined: {len(quarantined)}\n\n"
                f"Security Action: USB device has been ejected to prevent further access."
            )
        else:
            self.set_status_clean()

            for err in errors[:10]:
                self.ui_log(f"SCAN ERROR: {err}", "warning")

            self.ui_log("No suspicious files found.", "success")
            messagebox.showinfo(
                "USB Scan Completed",
                f"USB scan finished successfully.\n\n"
                f"Drive: {drive}\n"
                f"Files Scanned: {scanned}\n"
                f"No suspicious files found."
            )
if __name__ == "__main__":
    if setup_or_verify_password():
        ensure_dirs()
        generate_key()
        load_ml_model()
        app = SmartLockApp()
        app.mainloop()
