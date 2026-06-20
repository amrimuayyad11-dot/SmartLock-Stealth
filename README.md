# SmartLock Stealth

Advanced Windows USB protector with automatic file protection, malware scanning (YARA + EMBER ML), and stealth vault/quarantine.

![SmartLock Stealth UI](https://via.placeholder.com/800x400/0b1220/e5e7eb?text=SmartLock+Stealth)

## Features
- **Real-time USB detection** using WMI
- **Auto-protect** user-specified files/folders to hidden vault on USB insertion
- **Multi-engine malware scan**: Heuristics + YARA rules + EMBER machine learning
- **Auto-quarantine** suspicious files
- **Stealth hidden directories** (attrib +h)
- **Modern Tkinter GUI**
- **One-click EXE build** with PyInstaller

## Prerequisites
- **Windows 10/11** (WMI required)
- **Python 3.8+**
- [Microsoft Visual C++ 14.0+ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) (for pywin32 compilation)

## Installation ✅ FIXED

1. **Create & activate virtual environment** (recommended):
   ```cmd
   cd c:\Users\USER\FYP1
   python -m venv venv
   venv\Scripts\activate
   ```

2. **Upgrade pip**:
   ```cmd
   python -m pip install --upgrade pip
   ```

3. **Install dependencies**:
   ```cmd
   pip install -r requirements.txt
   ```

4. **Verify WMI** (critical for USB detection):
   ```cmd
   python -c "import wmi; print('WMI OK')"
   ```

## Quick Start
```cmd
# Run GUI
python SmartLockStealth.py

# Build standalone EXE
pyinstaller SmartLockStealth.spec
```

## Usage
1. Launch `SmartLockStealth.py`
2. Add files/folders to protect list
3. Click **Start Monitoring**
4. Insert USB → Auto-protect + Auto-scan happens!

**Engines status shown in GUI** (YARA/EMBER optional).

## Protected Items
- Edit `protected_items.txt` manually
- Files moved to `%APPDATA%\SmartLockStealthVault\` (hidden)
- Restore via GUI button

## Scanning
- **Heuristics**: Suspicious names/exts/keywords
- **YARA**: `malware_rules.yar`
- **EMBER ML**: PE malware classifier (`ember_model_2018.txt`)
- **Quarantine**: `%APPDATA%\SmartLockStealthQuarantine\`

## Files
```
SmartLockStealth.py     # Main GUI app
requirements.txt        # Dependencies (fixed)
malware_rules.yar       # YARA signatures
train_ember_model.py    # Train EMBER model
ember_model_2018.txt    # Pre-trained model (generate with train_ember_model.py)
SmartLockStealth.spec   # PyInstaller config
```

## Troubleshooting
- **pywin32 error**: Install [VC++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
- **No USB detection**: Run as Administrator; check WMI service
- **EMBER missing**: `pip install ember lightgbm`
- **YARA error**: `pip install yara-python`
- Logs: `smartlock_events.log`

## Build EXE
```cmd
pip install pyinstaller
pyinstaller SmartLockStealth.spec
```

Enjoy secure USB handling! 🔒

