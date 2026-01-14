# AI-Based Malicious URL Detection System

Student-friendly, presentation-ready project using **Lexical Feature Extraction** + **Random Forest**.

This version runs as a professional, standalone-style interactive tool (good for compiling into a single `.exe`).

## What you need

- Python 3.10+ recommended
- Install dependencies:

```bash
pip install -r requirements.txt
```

## Dataset (CSV)

Use any malicious URL CSV (for example from Kaggle). Common formats:

- Columns: `url` and `label` (0/1)
- Columns: `url` and `type` (benign/phishing/malware/...)

Place your CSV in the `data/` folder, for example:

- `data/malicious_url.csv`

If your CSV uses different column names, pass them as arguments.

## Run (standalone mode)

```bash
python src/malicious_url_detection.py
```

On first run, the tool will:

- Look for `data/malicious_url.csv` (or fall back to `data/sample_urls.csv`)
- Train a model and cache it in your user profile (so future runs load instantly)
- Start a loop so you can paste URLs one-by-one

Optional (recommended for class demos): print the required Precision/Recall/F1 report during training:

```bash
python src/malicious_url_detection.py --evaluate
```

If your dataset uses different column names, you can point directly to your CSV:

```bash
python src/malicious_url_detection.py --csv data/malicious_url.csv --evaluate
```

## Live mitigation demo

After training, the script prompts you to paste a URL and it outputs:

- `Safe` or `Malicious`
- a confidence score
- a **defanged** version of the URL (safe for reports)

## Build a single-file EXE (Windows)

1. Install PyInstaller:

```bash
pip install pyinstaller
```

2. Clean build output (recommended):

PowerShell:

```powershell
Remove-Item -Recurse -Force .\build, .\dist -ErrorAction SilentlyContinue
Remove-Item -Force .\MaliciousURLDetector.spec -ErrorAction SilentlyContinue
```

CMD:

```bat
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist MaliciousURLDetector.spec del /q MaliciousURLDetector.spec
```

3. Build one-file executable (console mode; required so Rich displays):

```bash
pyinstaller --onefile --name MaliciousURLDetector --add-data "data;data" src\\malicious_url_detection.py
```

PyInstaller outputs to `dist/MaliciousURLDetector.exe`.

If I want to submit just one file (no folder), I copy it to the project root:

```powershell
Copy-Item -Force .\dist\MaliciousURLDetector.exe .\MaliciousURLDetector.exe
```

Optional: hide the console window (NOT recommended for this project because the Rich dashboard needs a console):

```bash
pyinstaller --onefile --noconsole --name MaliciousURLDetector --add-data "data;data" src\\malicious_url_detection.py
```

## Notes

- The model is trained on lexical features only (length, dots, hyphens, digits, suspicious keywords, etc.).
- This is for academic/demo use; real deployments should combine ML with threat intel and sandboxing.
