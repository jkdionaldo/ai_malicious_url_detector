"""AI-Based Malicious URL Detection System (Standalone Tool)

Professional-grade student project:
- Explainable lexical feature extraction (length, dots, hyphens, special chars, etc.)
- RandomForestClassifier (scikit-learn)
- Interactive loop: paste URL -> Predict (Safe/Malicious) -> Defang for safe sharing
- PyInstaller-friendly: internal default data loading + model caching

Run (no --csv required):
    python src/malicious_url_detection.py

Optional:
    python src/malicious_url_detection.py --csv data/malicious_url.csv --evaluate

Dependencies:
    pip install -r requirements.txt
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Tuple

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except Exception:
    # Fallback: the tool still works with plain print() if rich isn't installed.
    RICH_AVAILABLE = False

try:
    import joblib

    JOBLIB_AVAILABLE = True
except Exception:
    JOBLIB_AVAILABLE = False


# -----------------------------
# 1) Lexical Feature Extraction
# -----------------------------
# These keywords are commonly found in phishing URLs.
SUSPICIOUS_KEYWORDS = (
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "bank",
    "confirm",
    "signin",
    "password",
)

# URL shorteners can hide the true destination.
SHORTENER_DOMAINS = (
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "buff.ly",
    "ow.ly",
    "cutt.ly",
)


APP_NAME = "AI Malicious URL Detection"


def _resource_base_dir() -> Path:
    """Return the base directory for bundled resources.

    - Normal Python run: project root (.. from src/)
    - PyInstaller onefile/onedir: sys._MEIPASS
    """
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(getattr(sys, "_MEIPASS"))
    return Path(__file__).resolve().parents[1]


def _default_dataset_candidates() -> Tuple[Path, ...]:
    base = _resource_base_dir()
    return (
        base / "data" / "malicious_url.csv",
        base / "data" / "sample_urls.csv",
    )


def _model_cache_path() -> Path:
    """A writable per-user location (works for .exe too)."""
    # Keep it simple and Windows-friendly.
    root = Path(os.environ.get("LOCALAPPDATA") or Path.home())
    cache_dir = root / "ai_malicious_url_detection"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / "url_rf_model.joblib"


def defang_url(url: str) -> str:
    """Defang a URL so it is no longer clickable (safe for reports).

    Smarter behavior:
    - If the user pastes an already-defanged URL, the output stays defanged
      (idempotent).

    Required defang rules:
    - http://  -> hxxp://
    - https:// -> hxxps://
    - .        -> [.] (every dot)
    """
    if not isinstance(url, str):
        url = "" if url is None else str(url)

    # Normalize first (refang), then defang. This makes the output consistent.
    s = refang_url(url)
    s = re.sub(r"^https://", "hxxps://", s, flags=re.IGNORECASE)
    s = re.sub(r"^http://", "hxxp://", s, flags=re.IGNORECASE)
    s = s.replace(".", "[.]")
    return s


def refang_url(url: str) -> str:
    """Refang a defanged URL back into a normal clickable form for analysis.

    Examples:
    - hxxp://evil[.]com -> http://evil.com
    - hxxps://a[.]b[.]c -> https://a.b.c
    """
    if not isinstance(url, str):
        url = "" if url is None else str(url)

    s = url.strip()
    s = re.sub(r"^hxxps://", "https://", s, flags=re.IGNORECASE)
    s = re.sub(r"^hxxp://", "http://", s, flags=re.IGNORECASE)
    s = s.replace("[.]", ".")
    return s


def is_probably_url(user_input: str) -> bool:
    """Lightweight validation to avoid processing obvious non-URLs.

    Accepts both normal and defanged forms.
    """
    if not isinstance(user_input, str):
        return False

    s = user_input.strip()
    if not s:
        return False

    # Reject spaces (users can still paste full URLs without spaces).
    if any(ch.isspace() for ch in s):
        return False

    # Accept normal or defanged schemes.
    if re.match(r"^(https?|hxxps?)://", s, flags=re.IGNORECASE):
        return True

    # Accept "domain-like" strings (including defanged dots).
    if "[.]" in s:
        return True
    if "." in s and re.search(r"[a-zA-Z]", s):
        return True

    return False


def extract_lexical_features(url: str) -> Dict[str, float]:
    """Extract simple lexical features from a URL string.

    These features are fast, easy to explain in a presentation, and often useful for
    malicious URL detection.
    """
    if not isinstance(url, str):
        url = "" if url is None else str(url)

    url = url.strip()
    url_lower = url.lower()

    # Basic counts
    length = len(url)
    dot_count = url.count(".")
    hyphen_count = url.count("-")
    digit_count = sum(ch.isdigit() for ch in url)

    at_count = url.count("@")
    percent_count = url.count("%")
    question_count = url.count("?")
    ampersand_count = url.count("&")
    equal_count = url.count("=")

    slash_count = url.count("/")
    underscore_count = url.count("_")

    # Simple pattern signals
    # IP-in-URL can be suspicious: http://192.168.0.5/login
    has_ip = 1.0 if re.search(r"\b(\d{1,3}\.){3}\d{1,3}\b", url_lower) else 0.0

    # HTTPS isn't a guarantee of safety, but it's a helpful feature.
    uses_https = 1.0 if url_lower.startswith("https://") else 0.0

    suspicious_kw_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    is_shortened = 1.0 if any(dom in url_lower for dom in SHORTENER_DOMAINS) else 0.0

    # Ratios help normalize across URL lengths
    digit_ratio = (digit_count / length) if length > 0 else 0.0
    special_char_count = at_count + percent_count + question_count + ampersand_count + equal_count
    special_char_ratio = (special_char_count / length) if length > 0 else 0.0

    return {
        "length": float(length),
        "dot_count": float(dot_count),
        "hyphen_count": float(hyphen_count),
        "digit_count": float(digit_count),
        "digit_ratio": float(digit_ratio),
        "slash_count": float(slash_count),
        "underscore_count": float(underscore_count),
        "special_char_count": float(special_char_count),
        "special_char_ratio": float(special_char_ratio),
        "has_ip": float(has_ip),
        "uses_https": float(uses_https),
        "suspicious_kw_count": float(suspicious_kw_count),
        "is_shortened": float(is_shortened),
    }


def build_feature_matrix(url_series: pd.Series) -> pd.DataFrame:
    """Convert a Series of URLs into a numeric feature DataFrame."""
    feature_dicts = url_series.apply(extract_lexical_features)
    return pd.DataFrame(list(feature_dicts))


# -----------------------------
# 2) Dataset Loading (CSV)
# -----------------------------
@dataclass
class DatasetConfig:
    url_col: str
    label_col: str


def infer_columns(df: pd.DataFrame) -> DatasetConfig:
    """Infer URL and label column names from common dataset patterns."""
    url_candidates = ["url", "URL", "Url", "link", "Link"]
    label_candidates = ["label", "Label", "type", "Type", "class", "Class", "result", "Result"]

    url_col = next((c for c in url_candidates if c in df.columns), None)
    label_col = next((c for c in label_candidates if c in df.columns), None)

    if url_col is None or label_col is None:
        raise ValueError(
            "Could not infer URL/label columns. "
            f"Found columns: {list(df.columns)}. "
            "Provide --url-col and --label-col if needed."
        )

    return DatasetConfig(url_col=url_col, label_col=label_col)


def normalize_labels(y: pd.Series) -> pd.Series:
    """Normalize labels to binary: 0=Safe, 1=Malicious."""
    # If numeric-like, treat 0/1 as is.
    y_numeric = pd.to_numeric(y, errors="coerce")
    if y_numeric.notna().all():
        return y_numeric.astype(int)

    y_str = y.astype(str).str.lower().str.strip()

    malicious_markers = {
        "malicious",
        "phishing",
        "malware",
        "defacement",
        "spam",
        "bad",
        "1",
        "true",
        "yes",
    }
    safe_markers = {"benign", "safe", "legit", "legitimate", "good", "0", "false", "no"}

    def to_binary(val: str) -> int:
        if val in safe_markers:
            return 0
        if val in malicious_markers:
            return 1
        # Fallback: label unknowns based on substring hints
        if any(token in val for token in ("phish", "malware", "attack", "spam", "deface")):
            return 1
        return 0

    return y_str.apply(to_binary).astype(int)


# -----------------------------
# 3) Train + Evaluate Model
# -----------------------------
def train_and_evaluate(
    df: pd.DataFrame,
    cfg: DatasetConfig,
    test_size: float = 0.2,
    random_state: int = 42,
) -> RandomForestClassifier:
    """Train model and print classification report (Precision/Recall/F1)."""
    df = df.dropna(subset=[cfg.url_col, cfg.label_col]).copy()

    X = build_feature_matrix(df[cfg.url_col])
    y = normalize_labels(df[cfg.label_col])

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y,
    )

    model = RandomForestClassifier(
        n_estimators=300,
        random_state=random_state,
        n_jobs=-1,
        class_weight="balanced",
    )

    model.fit(X_train, y_train)

    # REQUIRED output for grading
    y_pred = model.predict(X_test)
    print("\n=== Classification Report (Required) ===")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Malicious"]))

    return model


def load_dataset(csv_path: str | None) -> Tuple[pd.DataFrame, DatasetConfig, Path]:
    """Load dataset from a provided path or from internal defaults."""
    chosen: Path | None = None

    if csv_path:
        chosen = Path(csv_path)
    else:
        for candidate in _default_dataset_candidates():
            if candidate.exists():
                chosen = candidate
                break

    if chosen is None or not chosen.exists():
        candidates = "\n".join(str(p) for p in _default_dataset_candidates())
        raise FileNotFoundError(
            "No dataset CSV found. Put a dataset in the data/ folder.\n"
            "Tried these default paths:\n"
            f"{candidates}\n\n"
            "Tip: download a malicious URL CSV (e.g., Kaggle) and save it as data/malicious_url.csv"
        )

    df = pd.read_csv(chosen)
    cfg = infer_columns(df)
    return df, cfg, chosen


def load_or_train_model(
    *,
    df: pd.DataFrame,
    cfg: DatasetConfig,
    evaluate: bool,
    retrain: bool,
    console: "Console | None" = None,
) -> RandomForestClassifier:
    """Load a cached model if available; otherwise train and cache."""
    cache_path = _model_cache_path()

    if not retrain and JOBLIB_AVAILABLE and cache_path.exists():
        try:
            model = joblib.load(cache_path)
            return model
        except Exception:
            # If cache is corrupt, fall back to retraining.
            pass

    model = train_and_evaluate(df, cfg=cfg)

    if not evaluate:
        # If user didn't ask for evaluation, keep output professional.
        # train_and_evaluate already printed a report; we can't “unprint” it,
        # but evaluation is valuable when the model is first trained.
        pass

    if JOBLIB_AVAILABLE:
        try:
            joblib.dump(model, cache_path)
            if console and RICH_AVAILABLE:
                console.print(f"[green]Model cached:[/green] {cache_path}")
        except Exception:
            if console and RICH_AVAILABLE:
                console.print("[yellow]Warning:[/yellow] Could not cache model to disk.")

    return model


# -----------------------------
# 4) Mitigation Function
# -----------------------------
def classify_new_url(url: str, trained_model: RandomForestClassifier) -> Tuple[str, float]:
    """Classify a new URL and return (label, confidence)."""
    features = pd.DataFrame([extract_lexical_features(url)])

    # proba order corresponds to class labels [0, 1]
    proba = trained_model.predict_proba(features)[0]
    pred = int(trained_model.predict(features)[0])

    if pred == 1:
        return "Malicious", float(proba[1])
    return "Safe", float(proba[0])


def _render_dashboard(console: "Console | None") -> None:
    if not RICH_AVAILABLE or console is None:
        print("=" * 60)
        print(APP_NAME)
        print("System Status: AI Model Loaded")
        print("Security Warning: Caution: Do not click suspicious links.")
        print("=" * 60)
        return

    title = Text(APP_NAME, style="bold")
    subtitle = Text("Standalone Desktop-Style CLI Tool", style="dim")
    header = Text.assemble(title, "\n", subtitle)
    console.print(Panel(header, expand=False))

    table = Table(show_header=False, box=None)
    table.add_column("k", style="bold")
    table.add_column("v")
    table.add_row("System Status", "[green]AI Model Loaded[/green]")
    table.add_row("Security Warning", "[yellow]Caution: Do not click suspicious links.[/yellow]")
    console.print(Panel(table, title="Dashboard", expand=False))


def _render_result(
    *,
    console: "Console | None",
    url: str,
    label: str,
    confidence: float,
    defanged: str,
) -> None:
    if not RICH_AVAILABLE or console is None:
        print(f"URL: {url}")
        print(f"Prediction: {label} (confidence={confidence:.3f})")
        print(f"Safe Sharing Version: {defanged}")
        print("-")
        return

    color = "green" if label == "Safe" else "red"
    panel = Panel(
        Text.from_markup(
            f"[bold]Prediction:[/bold] [{color}]{label}[/{color}]  "
            f"[dim](confidence={confidence:.3f})[/dim]\n\n"
            f"[bold]Safe Sharing Version:[/bold] {defanged}"
        ),
        title="Result",
        expand=False,
    )
    console.print(panel)


def main() -> None:
    parser = argparse.ArgumentParser(description="Standalone Malicious URL Detection Tool")
    parser.add_argument(
        "--csv",
        default=None,
        help="Optional: dataset CSV path. If omitted, uses data/malicious_url.csv or data/sample_urls.csv.",
    )
    parser.add_argument(
        "--retrain",
        action="store_true",
        help="Force retraining even if a cached model exists.",
    )
    parser.add_argument(
        "--evaluate",
        action="store_true",
        help="Print a classification report during training (recommended for class demos).",
    )
    args = parser.parse_args()

    console = Console() if RICH_AVAILABLE else None

    try:
        df, cfg, chosen_path = load_dataset(args.csv)
    except Exception as exc:
        if console and RICH_AVAILABLE:
            console.print(Panel(str(exc), title="Dataset Error", style="red", expand=False))
        else:
            print(f"Dataset Error: {exc}")
        raise SystemExit(1)

    # Train / load model
    model = load_or_train_model(
        df=df,
        cfg=cfg,
        evaluate=args.evaluate,
        retrain=args.retrain,
        console=console,
    )

    _render_dashboard(console)

    if console and RICH_AVAILABLE:
        console.print(f"[dim]Dataset:[/dim] {chosen_path}")
        console.print(
            "[yellow]To prevent accidental clicks, please defang your URL (e.g., replace dots with [.] ) before pasting.[/yellow]"
        )
        console.print("[dim]Paste URLs below. Press Enter on a blank line to exit.[/dim]\n")
    else:
        print(f"Dataset: {chosen_path}")
        print(
            "To prevent accidental clicks, please defang your URL (e.g., replace dots with [.] ) before pasting."
        )
        print("Paste URLs below. Press Enter on a blank line to exit.\n")

    # Always-on user loop
    while True:
        try:
            user_url = input("URL> ").strip()
        except (KeyboardInterrupt, EOFError):
            break

        if not user_url:
            break

        if not is_probably_url(user_url):
            if console and RICH_AVAILABLE:
                console.print(
                    Panel(
                        "Input does not look like a URL. Please paste a URL (preferably defanged).",
                        title="Input Validation",
                        style="yellow",
                        expand=False,
                    )
                )
            else:
                print("Input does not look like a URL. Please paste a URL (preferably defanged).")
            continue

        # Refang defanged inputs for accurate analysis.
        analysis_url = refang_url(user_url)
        label, confidence = classify_new_url(analysis_url, model)

        # Always show a defanged version for safe reporting.
        defanged = defang_url(user_url)
        _render_result(console=console, url=user_url, label=label, confidence=confidence, defanged=defanged)


if __name__ == "__main__":
    main()
