from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

DB_PATH = str(DATA_DIR / "siem.db")
MODEL_PATH = str(DATA_DIR / "siem_isoforest.joblib")