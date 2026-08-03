from pathlib import Path
import firebase_admin
from firebase_admin import credentials, firestore

BASE_DIR = Path(__file__).resolve().parent.parent

cred = credentials.Certificate(BASE_DIR / "firebase-key.json")

if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)

db = firestore.client()