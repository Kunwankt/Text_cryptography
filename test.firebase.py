from firebase.firebase_config import db

doc = {
    "message": "Firebase Connected Successfully!",
    "project": "Text Encryption",
    "status": "Working"
}

db.collection("test").add(doc)

print("✅ Firebase Connected Successfully")