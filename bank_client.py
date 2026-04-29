import time
import json
import hmac
import hashlib
import uuid
import requests

API_URL = "https://api-antifraude.onrender.com"

# Banque CHECK : Cofidis
API_KEY = "key_cofidis_check"
SIGN_SECRET = "sig_cofidis_secret"


def generate_signature(timestamp: str, body: dict) -> str:
    body_bytes = json.dumps(
        body,
        separators=(",", ":"),
        ensure_ascii=False
    ).encode("utf-8")

    message = timestamp.encode("utf-8") + b"." + body_bytes

    return hmac.new(
        SIGN_SECRET.encode("utf-8"),
        message,
        hashlib.sha256
    ).hexdigest()


def check_client(nom, prenom, date_naissance, code_postal):
    body = {
        "nom": nom,
        "prenom": prenom,
        "date_naissance": date_naissance,
        "code_postal": code_postal
    }

    timestamp = str(int(time.time()))
    signature = generate_signature(timestamp, body)

    headers = {
        "x-api-key": API_KEY,
        "x-timestamp": timestamp,
        "x-signature": signature,
        "x-idempotency-key": str(uuid.uuid4()),
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(
            f"{API_URL}/check",
            headers=headers,
            data=json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8"),
            timeout=10
        )

        print("Status code:", response.status_code)
        print("Response:", response.text)

    except Exception as e:
        print("ERREUR :", str(e))


check_client("Dupont", "Jean", "1990-01-01", "75000")
