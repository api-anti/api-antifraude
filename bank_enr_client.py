import time
import json
import hmac
import hashlib
import uuid
import requests

API_URL = "https://api.antifraude-api.com"

# Banque ENR : Domofinance
API_KEY = "key_domofinance_enr"
SIGN_SECRET = "sig_domofinance_secret"

# Cloudflare Service Token
CF_CLIENT_ID = "COLLE_ICI_TON_CLIENT_ID"
CF_CLIENT_SECRET = "COLLE_ICI_TON_CLIENT_SECRET"


def sign(timestamp, body):
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


def generate_token(nom, prenom, dn, cp):
    body = {
        "nom": nom,
        "prenom": prenom,
        "date_naissance": dn,
        "code_postal": cp
    }

    timestamp = str(int(time.time()))
    signature = sign(timestamp, body)

    headers = {
        "CF-Access-Client-Id": CF_CLIENT_ID,
        "CF-Access-Client-Secret": CF_CLIENT_SECRET,
        "x-api-key": API_KEY,
        "x-timestamp": timestamp,
        "x-signature": signature,
        "Content-Type": "application/json"
    }

    res = requests.post(
        f"{API_URL}/generate-token",
        headers=headers,
        data=json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8"),
        timeout=10
    )

    print("GENERATE STATUS:", res.status_code)
    print("GENERATE RESPONSE:", res.text)

    data = res.json()

    if "token" not in data:
        raise Exception("La route /generate-token ne renvoie pas token")

    return data["token"]


def deposit_token(token):
    body = {
        "token": token
    }

    timestamp = str(int(time.time()))
    signature = sign(timestamp, body)

    headers = {
        "CF-Access-Client-Id": CF_CLIENT_ID,
        "CF-Access-Client-Secret": CF_CLIENT_SECRET,
        "x-api-key": API_KEY,
        "x-timestamp": timestamp,
        "x-signature": signature,
        "x-idempotency-key": str(uuid.uuid4()),
        "Content-Type": "application/json"
    }

    res = requests.post(
        f"{API_URL}/deposit-token",
        headers=headers,
        data=json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8"),
        timeout=10
    )

    print("DEPOSIT STATUS:", res.status_code)
    print("DEPOSIT RESPONSE:", res.text)


token = generate_token("Dupont", "Jean", "1990-01-01", "75000")
deposit_token(token)
