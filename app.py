import os
import time
import json
import hmac
import math
import hashlib
import secrets
import unicodedata
import psycopg2
from datetime import datetime
from fastapi import FastAPI, Header, HTTPException, Request
from collections import defaultdict

app = FastAPI()

# =========================
# ENV
# =========================

DATABASE_URL = os.getenv("DATABASE_URL")
K_MACHINE = int(os.getenv("K_MACHINE", "0"))

ADMIN_KEY_HASH = os.getenv("ADMIN_KEY_HASH")

PRICE_PER_CHECK = float(os.getenv("PRICE_PER_CHECK_EUR", "0.01"))

ALERT_HIGH_RATE_THRESHOLD = float(os.getenv("ALERT_HIGH_RATE_THRESHOLD", "0.5"))
ALERT_ERROR_RATE_THRESHOLD = float(os.getenv("ALERT_ERROR_RATE_THRESHOLD", "0.1"))

IP_ALLOWLIST_ENABLED = os.getenv("IP_ALLOWLIST_ENABLED", "false").lower() == "true"

# =========================
# BANQUES CONFIG
# =========================

BANKS = {
    "Domofinance": {
        "role": "ENR",
        "api_hash": os.getenv("KEY_DOMOFINANCE_HASH"),
        "sign_secret": os.getenv("SIGN_DOMOFINANCE"),
        "quota": int(os.getenv("MONTHLY_QUOTA_DOMOFINANCE", "100000")),
        "ips": []
    },
    "Projexio": {
        "role": "ENR",
        "api_hash": os.getenv("KEY_PROJEXIO_HASH"),
        "sign_secret": os.getenv("SIGN_PROJEXIO"),
        "quota": int(os.getenv("MONTHLY_QUOTA_PROJEXIO", "100000")),
        "ips": []
    },
    "Cofidis": {
        "role": "CHECK",
        "api_hash": os.getenv("KEY_COFIDIS_HASH"),
        "sign_secret": os.getenv("SIGN_COFIDIS"),
        "quota": int(os.getenv("MONTHLY_QUOTA_COFIDIS", "100000")),
        "ips": []
    },
    "Younited": {
        "role": "CHECK",
        "api_hash": os.getenv("KEY_YOUNITED_HASH"),
        "sign_secret": os.getenv("SIGN_YOUNITED"),
        "quota": int(os.getenv("MONTHLY_QUOTA_YOUNITED", "100000")),
        "ips": []
    }
}

# =========================
# HELPERS
# =========================

def sha256_text(x):
    return hashlib.sha256(x.encode()).hexdigest()

def find_bank(api_key):
    hashed = sha256_text(api_key)
    for name, b in BANKS.items():
        if b["api_hash"] == hashed:
            return name, b
    return None, None

# =========================
# AUTH
# =========================

def verify_api_key(x_api_key):
    if not x_api_key:
        raise HTTPException(401, "Missing API key")

    name, bank = find_bank(x_api_key)
    if not bank:
        raise HTTPException(401, "Invalid API key")

    return name, bank

def verify_admin(x_api_key):
    if sha256_text(x_api_key) != ADMIN_KEY_HASH:
        raise HTTPException(403, "Admin only")

# =========================
# SIGNATURE
# =========================

async def verify_signature(request, bank, timestamp, signature):
    if not timestamp or not signature:
        raise HTTPException(401, "Missing signature")

    if abs(time.time() - int(timestamp)) > 60:
        raise HTTPException(401, "Timestamp expired")

    body = await request.body()
    message = timestamp.encode() + b"." + body

    expected = hmac.new(
        bank["sign_secret"].encode(),
        message,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected, signature):
        raise HTTPException(401, "Bad signature")

# =========================
# DB
# =========================

def db():
    return psycopg2.connect(DATABASE_URL)

def init_db():
    conn = db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs(
        id SERIAL PRIMARY KEY,
        action TEXT,
        bank TEXT,
        result TEXT,
        created_at TIMESTAMP,
        prev_hash TEXT,
        current_hash TEXT
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS checks(
        id SERIAL PRIMARY KEY,
        bank TEXT,
        result TEXT,
        created_at TIMESTAMP
    );
    """)

    conn.commit()
    cur.close()
    conn.close()

@app.on_event("startup")
def startup():
    init_db()

# =========================
# AUDIT BLOCKCHAIN
# =========================

def last_hash():
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT current_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row[0] if row else "GENESIS"

def add_log(action, bank, result=None):
    prev = last_hash()
    payload = f"{prev}|{action}|{bank}|{result}|{datetime.now()}"
    curr = hashlib.sha256(payload.encode()).hexdigest()

    conn = db()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO audit_logs(action, bank, result, created_at, prev_hash, current_hash)
    VALUES (%s,%s,%s,%s,%s,%s)
    """, (action, bank, result, datetime.now(), prev, curr))

    conn.commit()
    cur.close()
    conn.close()

# =========================
# TOKEN
# =========================

P = 208351617316091241234326746312124448251235562226470491514186331217050270460481

def gen_token(data):
    h = int(hashlib.sha256(data.encode()).hexdigest(),16)%P
    return hashlib.sha256(str(pow(h,K_MACHINE,P)).encode()).hexdigest()

# =========================
# ROUTES
# =========================

@app.get("/status")
def status():
    return {
        "status": "ok",
        "security": "V2",
        "audit": "blockchain"
    }

@app.post("/generate-token")
async def generate(request: Request,
                   x_api_key: str = Header(None),
                   x_timestamp: str = Header(None),
                   x_signature: str = Header(None)):

    name, bank = verify_api_key(x_api_key)

    if bank["role"] != "ENR":
        raise HTTPException(403)

    await verify_signature(request, bank, x_timestamp, x_signature)

    data = await request.json()
    token = gen_token(json.dumps(data))

    return {"token": token}

@app.post("/deposit-token")
async def deposit(request: Request,
                  x_api_key: str = Header(None),
                  x_timestamp: str = Header(None),
                  x_signature: str = Header(None)):

    name, bank = verify_api_key(x_api_key)
    await verify_signature(request, bank, x_timestamp, x_signature)

    add_log("deposit", name)

    return {"status": "ok"}

@app.post("/check")
async def check(request: Request,
                x_api_key: str = Header(None),
                x_timestamp: str = Header(None),
                x_signature: str = Header(None)):

    name, bank = verify_api_key(x_api_key)

    if bank["role"] != "CHECK":
        raise HTTPException(403)

    await verify_signature(request, bank, x_timestamp, x_signature)

    data = await request.json()
    token = gen_token(json.dumps(data))

    result = "HIGH" if token else "LOW"

    add_log("check", name, result)

    return {"result": result}

@app.get("/admin/audit/verify")
def verify(x_api_key: str = Header(None)):
    verify_admin(x_api_key)

    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT action, bank, result, prev_hash, current_hash FROM audit_logs ORDER BY id ASC")
    rows = cur.fetchall()
    cur.close()
    conn.close()

    prev = "GENESIS"

    for r in rows:
        action, bank, result, p, c = r
        if p != prev:
            return {"valid": False}
        prev = c

    return {"valid": True, "logs": len(rows)}
# =========================
# V1 ROUTES (PRO BANK)
# =========================

@app.post("/v1/generate-token")
async def v1_generate_token(
    request: Request,
    x_api_key: str = Header(...),
    x_timestamp: str = Header(...),
    x_signature: str = Header(...)
):
    return await generate_token(request, x_api_key, x_timestamp, x_signature)


@app.post("/v1/deposit-token")
async def v1_deposit_token(
    request: Request,
    x_api_key: str = Header(...),
    x_timestamp: str = Header(...),
    x_signature: str = Header(...),
    x_idempotency_key: str = Header(...)
):
    return await deposit_token(request, x_api_key, x_timestamp, x_signature, x_idempotency_key)


@app.post("/v1/check")
async def v1_check(
    request: Request,
    x_api_key: str = Header(...),
    x_timestamp: str = Header(...),
    x_signature: str = Header(...),
    x_idempotency_key: str = Header(...)
):
    return await check(request, x_api_key, x_timestamp, x_signature, x_idempotency_key)
