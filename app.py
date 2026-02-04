import os
import time
import json
import asyncio
import logging
from datetime import datetime, timedelta, timezone
from collections import deque, defaultdict
from typing import Dict, Optional

import pyotp
import requests
from fastapi import FastAPI

# Official Kotak Neo SDK
from neo_api_client import NeoAPI

# -------------------------------------------------------
# CONFIG (ENV)
# -------------------------------------------------------

IST = timezone(timedelta(hours=5, minutes=30))

LOOKBACK_MIN = int(os.getenv("LOOKBACK_MIN", "5"))
UNDER_MOVE_PCT = float(os.getenv("UNDER_MOVE_PCT", "0.20"))
OPT_STALE_PCT = float(os.getenv("OPT_STALE_PCT", "0.10"))
TOP_K = int(os.getenv("TOP_K", "5"))
RUN_INTERVAL_S = int(os.getenv("RUN_INTERVAL_S", "60"))
SILENCE_MIN = int(os.getenv("ALERT_SILENCE_MIN", "5"))

TT_WEBHOOK_URL = os.getenv("TT_WEBHOOK_URL")
TT_API_TOKEN = os.getenv("TT_API_TOKEN")

# Kotak Neo official fields (from SDK documentation)
NEO_MOBILE = os.getenv("NEO_MOBILE")
NEO_PASSWORD = os.getenv("NEO_PASSWORD")
NEO_TOTP_SECRET = os.getenv("NEO_TOTP_SECRET")
NEO_CONSUMER_KEY = os.getenv("NEO_CONSUMER_KEY")

# -------------------------------------------------------
# GLOBALS
# -------------------------------------------------------

app = FastAPI()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger("goldm")

under_buf: deque = deque(maxlen=3600)
hist: Dict[str, deque] = defaultdict(lambda: deque(maxlen=3600))
last_alert_ts: Optional[datetime] = None

# global API client
client: Optional[NeoAPI] = None

# -------------------------------------------------------
# HELPERS
# -------------------------------------------------------

def normalize_base32(raw: str) -> str:
    """Normalize secret to valid base32."""
    import re, base64
    if not raw:
        raise ValueError("Empty TOTP secret")
    s = re.sub(r"[^A-Za-z2-7]", "", raw).upper()
    pad = (8 - (len(s) % 8)) % 8
    s = s + ("=" * pad)
    base64.b32decode(s, casefold=True)  # validate
    return s

def pct_change(buf: deque, m: int) -> Optional[float]:
    if len(buf) < 2:
        return None
    cutoff = time.time() - m * 60
    while buf and buf[0][0] < cutoff:
        buf.popleft()
    if len(buf) < 2:
        return None
    t0, p0 = buf[0]
    t1, p1 = buf[-1]
    if p0 is None or p1 is None:
        return None
    return 100.0 * (p1 - p0) / p0

def should_alert(u, ce, pe):
    if u is None or ce is None or pe is None:
        return False
    return (
        abs(u) >= UNDER_MOVE_PCT
        and abs(ce) <= OPT_STALE_PCT
        and abs(pe) <= OPT_STALE_PCT
    )

def post_tradetron(payload: dict):
    if not TT_WEBHOOK_URL or not TT_API_TOKEN:
        log.info("Tradetron not configured.")
        return

    data = {"key": TT_API_TOKEN, **payload}
    try:
        r = requests.post(TT_WEBHOOK_URL, json=data, timeout=5)
        log.info(f"Tradetron status={r.status_code}")
    except Exception as e:
        log.error(f"TT error: {e}")

# -------------------------------------------------------
# KOTAK LOGIN (OFFICIAL)
# -------------------------------------------------------

def kotak_login():
    global client

    if not all([NEO_MOBILE, NEO_PASSWORD, NEO_TOTP_SECRET, NEO_CONSUMER_KEY]):
        raise RuntimeError("Missing Kotak Neo credentials.")

    client = NeoAPI(
        environment="prod",
        consumer_key=NEO_CONSUMER_KEY,
        access_token=None,
        neo_fin_key=None
    )

    # Step 1: login to generate OTP
    client.login(
        mobilenumber=NEO_MOBILE,
        password=NEO_PASSWORD
    )

    # Step 2: TOTP → session_2fa
    secret = normalize_base32(NEO_TOTP_SECRET)
    code = pyotp.TOTP(secret).now()
    client.session_2fa(OTP=code)

    log.info("Kotak Neo login successful.")

# -------------------------------------------------------
# ENGINE LOOP
# -------------------------------------------------------

async def engine_loop():
    global last_alert_ts, client

    while True:
        try:
            if client is None:
                kotak_login()
        except Exception as e:
            log.error(f"Login error: {e}")
            await asyncio.sleep(30)
            continue

        # Collect underlying price (example: GOLDM-FUT — adjust as needed)
        try:
            # The official docs list quotes endpoints, but not OC.  [1](https://learn.tradetron.tech/p/tttv)
            # SDK’s fetch for live data uses quote API internally.
            q = client.quotes(["GOLDM"])
            ltp = None
            if isinstance(q, list) and q:
                ltp = q[0].get("last_price") or q[0].get("ltp")
            if ltp is not None:
                under_buf.append((time.time(), float(ltp)))
        except Exception as e:
            log.error(f"Underlying fetch error: {e}")

        # -------------------------------------------
        # Option chain NOT supported via public REST.
        # (Official docs list no OC endpoint.) [1](https://learn.tradetron.tech/p/tttv)[4](https://www.kotakneo.com/investing-guide/trading-account/kotak-neo-trade-api-guide/)
        # Placeholder: user must implement websockets or instrument-file based logic.
        # -------------------------------------------

        ce_pct = None
        pe_pct = None
        u_pct = pct_change(under_buf, LOOKBACK_MIN)

        # Logging only
        log.info(f"U%={u_pct} CE%={ce_pct} PE%={pe_pct} (Option chain placeholder)")

        # Alerts only work when CE/PE signals exist
        if ce_pct and pe_pct and should_alert(u_pct, ce_pct, pe_pct):
            now = datetime.now(IST)
            if last_alert_ts is None or now - last_alert_ts >= timedelta(minutes=SILENCE_MIN):
                payload = {
                    "event": "goldm_non_responsive",
                    "u_pct": u_pct,
                    "ce_pct": ce_pct,
                    "pe_pct": pe_pct,
                    "ts": now.isoformat(),
                }
                post_tradetron(payload)
                last_alert_ts = now

        await asyncio.sleep(RUN_INTERVAL_S)

# -------------------------------------------------------
# FASTAPI ROUTES
# -------------------------------------------------------

@app.on_event("startup")
async def startup():
    asyncio.create_task(engine_loop())

@app.get("/")
def root():
    return {"service": "goldm-premium-guard", "health": "/health"}

@app.get("/health")
def health():
    return {"ok": True, "time": datetime.now(IST).isoformat()}

@app.get("/totp")
def get_totp():
    try:
        secret = normalize_base32(NEO_TOTP_SECRET)
        return {"totp": pyotp.TOTP(secret).now()}
    except Exception as e:
        return {"error": str(e)}

@app.get("/login/test")
def login_test():
    try:
        kotak_login()
        return {"login_ok": True}
    except Exception as e:
        return {"login_ok": False, "error": str(e)}