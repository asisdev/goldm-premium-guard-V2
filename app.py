import os, time, json, asyncio, logging, base64, re
from collections import deque, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import requests
import pyotp
from fastapi import FastAPI

# ─────────────────────────────────────────────────────────────────────────────
# Config (ENV)
# ─────────────────────────────────────────────────────────────────────────────
IST = timezone(timedelta(hours=5, minutes=30))

# Strategy knobs
LOOKBACK_MIN   = int(os.getenv("LOOKBACK_MIN", "5"))
UNDER_MOVE_PCT = float(os.getenv("UNDER_MOVE_PCT", "0.20"))
OPT_STALE_PCT  = float(os.getenv("OPT_STALE_PCT",  "0.10"))
RUN_INTERVAL_S = int(os.getenv("RUN_INTERVAL_S", "60"))
TOP_K          = int(os.getenv("TOP_K", "5"))
SILENCE_MIN    = int(os.getenv("ALERT_SILENCE_MIN", "5"))

# Tradetron
TT_WEBHOOK_URL = os.getenv("TT_WEBHOOK_URL")
TT_API_TOKEN   = os.getenv("TT_API_TOKEN")

# Kotak v2 login — your identity & tokens (same set you use in Tradetron)
NEO_MOBILE       = os.getenv("NEO_MOBILE")        # e.g., 9434895910
NEO_PASSWORD     = os.getenv("NEO_PASSWORD")      # trading login password
NEO_TOTP_SECRET  = os.getenv("NEO_TOTP_SECRET")   # base32 secret (NOT the 6-digit code)
NEO_CLIENT_CODE  = os.getenv("NEO_CLIENT_CODE")   # UCC / client code (e.g., YNINF)
NEO_MPIN         = os.getenv("NEO_MPIN")          # 6-digit MPIN
NEO_ACCESS_TOKEN = os.getenv("NEO_ACCESS_TOKEN")  # token copied from API Dashboard

# Fixed v2 endpoints (from migration guide) for login + validate
# Keep editable: some tenants front these via different hosts.
NEO_TOTP_LOGIN_URL = os.getenv(
    "NEO_TOTP_LOGIN_URL",
    "https://mis.kotaksecurities.com/login/1.0/tradeApiLogin"
)
NEO_MPIN_VALIDATE_URL = os.getenv(
    "NEO_MPIN_VALIDATE_URL",
    "https://mis.kotaksecurities.com/login/1.0/tradeApiValidate"
)

# After MPIN validate, we MUST use {{baseUrl}} for everything else:
# Keep these as RELATIVE PATHS; the code will prepend baseUrl.
QUOTES_PATH       = os.getenv("NEO_QUOTES_PATH", "")        # e.g., "/market/1.0/quotes"
OPTIONCHAIN_PATH  = os.getenv("NEO_OPTIONCHAIN_PATH", "")   # e.g., "/market/1.0/option-chain"

# Some tenants expect token in different header keys; make it configurable.
TOKEN_HEADER_KEY  = os.getenv("NEO_TOKEN_HEADER_KEY", "x-api-token")
TOKEN_PREFIX      = os.getenv("NEO_TOKEN_PREFIX", "")  # usually "" (plain token as per v2)

# Discovery overrides
GOLDM_UNDERLYING  = os.getenv("GOLDM_FUT_SYMBOL", "GOLDM")  # FUT symbol or tradingsymbol if needed

# ─────────────────────────────────────────────────────────────────────────────
# App / Buffers
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger("goldm-v2")

under_buf: deque = deque(maxlen=3600)
hist: Dict[str, deque] = defaultdict(lambda: deque(maxlen=3600))
last_alert_ts: Optional[datetime] = None

# Global session state (after MPIN validation)
SESSION = {
    "baseUrl": None,          # from MPIN validation
    "tradeSid": None,         # if returned
    "tradeToken": None        # if returned
}

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def normalize_base32_secret(raw: str) -> str:
    if not raw:
        raise ValueError("Empty TOTP secret")
    s = re.sub(r'[^A-Za-z2-7]', '', str(raw)).upper()   # keep base32 charset only
    s = s + ('=' * ((8 - (len(s) % 8)) % 8))            # pad to multiple of 8
    base64.b32decode(s, casefold=True)                  # validate
    return s

def pct_change(buf: deque, lookback_min: int) -> Optional[float]:
    if len(buf) < 2: return None
    cutoff = time.time() - lookback_min * 60
    while buf and buf[0][0] < cutoff:
        buf.popleft()
    if len(buf) < 2: return None
    t0, p0 = buf[0]
    t1, p1 = buf[-1]
    if not p0 or p1 is None: return None
    return 100.0 * (p1 - p0) / p0

def should_alert(u, ce, pe):
    if u is None or ce is None or pe is None:
        return False
    return abs(u) >= UNDER_MOVE_PCT and abs(ce) <= OPT_STALE_PCT and abs(pe) <= OPT_STALE_PCT

def post_tradetron(payload: dict):
    if not TT_WEBHOOK_URL or not TT_API_TOKEN:
        log.info("Tradetron webhook not configured; skipping.")
        return
    data = {"key": TT_API_TOKEN, **payload}
    try:
        r = requests.post(TT_WEBHOOK_URL, json=data, timeout=5)
        log.info(f"Tradetron webhook status={r.status_code}")
    except Exception as e:
        log.error(f"Tradetron webhook error: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# Kotak v2 client: TOTP login → MPIN validate → baseUrl
# ─────────────────────────────────────────────────────────────────────────────
class KotakV2:
    def __init__(self):
        miss = [k for k,v in {
            "NEO_MOBILE": NEO_MOBILE,
            "NEO_PASSWORD": NEO_PASSWORD,
            "NEO_TOTP_SECRET": NEO_TOTP_SECRET,
            "NEO_CLIENT_CODE": NEO_CLIENT_CODE,
            "NEO_MPIN": NEO_MPIN,
            "NEO_ACCESS_TOKEN": NEO_ACCESS_TOKEN
        }.items() if not v]
        if miss:
            raise RuntimeError(f"Missing env vars: {', '.join(miss)}")
        self.s = requests.Session()

    def login_totp(self) -> bool:
        """
        v2: Fixed endpoint (per migration doc) for TOTP login.
        We pass the plain ACCESS TOKEN in headers (no Bearer), as per v2 note.
        """
        try:
            secret = normalize_base32_secret(NEO_TOTP_SECRET)
            totp = pyotp.TOTP(secret).now()
        except Exception as e:
            log.error(f"TOTP secret error: {e}")
            return False

        headers = {
            "Content-Type": "application/json",
            TOKEN_HEADER_KEY: f"{TOKEN_PREFIX}{NEO_ACCESS_TOKEN}".strip()
        }
        body = {
            "mobile": str(NEO_MOBILE),
            "password": NEO_PASSWORD,
            "totp": totp
        }
        try:
            r = self.s.post(NEO_TOTP_LOGIN_URL, headers=headers, data=json.dumps(body), timeout=15)
            if not r.ok:
                log.warning(f"TOTP login failed {r.status_code}: {r.text[:200]}")
                return False
            log.info("TOTP login OK.")
            return True
        except Exception as e:
            log.error(f"TOTP login exception: {e}")
            return False

    def validate_mpin(self) -> bool:
        """
        v2: MPIN validation returns baseUrl; we must use that for subsequent routes.
        """
        headers = {
            "Content-Type": "application/json",
            TOKEN_HEADER_KEY: f"{TOKEN_PREFIX}{NEO_ACCESS_TOKEN}".strip()
        }
        body = {
            "clientId": NEO_CLIENT_CODE,
            "mpin": str(NEO_MPIN)
        }
        try:
            r = self.s.post(NEO_MPIN_VALIDATE_URL, headers=headers, data=json.dumps(body), timeout=15)
            if not r.ok:
                log.warning(f"MPIN validate failed {r.status_code}: {r.text[:200]}")
                return False
            j = r.json() if "application/json" in r.headers.get("content-type","") else {}
            base_url = j.get("baseUrl") or (j.get("data",{}) if isinstance(j.get("data"), dict) else {}).get("baseUrl")
            SESSION["baseUrl"] = base_url
            SESSION["tradeSid"] = j.get("tradeSid") or j.get("sid")
            SESSION["tradeToken"] = j.get("tradeToken") or j.get("token")
            if not SESSION["baseUrl"]:
                log.warning(f"MPIN validate OK but baseUrl missing in response keys={list(j.keys())}")
                return False
            log.info(f"MPIN validate OK. baseUrl={SESSION['baseUrl']}")
            return True
        except Exception as e:
            log.error(f"MPIN validate exception: {e}")
            return False

    def ensure_session(self) -> bool:
        if not SESSION["baseUrl"]:
            return self.login_totp() and self.validate_mpin()
        return True

    def _build_url(self, rel_path: str) -> Optional[str]:
        base = SESSION["baseUrl"]
        if not base or not rel_path:
            return None
        return f"{base.rstrip('/')}/{rel_path.lstrip('/')}"

    def quotes(self, symbols: List[str]) -> Dict[str, dict]:
        if not self.ensure_session(): return {}
        url = self._build_url(QUOTES_PATH)
        if not url:
            log.info("NEO_QUOTES_PATH not set; skipping quotes.")
            return {}
        headers = {"Content-Type": "application/json", TOKEN_HEADER_KEY: f"{TOKEN_PREFIX}{NEO_ACCESS_TOKEN}".strip()}
        body = {"symbols": symbols}
        try:
            r = self.s.post(url, headers=headers, data=json.dumps(body), timeout=15)
            j = r.json() if "application/json" in r.headers.get("content-type","") else {}
            rows = j.get("data") or j.get("quotes") or (j if isinstance(j, list) else [])
            out = {}
            for row in rows:
                sym = row.get("tradingsymbol") or row.get("symbol")
                ltp = row.get("last_price") or row.get("ltp")
                oi  = row.get("oi") or row.get("open_interest")
                if sym:
                    out[sym] = {
                        "ltp": float(ltp) if ltp not in (None, "") else None,
                        "oi": int(oi) if oi not in (None, "") else None
                    }
            return out
        except Exception as e:
            log.error(f"quotes error: {e}")
            return {}

    def option_chain(self, underlying: str="GOLDM") -> List[dict]:
        if not self.ensure_session(): return []
        url = self._build_url(OPTIONCHAIN_PATH)
        if not url:
            log.info("NEO_OPTIONCHAIN_PATH not set; skipping option-chain.")
            return []
        headers = {"Content-Type": "application/json", TOKEN_HEADER_KEY: f"{TOKEN_PREFIX}{NEO_ACCESS_TOKEN}".strip()}
        body = {"symbol": underlying}
        try:
            r = self.s.post(url, headers=headers, data=json.dumps(body), timeout=15)
            j = r.json() if "application/json" in r.headers.get("content-type","") else {}
            rows = j.get("data") or j.get("options") or []
            return rows if isinstance(rows, list) else []
        except Exception as e:
            log.error(f"option_chain error: {e}")
            return []

# ─────────────────────────────────────────────────────────────────────────────
# Engine
# ─────────────────────────────────────────────────────────────────────────────
async def engine_loop():
    global last_alert_ts
    try:
        broker = KotakV2()
    except Exception as e:
        log.error(f"ENV error: {e}")
        while True:
            await asyncio.sleep(max(30, RUN_INTERVAL_S))

    while True:
        now = datetime.now(IST)
        now_ts = time.time()

        # Underlying FUT (if quotes path is set)
        try:
            q_u = broker.quotes([GOLDM_UNDERLYING]).get(GOLDM_UNDERLYING, {})
            u = q_u.get("ltp")
            if u is not None:
                under_buf.append((now_ts, float(u)))
        except Exception as e:
            log.error(f"Underlying quote error: {e}")

        # Option-chain → max OI CE/PE
        try:
            chain = broker.option_chain("GOLDM")
            quotes = {}
            ce_syms, pe_syms = [], []
            for row in chain:
                ts  = row.get("tradingsymbol") or row.get("symbol")
                ltp = row.get("last_price") or row.get("ltp")
                oi  = row.get("oi") or row.get("open_interest")
                typ = (row.get("option_type") or row.get("type") or "").upper()
                if not ts or not typ: continue
                quotes[ts] = {
                    "ltp": float(ltp) if ltp not in (None, "") else None,
                    "oi": int(oi) if oi not in (None, "") else None
                }
                if typ == "CE": ce_syms.append(ts)
                elif typ == "PE": pe_syms.append(ts)

            for ts, meta in quotes.items():
                if meta.get("ltp") is not None:
                    hist[ts].append((now_ts, float(meta["ltp"])))

            ce_sorted = sorted([s for s in ce_syms if quotes.get(s,{}).get("oi") is not None],
                               key=lambda s: quotes[s]["oi"], reverse=True)
            pe_sorted = sorted([s for s in pe_syms if quotes.get(s,{}).get("oi") is not None],
                               key=lambda s: quotes[s]["oi"], reverse=True)

            ce_pick = ce_sorted[0] if ce_sorted else None
            pe_pick = pe_sorted[0] if pe_sorted else None

            u_pct  = pct_change(under_buf, LOOKBACK_MIN)
            ce_pct = pct_change(hist[ce_pick], LOOKBACK_MIN) if ce_pick else None
            pe_pct = pct_change(hist[pe_pick], LOOKBACK_MIN) if pe_pick else None

            log.info(f"Pick CE={ce_pick} PE={pe_pick} | U%={u_pct} CE%={ce_pct} PE%={pe_pct}")

            if ce_pick and pe_pick and should_alert(u_pct, ce_pct, pe_pct):
                if (last_alert_ts is None) or (now - last_alert_ts >= timedelta(minutes=SILENCE_MIN)):
                    payload = {
                        "event": "goldm_non_responsive",
                        "u_pct": round(u_pct,4) if u_pct is not None else None,
                        "ce_pct": round(ce_pct,4) if ce_pct is not None else None,
                        "pe_pct": round(pe_pct,4) if pe_pct is not None else None,
                        "ce_symbol": ce_pick,
                        "pe_symbol": pe_pick,
                        "lookback_min": LOOKBACK_MIN,
                        "thresholds": {"under": UNDER_MOVE_PCT, "opt": OPT_STALE_PCT},
                        "ts": now.isoformat()
                    }
                    post_tradetron(payload)
                    last_alert_ts = now

        except Exception as e:
            log.error(f"Loop error: {e}")

        await asyncio.sleep(RUN_INTERVAL_S)

# ─────────────────────────────────────────────────────────────────────────────
# API
# ─────────────────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def _startup():
    asyncio.create_task(engine_loop())

@app.get("/")
def root():
    return {"service":"goldm-premium-guard","docs":"/docs","status":"/status","health":"/health"}

@app.get("/health")
def health():
    return {"ok": True, "time": datetime.now(IST).isoformat()}

@app.get("/status")
def status():
    return {
        "login_url": NEO_TOTP_LOGIN_URL,
        "mpin_validate_url": NEO_MPIN_VALIDATE_URL,
        "baseUrl": SESSION["baseUrl"],
        "quotes_path": QUOTES_PATH or "(not set)",
        "optionchain_path": OPTIONCHAIN_PATH or "(not set)",
        "token_header": TOKEN_HEADER_KEY,
        "lookback_min": LOOKBACK_MIN,
        "under_move_pct": UNDER_MOVE_PCT,
        "opt_stale_pct": OPT_STALE_PCT
    }

@app.get("/totp/now")
def totp_now():
    try:
        secret = normalize_base32_secret(NEO_TOTP_SECRET)
        code = pyotp.TOTP(secret).now()
        return {"ok": True, "totp": code}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@app.post("/login/test")
def login_test():
    try:
        client = KotakV2()
        ok1 = client.login_totp()
        ok2 = client.validate_mpin() if ok1 else False
        return {"login_totp_ok": ok1, "mpin_validate_ok": ok2, "baseUrl": SESSION["baseUrl"]}
    except Exception as e:
        return {"login_totp_ok": False, "mpin_validate_ok": False, "error": str(e)}