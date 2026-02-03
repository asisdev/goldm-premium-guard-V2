import os, time, json, asyncio, logging
from collections import deque, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import requests
import pyotp
from fastapi import FastAPI

# -------------------- Config from ENV --------------------
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

# Kotak login (Mobile + Password + TOTP)
NEO_MOBILE      = os.getenv("NEO_MOBILE")         # e.g., 9434895910  (do NOT hardcode)
NEO_PASSWORD    = os.getenv("NEO_PASSWORD")
NEO_TOTP_SECRET = os.getenv("NEO_TOTP_SECRET")    # base32 secret from your Authenticator

# Kotak REST endpoints (configurable)
NEO_BASE_URL         = os.getenv("NEO_BASE_URL", "https://napi.kotaksecurities.com")
NEO_LOGIN_URL        = os.getenv("NEO_LOGIN_URL", "")        # if empty, app will try candidates
NEO_QUOTES_URL       = os.getenv("NEO_QUOTES_URL", "")       # e.g., quotes endpoint
NEO_OPTIONCHAIN_URL  = os.getenv("NEO_OPTIONCHAIN_URL", "")  # e.g., option-chain endpoint

# -------------------- App/Logs --------------------
app = FastAPI()
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger("goldm-rest")

# Buffers
under_buf: deque = deque(maxlen=3600)
hist: Dict[str, deque] = defaultdict(lambda: deque(maxlen=3600))
last_alert_ts: Optional[datetime] = None

# -------------------- Kotak REST Client (Configurable) --------------------
class KotakREST:
    """
    REST-only client; does NOT use neo_api_client.
    You MUST supply correct endpoints via env once confirmed with Kotak.
    """
    def __init__(self):
        miss = [k for k, v in {
            "NEO_MOBILE": NEO_MOBILE,
            "NEO_PASSWORD": NEO_PASSWORD,
            "NEO_TOTP_SECRET": NEO_TOTP_SECRET
        }.items() if not v]
        if miss:
            raise RuntimeError(f"Missing env vars: {', '.join(miss)}")

        self.session = requests.Session()
        self.tokens: Dict[str, str] = {}
        self.logged_in = False

        # Build candidate login endpoints/payload shapes
        self.login_urls = [u for u in [
            NEO_LOGIN_URL.strip() or "",
            f"{NEO_BASE_URL.rstrip('/')}/api/login",
            f"{NEO_BASE_URL.rstrip('/')}/auth/1.0/login",
            f"{NEO_BASE_URL.rstrip('/')}/login/1.0/login"
        ] if u]

        # Payload variants commonly seen in different deployments
        self.payload_variants = [
            lambda totp: {"mobile": NEO_MOBILE, "password": NEO_PASSWORD, "totp": totp},
            lambda totp: {"mobilenumber": NEO_MOBILE, "password": NEO_PASSWORD, "totp": totp},
            lambda totp: {"username": NEO_MOBILE, "password": NEO_PASSWORD, "totp": totp},
            lambda totp: {"userid": NEO_MOBILE, "password": NEO_PASSWORD, "totp": totp},
        ]

    def _extract_token_from_response(self, j: dict) -> Optional[str]:
        """
        Try multiple common keys that may carry an access/session token.
        """
        for key in ("access_token", "session_token", "token", "jwt", "jwtToken", "authorization"):
            val = j.get(key)
            if isinstance(val, str) and len(val) > 10:
                return val
        # Sometimes token is nested under 'data'
        data = j.get("data") or {}
        if isinstance(data, dict):
            for key in ("access_token", "session_token", "token", "jwt", "jwtToken", "authorization"):
                val = data.get(key)
                if isinstance(val, str) and len(val) > 10:
                    return val
        return None

    def login(self) -> bool:
        totp_code = pyotp.TOTP(NEO_TOTP_SECRET).now()
        headers = {"Content-Type": "application/json"}

        for url in self.login_urls:
            for make_payload in self.payload_variants:
                payload = make_payload(totp_code)
                try:
                    r = self.session.post(url, headers=headers, data=json.dumps(payload), timeout=10)
                    if r.status_code >= 500:
                        log.warning(f"Login server error at {url}: {r.status_code}")
                        continue
                    j = {}
                    try:
                        j = r.json()
                    except Exception:
                        pass

                    if r.ok:
                        token = self._extract_token_from_response(j) or r.headers.get("Authorization")
                        if token:
                            self.tokens["auth"] = token
                            self.logged_in = True
                            log.info(f"Login OK via {url} (payload keys={list(payload.keys())})")
                            return True
                        else:
                            log.warning(f"Login response OK but token not found (url={url}) resp_keys={list(j.keys())}")
                    else:
                        log.warning(f"Login failed at {url} {r.status_code} body={j or r.text[:200]}")
                except Exception as e:
                    log.warning(f"Login attempt exception at {url}: {e}")
        return False

    def ensure(self) -> bool:
        if not self.logged_in:
            return self.login()
        return True

    def auth_headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json"}
        auth = self.tokens.get("auth")
        if auth:
            # Support both bare token and Bearer patterns
            if not auth.lower().startswith("bearer "):
                h["Authorization"] = f"Bearer {auth}"
            else:
                h["Authorization"] = auth
        return h

    # ---- Quotes for a list of symbols (You MUST set NEO_QUOTES_URL) ----
    def quotes(self, symbols: List[str]) -> Dict[str, dict]:
        if not self.ensure():
            return {}
        if not NEO_QUOTES_URL:
            log.info("NEO_QUOTES_URL not set; skipping quotes call.")
            return {}
        url = NEO_QUOTES_URL.strip()
        try:
            body = {"symbols": symbols}
            r = self.session.post(url, headers=self.auth_headers(), data=json.dumps(body), timeout=10)
            j = r.json() if r.headers.get("content-type","").startswith("application/json") else {}
            out = {}
            # Try to normalize response structure
            rows = j.get("data") or j.get("quotes") or j if isinstance(j, list) else []
            if isinstance(rows, list):
                for row in rows:
                    sym = row.get("tradingsymbol") or row.get("symbol") or row.get("instrument_token")
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

    # ---- Option chain for GOLDM (You MUST set NEO_OPTIONCHAIN_URL or skip) ----
    def option_chain(self, symbol: str) -> List[dict]:
        if not self.ensure():
            return []
        if not NEO_OPTIONCHAIN_URL:
            log.info("NEO_OPTIONCHAIN_URL not set; skipping option-chain call.")
            return []
        url = NEO_OPTIONCHAIN_URL.strip()
        try:
            body = {"symbol": symbol}
            r = self.session.post(url, headers=self.auth_headers(), data=json.dumps(body), timeout=10)
            j = r.json() if r.headers.get("content-type","").startswith("application/json") else {}
            rows = j.get("data") or j.get("options") or []
            return rows if isinstance(rows, list) else []
        except Exception as e:
            log.error(f"option_chain error: {e}")
            return []

# -------------------- Helpers --------------------
def pct_change(buf: deque, lookback_min: int) -> Optional[float]:
    if len(buf) < 2:
        return None
    cutoff = time.time() - lookback_min * 60
    while buf and buf[0][0] < cutoff:
        buf.popleft()
    if len(buf) < 2:
        return None
    t0, p0 = buf[0]
    t1, p1 = buf[-1]
    if not p0 or p1 is None:
        return None
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

# -------------------- Main Engine (safe; never crashes the server) --------------------
async def engine_loop():
    global last_alert_ts
    try:
        broker = KotakREST()
    except Exception as e:
        log.error(f"ENV error: {e}")
        # Keep server alive; retry later
        while True:
            await asyncio.sleep(max(30, RUN_INTERVAL_S))
        # (return not needed)

    # NOTE: You must set correct endpoints (NEO_QUOTES_URL / NEO_OPTIONCHAIN_URL)
    # The loop is resilient and will keep running even if calls fail.

    fut_symbol = os.getenv("GOLDM_FUT_SYMBOL", "GOLDM")  # allow override
    ce_list: List[str] = []
    pe_list: List[str] = []

    while True:
        now = datetime.now(IST)
        now_ts = time.time()

        # ---- Underlying FUT LTP (if quotes endpoint is provided) ----
        try:
            if NEO_QUOTES_URL:
                u_q = broker.quotes([fut_symbol]).get(fut_symbol, {})
                u = u_q.get("ltp")
                if u is not None:
                    under_buf.append((now_ts, float(u)))
        except Exception as e:
            log.error(f"Underlying quote error: {e}")

        # ---- Option chain (if endpoint provided) ----
        try:
            if NEO_OPTIONCHAIN_URL:
                chain = broker.option_chain("GOLDM")
                # Normalize minimal structure
                quotes: Dict[str, dict] = {}
                ce_list.clear()
                pe_list.clear()
                for row in chain:
                    ts = row.get("tradingsymbol") or row.get("symbol")
                    ltp = row.get("last_price") or row.get("ltp")
                    oi  = row.get("oi") or row.get("open_interest")
                    typ = row.get("option_type") or row.get("type")
                    if not ts or not typ:
                        continue
                    quotes[ts] = {
                        "ltp": float(ltp) if ltp not in (None, "") else None,
                        "oi": int(oi) if oi not in (None, "") else None
                    }
                    if str(typ).upper() == "CE":
                        ce_list.append(ts)
                    elif str(typ).upper() == "PE":
                        pe_list.append(ts)

                # Update price histories
                for sym, meta in quotes.items():
                    if meta.get("ltp") is not None:
                        hist[sym].append((now_ts, float(meta["ltp"])))

                # Pick highest OI CE/PE
                ce_sorted = sorted(
                    [s for s in ce_list if quotes.get(s, {}).get("oi") is not None],
                    key=lambda s: quotes[s]["oi"], reverse=True
                )
                pe_sorted = sorted(
                    [s for s in pe_list if quotes.get(s, {}).get("oi") is not None],
                    key=lambda s: quotes[s]["oi"], reverse=True
                )
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

# -------------------- FastAPI endpoints --------------------
@app.on_event("startup")
async def _startup():
    asyncio.create_task(engine_loop())

@app.get("/health")
def health():
    return {"ok": True, "time": datetime.now(IST).isoformat()}

@app.get("/status")
def status():
    return {
        "base_url": NEO_BASE_URL,
        "login_url": NEO_LOGIN_URL or "(using candidates)",
        "quotes_url": NEO_QUOTES_URL or "(not set)",
        "optionchain_url": NEO_OPTIONCHAIN_URL or "(not set)",
        "lookback_min": LOOKBACK_MIN,
        "under_move_pct": UNDER_MOVE_PCT,
        "opt_stale_pct": OPT_STALE_PCT,
        "run_interval_s": RUN_INTERVAL_S
    }

@app.post("/login/test")
def login_test():
    try:
        client = KotakREST()
        ok = client.login()
        return {"login_ok": ok, "headers_seen": list(client.session.headers.keys()), "has_token": bool(client.tokens.get("auth"))}
    except Exception as e:
        return {"login_ok": False, "error": str(e)}