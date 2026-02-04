# goldm-premium-guard

FastAPI service deployed on Render that uses the **official Kotak Neo SDK v2**  
to authenticate using Mobile + Password + TOTP.

Python version is pinned to **3.12** using `runtime.txt` for compatibility.

### Important environment variables (set in Render → Environment)

- `NEO_MOBILE`
- `NEO_PASSWORD`
- `NEO_TOTP_SECRET` (Base32 secret)
- `NEO_CONSUMER_KEY` (Token from Neo app → Invest → Trade API)
- `TT_WEBHOOK_URL` (Optional)
- `TT_API_TOKEN` (Optional)

### Local run (optional)