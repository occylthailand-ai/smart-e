# Smart-E

All-in-One platform for Thai SME commerce: **E-Commerce + CRM + LINE + TikTok + Payment**,
in a single pure-Python backend with a static dashboard.

- **Backend** — `server.py`: pure Python **stdlib only** (`http.server` + `sqlite3`), no
  pip install required. Auto-creates its SQLite schema on start.
- **Dashboard** — `index.html`: a standalone admin UI that talks to the backend API.
- **Payments** — Thai **PromptPay** QR generated on the server (EMVCo TLV payload + CRC-16),
  plus a manual payment-confirm step.

## Requirements

- Python 3 (standard library only — nothing to install for the backend).

## Environment variables

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `ADMIN_KEY` | **yes** | *(unset)* | Gates every `/api/*` route via the `X-Admin-Key` header. **While unset the server fail-closes: every API call returns `503` until an admin sets it.** |
| `LINE_CHANNEL_SECRET` | for LINE | *(unset)* | HMAC-SHA256 secret used to verify `POST /api/webhook/line`. While unset, webhook calls are rejected (`401`). |
| `LINE_API_BASE` | no | LINE's real API | Base URL for outbound LINE calls; override it to point at a mock in tests. |
| `PORT` | no | `8000` | Port the server listens on. |
| `SMART_E_DB` | no | `~/smart_e.db` | Path to the SQLite database file. |

## Run

```bash
# start the backend (creates the DB + tables automatically)
ADMIN_KEY=your-secret python3 server.py
# → http://localhost:8000  ·  API at http://localhost:8000/api/

# (optional) load demo data into the DB
python3 seed.py
```

Open `index.html` in a browser (or serve it statically) and point it at the backend to use
the dashboard.

## Tests

The test suite boots a real server on a temp DB and exercises the live endpoints (auth gate,
input validation, stock/oversell guards, PromptPay payload + CRC, payment idempotency, the
non-object-body 400 path, and more):

```bash
python3 test_server.py    # exits non-zero if any check fails
```

## Authentication

- **Admin API** — every `/api/*` route (except the LINE webhook) requires the `X-Admin-Key`
  request header to equal `ADMIN_KEY`. The check is constant-time; a missing/wrong key gets
  `401`, and an unset `ADMIN_KEY` gets `503` (fail-closed — no anonymous access ever).
- **LINE webhook** — `POST /api/webhook/line` is authenticated instead by the
  `X-Line-Signature` header (base64 HMAC-SHA256 of the raw body under `LINE_CHANNEL_SECRET`),
  since it is called by the LINE platform, not an admin.

## API overview

All routes are under `/api` and return JSON.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/dashboard/stats` | Aggregate dashboard metrics |
| GET/POST | `/api/products` | List / create products |
| GET/PUT/DELETE | `/api/products/{id}` | Read / update / delete a product |
| GET/POST | `/api/customers` | List / create customers |
| GET/PUT | `/api/customers/{id}` | Read / update a customer |
| GET/POST | `/api/orders` | List / create orders (stock-checked) |
| PUT | `/api/orders/{id}/status` | Update order status (stock-symmetric un-cancel) |
| GET | `/api/payments` | List payments |
| POST | `/api/payments/qr` | Create a PromptPay QR for an amount |
| POST | `/api/payments/confirm` | Mark a payment paid + advance its order |
| GET | `/api/line/messages` | LINE message history |
| POST | `/api/line/broadcast` | Broadcast a LINE message to customers |
| POST | `/api/webhook/line` | LINE inbound webhook (signature-verified) |
| GET | `/api/tiktok/orders` · `/api/tiktok/ads` | TikTok data |
| GET | `/api/analytics` | Analytics summary |
| GET/POST | `/api/settings` | Read / save settings |

## Data model

SQLite tables created on startup: `products`, `customers`, `orders`, `order_items`,
`payments`, `line_messages`, `tiktok_orders`, `tiktok_ads`, `settings`.

## Notes

- The `package.json` in this repo declares a separate Vite/React frontend toolchain; the
  committed, ready-to-use dashboard is `index.html`.
- Money amounts are validated server-side (no negative or non-finite `amount`/`price`),
  and order stock is checked on create and restored symmetrically on cancel.
