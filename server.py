"""
Smart-E Backend Server
All-in-One: E-Commerce + CRM + LINE + TikTok + Payment
Pure Python stdlib — no external packages required
Run: python3 server.py
"""

import http.server
import json
import sqlite3
import base64
import hashlib
import hmac
import os
import re
import traceback
import urllib.parse
import urllib.request
from datetime import datetime, date, timedelta
import math

# DB_PATH/PORT are env-overridable so the server can run against an isolated
# database/port (deployments with a custom data dir, and the regression test in
# test_server.py which spins up a throwaway db on an alt port). Defaults are
# unchanged, so existing runs behave exactly as before.
DB_PATH = os.environ.get('SMART_E_DB') or os.path.join(os.path.expanduser("~"), "smart_e.db")
FRONTEND_PATH = os.path.join(os.path.dirname(__file__), "index.html")
PORT = int(os.environ.get('PORT', '8000'))

# Every API route below (dashboard/products/orders/customers/payments/tiktok/
# analytics/settings/line messages+broadcast) had zero authentication — anyone
# who could reach this port could read all customer PII (name/email/phone/LINE
# user ID), delete products, confirm fake payments, and send real LINE
# broadcast messages to customers. ADMIN_KEY gates all of it now. Left unset
# by default so a fresh deploy fails closed (503, not silently wide open)
# until an admin actually sets it — matches the fail-closed pattern already
# used for webhook secrets elsewhere in this project family.
ADMIN_KEY = os.environ.get('ADMIN_KEY', '')
# /api/webhook/line is called by LINE's platform, not an admin — it needs its
# own signature check (LINE Messaging API's HMAC-SHA256-over-raw-body scheme),
# not the admin key. It previously had no verification at all: anyone could
# POST fake "follow"/"message" events and inject fake customers/messages.
LINE_CHANNEL_SECRET = os.environ.get('LINE_CHANNEL_SECRET', '')
# Base URL of the LINE Messaging API. Overridable so a test can point the broadcast
# call at a closed/local port and deterministically exercise the send-failure path
# (default is the real endpoint; production is unchanged).
LINE_API_BASE = os.environ.get('LINE_API_BASE', 'https://api.line.me')

# ─────────────────────────────────────────────
# DATABASE SETUP
# ─────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            stock INTEGER DEFAULT 0,
            category TEXT DEFAULT 'ทั่วไป',
            image_url TEXT,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            line_user_id TEXT,
            line_display_name TEXT,
            line_picture_url TEXT,
            tag TEXT DEFAULT 'ทั่วไป',
            total_orders INTEGER DEFAULT 0,
            total_spent REAL DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER,
            customer_name TEXT,
            status TEXT DEFAULT 'pending',
            channel TEXT DEFAULT 'web',
            total REAL DEFAULT 0,
            note TEXT,
            address TEXT,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            FOREIGN KEY(customer_id) REFERENCES customers(id)
        );
        CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER,
            product_id INTEGER,
            product_name TEXT,
            qty INTEGER DEFAULT 1,
            price REAL,
            FOREIGN KEY(order_id) REFERENCES orders(id),
            FOREIGN KEY(product_id) REFERENCES products(id)
        );
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER,
            method TEXT DEFAULT 'promptpay',
            amount REAL,
            status TEXT DEFAULT 'pending',
            qr_payload TEXT,
            ref_code TEXT,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            FOREIGN KEY(order_id) REFERENCES orders(id)
        );
        CREATE TABLE IF NOT EXISTS line_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER,
            line_user_id TEXT,
            message TEXT,
            direction TEXT DEFAULT 'in',
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS tiktok_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tiktok_order_id TEXT UNIQUE,
            customer_name TEXT,
            items_json TEXT,
            total REAL,
            status TEXT DEFAULT 'pending',
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS tiktok_ads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_name TEXT,
            impressions INTEGER DEFAULT 0,
            clicks INTEGER DEFAULT 0,
            spend REAL DEFAULT 0,
            revenue REAL DEFAULT 0,
            date TEXT DEFAULT (date('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
    """)
    conn.commit()
    conn.close()

# ─────────────────────────────────────────────
# PROMPTPAY QR GENERATOR (EMV QR Code Format)
# ─────────────────────────────────────────────

def _resolve_promptpay_target(raw: str):
    """Map a merchant identifier to (sub-tag, value) for the PromptPay merchant account.
      - mobile number  -> ('01', '0066' + 9 significant digits)   any local/intl form
      - national/tax ID -> ('02', <13 digits>)                     business PromptPay
      - e-wallet ID     -> ('03', <15 digits>)
    """
    digits = re.sub(r'\D', '', raw or '')
    # Already-canonical mobile form 0066XXXXXXXXX (13 chars). Checked before the 13-digit
    # national-ID case, which it would otherwise collide with (national IDs never start 0066).
    if digits.startswith('0066') and len(digits) == 13:
        return '01', digits
    if len(digits) == 15:
        return '03', digits
    if len(digits) == 13:
        return '02', digits
    # Mobile number in any other form -> strip the local "0" or intl "66" prefix, then re-add 0066.
    if digits.startswith('66'):
        digits = digits[2:]
    elif digits.startswith('0'):
        digits = digits[1:]
    return '01', '0066' + digits


def generate_promptpay_payload(phone_or_id: str, amount: float = None) -> str:
    """Generate EMV QR Code payload string for PromptPay"""
    def tlv(tag: str, value: str) -> str:
        length = f"{len(value):02d}"
        return f"{tag}{length}{value}"

    # Resolve the PromptPay target. It can be a mobile number (sub-tag 01, formatted as
    # 0066 + the 9 significant digits), a 13-digit national/tax ID (sub-tag 02 — how a
    # business/OTOP shop usually registers PromptPay), or a 15-digit e-wallet ID (sub-tag 03).
    # The old code only ever used sub-tag 01 and blindly prefixed "0066": a number already in
    # intl form ("66..." or "+66...") became "006666..." (double 66 -> an invalid PromptPay ID,
    # so the QR points at no real account and the merchant never gets paid), and a national ID
    # was mangled into sub-tag 01. Normalise all common forms and pick the correct sub-tag.
    target_tag, target_val = _resolve_promptpay_target(phone_or_id)

    merchant_info = tlv(target_tag, target_val)
    gui = tlv('00', 'A000000677010111')
    merchant_account = tlv('29', gui + merchant_info)
    # Point of Initiation Method (tag 01): "12" = dynamic (single transaction, amount
    # embedded), "11" = static (reusable, payer fills in the amount). This was hardcoded
    # to "12" even for the no-amount case that _create_qr explicitly supports as a
    # "payer enters the amount" QR — a "12" code with no amount tag is contradictory
    # per the EMVCo/PromptPay spec, and some bank apps treat "12" as single-use and
    # reject/blackhole a reused code. Pick the method that matches whether an amount is set.
    has_amount = bool(amount and amount > 0)
    poi = '12' if has_amount else '11'
    payload = tlv('00', '01') + tlv('01', poi) + merchant_account + tlv('53', '764')

    if has_amount:
        amount_str = f"{amount:.2f}"
        payload += tlv('54', amount_str)

    payload += tlv('58', 'TH') + tlv('59', 'Smart-E Shop') + tlv('60', 'Bangkok')

    # CRC16 checksum
    payload += '6304'
    crc = 0xFFFF
    for char in payload.encode('utf-8'):
        crc ^= char << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
        crc &= 0xFFFF
    payload += f"{crc:04X}"
    return payload

# ─────────────────────────────────────────────
# HTTP REQUEST HANDLER
# ─────────────────────────────────────────────

class SmartEHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {format % args}")

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False, default=str).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', len(body))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html: str):
        body = html.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def read_body(self):
        length = int(self.headers.get('Content-Length', 0))
        if length:
            self._raw_body = self.rfile.read(length)
            try:
                parsed = json.loads(self._raw_body.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return None
            # เดิมคืนค่า JSON อะไรก็ได้ที่ parse ผ่าน -- แต่ body ที่ valid แต่ไม่ใช่ object
            # (เช่น [] , "x" , 123) จะทำให้ handler ที่เรียก body.get(...) โยน AttributeError
            # แล้ว _guard แปลง client error เป็น 500 ทุก endpoint คาดหวัง JSON object เสมอ
            # จึงเก็บกวาดตรงนี้ด้วย sentinel None เดียวกับที่ dispatcher map เป็น 400 อยู่แล้ว
            if not isinstance(parsed, dict):
                return None
            return parsed
        self._raw_body = b''
        return {}

    def _require_admin(self):
        if not ADMIN_KEY:
            self.send_json({'error': 'ADMIN_KEY not set on server — refusing all API access until an admin configures it'}, 503)
            return False
        if not hmac.compare_digest(self.headers.get('X-Admin-Key', ''), ADMIN_KEY):
            self.send_json({'error': 'Unauthorized'}, 401)
            return False
        return True

    def _verify_line_signature(self, raw_body):
        if not LINE_CHANNEL_SECRET:
            return False
        signature = self.headers.get('X-Line-Signature', '')
        expected = base64.b64encode(
            hmac.new(LINE_CHANNEL_SECRET.encode('utf-8'), raw_body, hashlib.sha256).digest()
        ).decode('utf-8')
        return hmac.compare_digest(signature, expected)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type,X-Line-Signature,X-Admin-Key')
        self.end_headers()

    def _guard(self, fn):
        # ตัวครอบ dispatcher ทุก HTTP method — เดิมถ้า handler โยน exception (เช่น DB
        # error, ค่าที่แปลงชนิดไม่ได้) exception จะหลุดออกจาก BaseHTTPRequestHandler
        # แล้ว connection ถูกปิดโดยไม่ส่ง response เลย (client เห็น empty reply / 000)
        # ที่นี่ดักไว้แล้วตอบ 500 JSON ที่อ่านได้แทน — กัน crash-class ทั้งที่มีอยู่และ
        # ที่จะเกิดในอนาคตทุกจุดในทีเดียว
        try:
            fn()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            traceback.print_exc()
            try:
                self.send_json({'error': 'เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์'}, 500)
            except Exception:
                pass

    def do_GET(self):    self._guard(self._dispatch_get)
    def do_POST(self):   self._guard(self._dispatch_post)
    def do_PUT(self):    self._guard(self._dispatch_put)
    def do_DELETE(self): self._guard(self._dispatch_delete)

    def _dispatch_get(self):
        path = urllib.parse.urlparse(self.path).path
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(self.path).query))

        if path == '/' or path == '/index.html':
            if os.path.exists(FRONTEND_PATH):
                with open(FRONTEND_PATH, 'r', encoding='utf-8') as f:
                    self.send_html(f.read())
            else:
                self.send_html("<h1>Smart-E</h1><p>Frontend not found. Place index.html next to server.py.</p>")
            return

        if not self._require_admin():
            return

        # ── API Routes ──
        if path == '/api/dashboard/stats':
            self._get_dashboard_stats()
        elif path == '/api/products':
            self._get_products(query)
        elif re.match(r'^/api/products/\d+$', path):
            pid = int(path.split('/')[-1])
            self._get_product(pid)
        elif path == '/api/orders':
            self._get_orders(query)
        elif path == '/api/customers':
            self._get_customers(query)
        elif re.match(r'^/api/customers/\d+$', path):
            cid = int(path.split('/')[-1])
            self._get_customer(cid)
        elif path == '/api/payments':
            self._get_payments(query)
        elif path == '/api/tiktok/orders':
            self._get_tiktok_orders(query)
        elif path == '/api/tiktok/ads':
            self._get_tiktok_ads(query)
        elif path == '/api/analytics':
            self._get_analytics(query)
        elif path == '/api/settings':
            self._get_settings()
        elif path == '/api/line/messages':
            self._get_line_messages(query)
        else:
            self.send_json({'error': 'Not found'}, 404)

    def _dispatch_post(self):
        path = urllib.parse.urlparse(self.path).path
        body = self.read_body()
        if body is None:
            self.send_json({'error': 'Invalid JSON body'}, 400)
            return

        # LINE's platform calls this, not an admin -- verify via signature, not X-Admin-Key
        if path == '/api/webhook/line':
            if not self._verify_line_signature(self._raw_body):
                self.send_json({'error': 'Invalid or missing LINE signature'}, 401)
                return
            self._line_webhook(body)
            return

        if not self._require_admin():
            return

        if path == '/api/products':
            self._create_product(body)
        elif path == '/api/orders':
            self._create_order(body)
        elif path == '/api/customers':
            self._create_customer(body)
        elif path == '/api/payments/qr':
            self._create_qr(body)
        elif path == '/api/payments/confirm':
            self._confirm_payment(body)
        elif path == '/api/line/broadcast':
            self._line_broadcast(body)
        elif path == '/api/settings':
            self._save_settings(body)
        else:
            self.send_json({'error': 'Not found'}, 404)

    def _dispatch_put(self):
        path = urllib.parse.urlparse(self.path).path
        body = self.read_body()
        if body is None:
            self.send_json({'error': 'Invalid JSON body'}, 400)
            return

        if not self._require_admin():
            return

        m = re.match(r'^/api/products/(\d+)$', path)
        if m:
            self._update_product(int(m.group(1)), body)
            return

        m = re.match(r'^/api/orders/(\d+)/status$', path)
        if m:
            self._update_order_status(int(m.group(1)), body)
            return

        m = re.match(r'^/api/customers/(\d+)$', path)
        if m:
            self._update_customer(int(m.group(1)), body)
            return

        self.send_json({'error': 'Not found'}, 404)

    def _dispatch_delete(self):
        path = urllib.parse.urlparse(self.path).path

        if not self._require_admin():
            return

        m = re.match(r'^/api/products/(\d+)$', path)
        if m:
            self._delete_product(int(m.group(1)))
            return
        self.send_json({'error': 'Not found'}, 404)

    # ──────────────────────────────────────────
    # DASHBOARD
    # ──────────────────────────────────────────

    def _get_dashboard_stats(self):
        conn = get_db()
        c = conn.cursor()
        today = date.today().isoformat()
        week_ago = (date.today() - timedelta(days=7)).isoformat()
        month_ago = (date.today() - timedelta(days=30)).isoformat()

        # Today's revenue
        c.execute("SELECT COALESCE(SUM(total),0) FROM orders WHERE date(created_at)=? AND status!='cancelled'", (today,))
        today_revenue = c.fetchone()[0]

        # Total orders
        c.execute("SELECT COUNT(*) FROM orders WHERE status='pending'")
        pending_orders = c.fetchone()[0]

        # New customers (today)
        c.execute("SELECT COUNT(*) FROM customers WHERE date(created_at)=?", (today,))
        new_customers = c.fetchone()[0]

        # Monthly revenue
        c.execute("SELECT COALESCE(SUM(total),0) FROM orders WHERE date(created_at)>=? AND status!='cancelled'", (month_ago,))
        monthly_revenue = c.fetchone()[0]

        # Total customers
        c.execute("SELECT COUNT(*) FROM customers")
        total_customers = c.fetchone()[0]

        # Total products
        c.execute("SELECT COUNT(*) FROM products")
        total_products = c.fetchone()[0]

        # Sales by channel
        c.execute("SELECT channel, COUNT(*) as cnt, COALESCE(SUM(total),0) as rev FROM orders WHERE status!='cancelled' GROUP BY channel")
        channels = [dict(r) for r in c.fetchall()]

        # Daily revenue (last 30 days)
        c.execute("""
            SELECT date(created_at) as day, COALESCE(SUM(total),0) as revenue, COUNT(*) as orders
            FROM orders WHERE date(created_at)>=? AND status!='cancelled'
            GROUP BY date(created_at) ORDER BY day
        """, (month_ago,))
        daily_revenue = [dict(r) for r in c.fetchall()]

        # Top products — join orders and exclude cancelled ones, same as every other
        # revenue metric above (today/monthly/channels/daily all filter status!='cancelled').
        # Before this join a product that was ordered then cancelled still counted its qty +
        # revenue here, so cancelled orders could push a product to the top of the best-seller
        # list and mislead restocking/marketing decisions.
        c.execute("""
            SELECT p.name, SUM(oi.qty) as sold, SUM(oi.qty*oi.price) as revenue
            FROM order_items oi
            JOIN products p ON p.id=oi.product_id
            JOIN orders o ON o.id=oi.order_id
            WHERE o.status!='cancelled'
            GROUP BY oi.product_id ORDER BY revenue DESC LIMIT 5
        """)
        top_products = [dict(r) for r in c.fetchall()]

        # Recent orders
        c.execute("""
            SELECT o.id, o.customer_name, o.total, o.status, o.channel, o.created_at
            FROM orders o ORDER BY o.created_at DESC LIMIT 8
        """)
        recent_orders = [dict(r) for r in c.fetchall()]

        conn.close()
        self.send_json({
            'today_revenue': today_revenue,
            'pending_orders': pending_orders,
            'new_customers': new_customers,
            'monthly_revenue': monthly_revenue,
            'total_customers': total_customers,
            'total_products': total_products,
            'channels': channels,
            'daily_revenue': daily_revenue,
            'top_products': top_products,
            'recent_orders': recent_orders
        })

    # ──────────────────────────────────────────
    # PRODUCTS
    # ──────────────────────────────────────────

    def _get_products(self, query={}):
        conn = get_db()
        c = conn.cursor()
        sql = "SELECT * FROM products"
        params = []
        if q := query.get('q'):
            sql += " WHERE name LIKE ? OR description LIKE ?"
            params.extend([f'%{q}%', f'%{q}%'])
        if cat := query.get('category'):
            sep = " AND " if params else " WHERE "
            sql += f"{sep}category=?"
            params.append(cat)
        sql += " ORDER BY created_at DESC"
        c.execute(sql, params)
        products = [dict(r) for r in c.fetchall()]

        # Categories
        c.execute("SELECT DISTINCT category FROM products ORDER BY category")
        categories = [r[0] for r in c.fetchall()]
        conn.close()
        self.send_json({'products': products, 'categories': categories, 'total': len(products)})

    def _get_product(self, pid):
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM products WHERE id=?", (pid,))
        row = c.fetchone()
        conn.close()
        if row:
            self.send_json(dict(row))
        else:
            self.send_json({'error': 'Not found'}, 404)

    def _create_product(self, body):
        # ตรวจก่อนบันทึกตามแนวเดียวกับ _create_order (price>=0) และ _create_customer (name ไม่ว่าง)
        # -- เดิมรับ name ว่าง/price ติดลบ/stock ติดลบ ได้เลย: สินค้าไม่มีชื่อโผล่ในแคตตาล็อก, และ
        # price ติดลบทำให้ total ออเดอร์ติดลบเมื่อแคชเชียร์เพิ่มสินค้านั้น (POS ดึง data-price จาก
        # สินค้า) → รายได้/ยอดใช้จ่ายลูกค้าเพี้ยน
        name = (body.get('name') or '').strip()
        if not name:
            self.send_json({'error': 'name ต้องไม่ว่าง'}, 400)
            return
        try:
            price = float(body.get('price', 0))
            stock = int(body.get('stock', 0))
        except (TypeError, ValueError):
            self.send_json({'error': 'price ต้องเป็นตัวเลข และ stock ต้องเป็นจำนวนเต็ม'}, 400)
            return
        if price < 0 or stock < 0:
            self.send_json({'error': 'price และ stock ต้องไม่ติดลบ'}, 400)
            return
        conn = get_db()
        c = conn.cursor()
        c.execute("""INSERT INTO products (name,description,price,stock,category,image_url)
                     VALUES (?,?,?,?,?,?)""",
                  (name, body.get('description',''),
                   price, stock,
                   body.get('category','ทั่วไป'), body.get('image_url','')))
        pid = c.lastrowid
        conn.commit()
        c.execute("SELECT * FROM products WHERE id=?", (pid,))
        row = dict(c.fetchone())
        conn.close()
        self.send_json(row, 201)

    def _update_product(self, pid, body):
        # POST /api/products ตรวจ price/stock เป็นตัวเลขแล้ว แต่ PUT เดิมรับอะไรก็ได้ --
        # SQLite เก็บ string "abc" ลงคอลัมน์ price ได้เฉยๆ แล้วพังปลายทาง (สต๊อกจริงถูก
        # เขียนทับเป็น 0 ตอน order decrement เพราะ 'xyz' ถูก coerce เป็น 0)
        if 'name' in body:
            # แก้ชื่อเป็นค่าว่างไม่ได้ (เหมือน _create_product/_create_customer) -- เก็บค่าที่ strip แล้ว
            name = (body.get('name') or '').strip()
            if not name:
                self.send_json({'error': 'name ต้องไม่ว่าง'}, 400)
                return
            body['name'] = name
        if 'price' in body or 'stock' in body:
            try:
                if 'price' in body:
                    body['price'] = float(body['price'])
                if 'stock' in body:
                    body['stock'] = int(body['stock'])
            except (TypeError, ValueError):
                self.send_json({'error': 'price ต้องเป็นตัวเลข และ stock ต้องเป็นจำนวนเต็ม'}, 400)
                return
            if ('price' in body and body['price'] < 0) or ('stock' in body and body['stock'] < 0):
                self.send_json({'error': 'price และ stock ต้องไม่ติดลบ'}, 400)
                return
        conn = get_db()
        c = conn.cursor()
        # เดิม: PUT id ที่ไม่มีจริง → UPDATE ไม่โดนแถวไหน แล้วตอบ {'error':'Not found'} ด้วย HTTP 200
        # (ไม่ใช่ 404) ต่างจาก _delete_product/_update_order_status ที่ 404 บน id ที่ไม่มี ทำให้ client
        # แยกไม่ออกว่า "อัปเดตสำเร็จ" หรือ "ไม่มีสินค้านี้" ตรวจก่อนตามแนวเดียวกับ handler อื่น
        if c.execute("SELECT id FROM products WHERE id=?", (pid,)).fetchone() is None:
            conn.close()
            self.send_json({'error': 'ไม่พบสินค้านี้'}, 404)
            return
        fields = []
        params = []
        for field in ['name','description','price','stock','category','image_url']:
            if field in body:
                fields.append(f"{field}=?")
                params.append(body[field])
        if fields:
            params.append(pid)
            c.execute(f"UPDATE products SET {','.join(fields)} WHERE id=?", params)
            conn.commit()
        c.execute("SELECT * FROM products WHERE id=?", (pid,))
        row = c.fetchone()
        conn.close()
        self.send_json(dict(row) if row else {'error': 'ไม่พบสินค้านี้'}, 200 if row else 404)

    def _delete_product(self, pid):
        conn = get_db()
        c = conn.cursor()
        # เดิมลบตรงๆ แล้วตอบ success เสมอ แม้ id ไม่มีจริง (UI ขึ้น "ลบแล้ว" ทั้งที่ไม่มีอะไรถูกลบ)
        if c.execute("SELECT id FROM products WHERE id=?", (pid,)).fetchone() is None:
            conn.close()
            self.send_json({'error': 'ไม่พบสินค้านี้'}, 404)
            return
        # สินค้าที่ถูกอ้างใน order_items = มีประวัติการขาย SQLite ไม่ได้บังคับ FK (PRAGMA
        # foreign_keys ปิดอยู่) การลบตรงๆ จึงทิ้ง order_items ให้กำพร้าเงียบๆ และลบยอดขายเดิม
        # ของสินค้านี้ออกจากทุกรายงาน (top-products INNER JOIN products แล้วตัดแถวกำพร้าทิ้ง)
        # ปฏิเสธการลบ — เจ้าของตั้งสต๊อกเป็น 0 เพื่อซ่อนจากหน้าร้านได้โดยไม่ทำลายประวัติ
        sold = c.execute("SELECT COUNT(*) FROM order_items WHERE product_id=?", (pid,)).fetchone()[0]
        if sold > 0:
            conn.close()
            self.send_json({'error': f'ลบไม่ได้: สินค้านี้มีประวัติการขาย {sold} รายการ การลบจะทำให้ยอดขายเดิมหายจากรายงาน — ตั้งสต๊อกเป็น 0 เพื่อซ่อนจากหน้าร้านแทน'}, 409)
            return
        c.execute("DELETE FROM products WHERE id=?", (pid,))
        conn.commit()
        conn.close()
        self.send_json({'success': True})

    # ──────────────────────────────────────────
    # ORDERS
    # ──────────────────────────────────────────

    def _get_orders(self, query={}):
        conn = get_db()
        c = conn.cursor()
        sql = "SELECT o.*, GROUP_CONCAT(oi.product_name || ' x' || oi.qty, ', ') as items_summary FROM orders o LEFT JOIN order_items oi ON oi.order_id=o.id"
        params = []
        where = []
        if status := query.get('status'):
            where.append("o.status=?")
            params.append(status)
        if channel := query.get('channel'):
            where.append("o.channel=?")
            params.append(channel)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " GROUP BY o.id ORDER BY o.created_at DESC"
        if limit := query.get('limit'):
            # เดิม int(limit) ตรงๆ ทำให้ ?limit=abc โยน ValueError → do_GET ไม่มี try/except
            # ครอบ คำขอจึงตายแบบ empty reply แทนที่จะได้ error ที่อ่านได้ — ละเว้นค่าที่ไม่ใช่
            # จำนวนเต็มบวก (คืนทั้งหมด)
            try:
                lim = int(limit)
            except (TypeError, ValueError):
                lim = 0
            if lim > 0:
                sql += f" LIMIT {lim}"
        c.execute(sql, params)
        orders = [dict(r) for r in c.fetchall()]
        conn.close()
        self.send_json({'orders': orders, 'total': len(orders)})

    def _create_order(self, body):
        # เดิมถ้า items ไม่ใช่ list ของ dict (เช่น ส่ง string มาแทน) จะ crash ด้วย
        # AttributeError ที่ไม่ได้ดักไว้ -- request handler process เดียวตายไปเงียบๆ
        # (empty response ให้ client) แทนที่จะตอบ 400 error ที่อ่านได้ว่าผิดพลาดตรงไหน
        items = body.get('items', [])
        if not isinstance(items, list) or not all(isinstance(i, dict) for i in items):
            self.send_json({'error': 'items ต้องเป็น array ของ {product_id, product_name, qty, price}'}, 400)
            return
        # เดิม price/qty ในแต่ละ item ไม่เคยถูกตรวจเป็นตัวเลข -- ถ้าส่ง price:"abc" มา sum() จะ
        # ระเบิดด้วย TypeError (int + str) แล้วตอบ empty response (crash class เดียวกับที่ไฟล์นี้
        # ดักไว้แล้วสำหรับ shape ของ items) ส่วน qty ติดลบจะทำให้ MAX(0,stock-(-5)) = stock+5
        # คือ "สั่งซื้อ" แล้วสต๊อกเพิ่มขึ้น และ total/รายได้/ยอดใช้จ่ายลูกค้าเพี้ยนตามไปด้วย --
        # ตรวจ+coerce แบบเดียวกับ _create_product ก่อนนำไปใช้คำนวณและบันทึก
        for item in items:
            try:
                item['price'] = float(item.get('price', 0))
                item['qty'] = int(item.get('qty', 1))
            except (TypeError, ValueError):
                self.send_json({'error': 'price และ qty ของสินค้าแต่ละรายการต้องเป็นตัวเลข'}, 400)
                return
            # float("nan"/"inf") ไม่โยน ValueError และลอดผ่าน `price < 0` ด้านล่าง (int() กัน qty
            # ไว้แล้ว) -- ถ้าปล่อยไป total = sum(price*qty) กลายเป็น NaN/inf แล้วถูกเขียนลง
            # orders.total และบวกสะสมเข้า customers.total_spent ทำให้มูลค่าลูกค้า/รายได้เพี้ยนถาวร
            if not math.isfinite(item['price']):
                self.send_json({'error': 'price ต้องเป็นตัวเลขจำกัด (ไม่รับ NaN/Infinity)'}, 400)
                return
            if item['price'] < 0 or item['qty'] < 1:
                self.send_json({'error': 'price ต้องไม่ติดลบ และ qty ต้องเป็นจำนวนเต็มตั้งแต่ 1 ขึ้นไป'}, 400)
                return
        conn = get_db()
        c = conn.cursor()
        # ป้องกันการสั่งเกินสต๊อก: เดิม _create_order ตัดสต๊อกด้วย MAX(0,stock-qty) (ปัดเหลือ 0
        # เมื่อสั่งเกิน) แต่ _update_order_status ตอนยกเลิกคืนด้วย stock+qty แบบไม่ปัด -- สั่งเกิน
        # สต๊อกแล้วยกเลิกจึง "เสก" สต๊อกเพิ่มจากอากาศ (5 -> สั่ง 10 -> 0 -> ยกเลิก -> 10) ตรวจ
        # สต๊อกให้พอก่อนรับออเดอร์ เพื่อให้การตัด/คืนสมมาตรเสมอ (รวม qty ต่อ product_id เผื่อ
        # สินค้าเดียวกันถูกส่งมาซ้ำหลายรายการ)
        need = {}
        for item in items:
            pid = item.get('product_id')
            if pid is not None:
                need[pid] = need.get(pid, 0) + item['qty']
        for pid, want in need.items():
            prow = c.execute("SELECT name, stock FROM products WHERE id=?", (pid,)).fetchone()
            if prow is None:
                conn.close()
                self.send_json({'error': f'ไม่พบสินค้า id={pid}'}, 400)
                return
            if want > prow['stock']:
                conn.close()
                self.send_json({'error': f'สต๊อกไม่พอสำหรับ "{prow["name"]}" (มี {prow["stock"]} ต้องการ {want})'}, 400)
                return
        total = sum(item['price'] * item['qty'] for item in items)
        c.execute("""INSERT INTO orders (customer_id,customer_name,status,channel,total,note,address)
                     VALUES (?,?,?,?,?,?,?)""",
                  (body.get('customer_id'), body.get('customer_name','ลูกค้าทั่วไป'),
                   body.get('status','pending'), body.get('channel','web'),
                   total, body.get('note',''), body.get('address','')))
        oid = c.lastrowid
        for item in items:
            c.execute("""INSERT INTO order_items (order_id,product_id,product_name,qty,price)
                         VALUES (?,?,?,?,?)""",
                      (oid, item.get('product_id'), item.get('product_name',''),
                       item.get('qty',1), item.get('price',0)))
            c.execute("UPDATE products SET stock=MAX(0,stock-?) WHERE id=?",
                      (item.get('qty',1), item.get('product_id')))
        if body.get('customer_id'):
            c.execute("UPDATE customers SET total_orders=total_orders+1, total_spent=total_spent+? WHERE id=?",
                      (total, body['customer_id']))
        conn.commit()
        c.execute("SELECT * FROM orders WHERE id=?", (oid,))
        row = dict(c.fetchone())
        conn.close()
        self.send_json(row, 201)

    # สถานะที่อนุญาต = ที่ dropdown ฝั่ง UI ตั้งได้ (pending/confirmed/shipped/delivered/cancelled)
    # รวมกับที่มีอยู่จริงในข้อมูล/หลังบ้าน (paid/processing) -- เดิมรับ status อะไรก็ได้รวมถึง None
    # ทำให้คอลัมน์เป็น NULL หรือค่าขยะ แล้ว dashboard ที่ query ตาม status เพี้ยนตาม
    ORDER_STATUSES = {'pending', 'confirmed', 'paid', 'processing', 'shipped', 'delivered', 'cancelled'}

    def _update_order_status(self, oid, body):
        new_status = body.get('status')
        if new_status not in self.ORDER_STATUSES:
            self.send_json({'error': 'status ต้องเป็นหนึ่งใน: ' + ', '.join(sorted(self.ORDER_STATUSES))}, 400)
            return
        conn = get_db()
        c = conn.cursor()
        row = c.execute("SELECT status, customer_id, total FROM orders WHERE id=?", (oid,)).fetchone()
        if row is None:
            conn.close()
            self.send_json({'error': 'ไม่พบออเดอร์นี้'}, 404)
            return
        # เดิมยกเลิกออเดอร์แล้วสต๊อกที่ถูกตัดตอน _create_order ไม่เคยถูกคืนเลย -- สต๊อกจริงลดลง
        # ถาวรทุกครั้งที่ยกเลิก คืนสต๊อกเมื่อเปลี่ยนเข้า 'cancelled' จากสถานะที่ยังไม่ยกเลิก และ
        # ตัดกลับเมื่อ "ยกเลิกการยกเลิก" (cancelled -> active) เพื่อไม่ให้ได้สต๊อกฟรีจากการสลับสถานะ
        was_cancelled = (row['status'] == 'cancelled')
        now_cancelled = (new_status == 'cancelled')
        if now_cancelled != was_cancelled:
            items = c.execute("SELECT product_id, qty FROM order_items WHERE order_id=?", (oid,)).fetchall()
            # "ยกเลิกการยกเลิก" (cancelled -> active) ตัดสต๊อกกลับด้วย MAX(0,stock-qty) เดิม -- แต่
            # _create_order กันการสั่งเกินสต๊อกไว้ ส่วนนี้ไม่ได้กัน จึงเกิด overselling จากการสลับ
            # สถานะได้: A สั่ง 5 (สต๊อก 5->0) -> ยกเลิก (0->5) -> B สั่ง 5 (5->0) -> un-cancel A ->
            # MAX(0,0-5)=0 ออเดอร์ A กลับมา active อ้างของ 5 ชิ้นที่ไม่มีจริง (floor ที่ 0 กลบไว้)
            # ตรวจสต๊อกให้พอก่อน un-cancel เหมือน _create_order (รวม qty ต่อ product_id เผื่อซ้ำ) --
            # ถ้าไม่พอ ปฏิเสธ 400 แทนที่จะเสกออเดอร์ที่ทำจริงไม่ได้ให้ฟื้น
            if not now_cancelled:
                need = {}
                for it in items:
                    if it['product_id'] is not None:
                        need[it['product_id']] = need.get(it['product_id'], 0) + it['qty']
                for pid, want in need.items():
                    prow = c.execute("SELECT name, stock FROM products WHERE id=?", (pid,)).fetchone()
                    if prow is not None and want > prow['stock']:
                        conn.close()
                        self.send_json({'error': f'ยกเลิกการยกเลิกไม่ได้: สต๊อกไม่พอสำหรับ "{prow["name"]}" (มี {prow["stock"]} ต้องการ {want})'}, 400)
                        return
            for it in items:
                if it['product_id'] is None:
                    continue
                if now_cancelled:
                    c.execute("UPDATE products SET stock=stock+? WHERE id=?", (it['qty'], it['product_id']))
                else:
                    c.execute("UPDATE products SET stock=MAX(0,stock-?) WHERE id=?", (it['qty'], it['product_id']))
            # ยอดใช้จ่ายของลูกค้าต้องขยับสมมาตรกับสต๊อกด้วย: _create_order เพิ่ม total_orders/total_spent
            # ให้ลูกค้าตอนสร้างออเดอร์ แต่เดิมตอนยกเลิกกลับไม่ลดคืนเลย -- ลูกค้าที่สั่งแล้วยกเลิกจึงมี
            # ยอดใช้จ่ายค้าง (total_spent ใช้จัดอันดับลูกค้า/VIP ที่ _get_customers ORDER BY total_spent)
            # ทำให้คนที่ไม่ได้จ่ายจริงลอยขึ้นเป็นลูกค้าท็อป กันยอดติดลบด้วย MAX(0,...) เผื่อข้อมูลเพี้ยน
            if row['customer_id'] is not None:
                amt = row['total'] or 0
                if now_cancelled:
                    c.execute("UPDATE customers SET total_orders=MAX(0,total_orders-1), total_spent=MAX(0,total_spent-?) WHERE id=?",
                              (amt, row['customer_id']))
                else:
                    c.execute("UPDATE customers SET total_orders=total_orders+1, total_spent=total_spent+? WHERE id=?",
                              (amt, row['customer_id']))
        c.execute("UPDATE orders SET status=? WHERE id=?", (new_status, oid))
        conn.commit()
        conn.close()
        self.send_json({'success': True, 'id': oid, 'status': new_status})

    # ──────────────────────────────────────────
    # CUSTOMERS
    # ──────────────────────────────────────────

    def _get_customers(self, query={}):
        conn = get_db()
        c = conn.cursor()
        sql = "SELECT * FROM customers"
        params = []
        if q := query.get('q'):
            sql += " WHERE name LIKE ? OR email LIKE ? OR phone LIKE ? OR line_display_name LIKE ?"
            params.extend([f'%{q}%']*4)
        if tag := query.get('tag'):
            sep = " AND " if params else " WHERE "
            sql += f"{sep}tag=?"
            params.append(tag)
        sql += " ORDER BY total_spent DESC"
        c.execute(sql, params)
        customers = [dict(r) for r in c.fetchall()]
        conn.close()
        self.send_json({'customers': customers, 'total': len(customers)})

    def _get_customer(self, cid):
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM customers WHERE id=?", (cid,))
        row = c.fetchone()
        if not row:
            conn.close()
            return self.send_json({'error': 'Not found'}, 404)
        customer = dict(row)
        c.execute("SELECT * FROM orders WHERE customer_id=? ORDER BY created_at DESC LIMIT 10", (cid,))
        orders = [dict(r) for r in c.fetchall()]
        c.execute("SELECT * FROM line_messages WHERE customer_id=? ORDER BY created_at DESC LIMIT 20", (cid,))
        messages = [dict(r) for r in c.fetchall()]
        conn.close()
        customer['orders'] = orders
        customer['messages'] = messages
        self.send_json(customer)

    # อีเมลไม่บังคับ (ลูกค้าหน้าร้าน/LINE อาจไม่มี) แต่ถ้าใส่มาต้องเป็นรูปแบบที่ใช้ได้จริง
    EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

    def _create_customer(self, body):
        # ตรวจก่อนบันทึกตามแนวเดียวกับ _create_order/_create_product -- เดิม _create_customer
        # ยิง INSERT ด้วยชื่อว่าง ('') ได้ทันที (คอลัมน์ name เป็น NOT NULL ซึ่งกันแค่ NULL ไม่กัน
        # empty string) → มีลูกค้า "ไม่มีชื่อ" โผล่ในรายการ/นับใน total_customers ติดต่อไม่ได้
        name = (body.get('name') or '').strip()
        if not name:
            self.send_json({'error': 'name ต้องไม่ว่าง'}, 400)
            return
        email = (body.get('email') or '').strip()
        if email and not self.EMAIL_RE.match(email):
            self.send_json({'error': 'อีเมลไม่ถูกต้อง'}, 400)
            return
        conn = get_db()
        c = conn.cursor()
        c.execute("""INSERT INTO customers (name,email,phone,line_user_id,line_display_name,tag)
                     VALUES (?,?,?,?,?,?)""",
                  (name, email, body.get('phone',''),
                   body.get('line_user_id',''), body.get('line_display_name',''),
                   body.get('tag','ทั่วไป')))
        cid = c.lastrowid
        conn.commit()
        c.execute("SELECT * FROM customers WHERE id=?", (cid,))
        conn.close()
        self.send_json({'id': cid, 'success': True}, 201)

    def _update_customer(self, cid, body):
        # กันการ "อัปเดตทับ" ชื่อให้ว่าง หรือใส่อีเมลผิดรูปแบบ (validate เฉพาะฟิลด์ที่ส่งมาแก้)
        if 'name' in body and not (body.get('name') or '').strip():
            self.send_json({'error': 'name ต้องไม่ว่าง'}, 400)
            return
        if 'email' in body:
            em = (body.get('email') or '').strip()
            if em and not self.EMAIL_RE.match(em):
                self.send_json({'error': 'อีเมลไม่ถูกต้อง'}, 400)
                return
        conn = get_db()
        # เดิม: PUT id ที่ไม่มีจริง → UPDATE ไม่โดนแถวไหน แต่ยังตอบ {'success':True} (200) เสมอ —
        # แอดมินแก้ลูกค้าที่ไม่มีอยู่/พิมพ์ id ผิด ก็เห็นว่า "สำเร็จ" ทั้งที่ไม่มีอะไรเปลี่ยน ตรวจก่อน
        # ตอบ 404 ให้ตรงกับ _delete_product/_confirm_payment ที่ 404 บน record ที่ไม่มี
        if conn.execute("SELECT id FROM customers WHERE id=?", (cid,)).fetchone() is None:
            conn.close()
            self.send_json({'error': 'ไม่พบลูกค้านี้'}, 404)
            return
        fields = []
        params = []
        for f in ['name','email','phone','tag']:
            if f in body:
                fields.append(f"{f}=?")
                params.append(body[f])
        if fields:
            params.append(cid)
            conn.execute(f"UPDATE customers SET {','.join(fields)} WHERE id=?", params)
            conn.commit()
        conn.close()
        self.send_json({'success': True})

    # ──────────────────────────────────────────
    # PAYMENTS
    # ──────────────────────────────────────────

    def _get_payments(self, query={}):
        conn = get_db()
        c = conn.cursor()
        sql = "SELECT p.*, o.customer_name FROM payments p LEFT JOIN orders o ON o.id=p.order_id ORDER BY p.created_at DESC"
        c.execute(sql)
        payments = [dict(r) for r in c.fetchall()]

        c.execute("SELECT COALESCE(SUM(amount),0) FROM payments WHERE status='paid'")
        total_paid = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM payments WHERE status='pending'")
        pending_count = c.fetchone()[0]
        conn.close()
        self.send_json({'payments': payments, 'total_paid': total_paid, 'pending_count': pending_count})

    def _create_qr(self, body):
        # เดิม phone default เป็น '0800000000' -- ถ้า caller ไม่ส่ง phone มา QR จะถูกสร้างชี้ไปเบอร์
        # ปลอมนี้แบบเงียบๆ (เป็น QR ที่ valid แต่เงินลูกค้าเข้าเบอร์อื่น ไม่ใช่ร้าน) frontend มาร์ค
        # required อยู่แล้วแต่ backend ต้องกันเอง -- ต้องมีพร้อมเพย์จริง (มือถือ 10 / บัตร 13 / e-wallet 15)
        phone = (body.get('phone') or '').strip()
        if len(re.sub(r'\D', '', phone)) < 10:
            self.send_json({'error': 'ต้องระบุพร้อมเพย์ของร้าน (เบอร์มือถือ เลขบัตรประชาชน หรือ e-wallet) ก่อนสร้าง QR'}, 400)
            return
        try:
            amount = float(body.get('amount', 0))
        except (TypeError, ValueError):
            self.send_json({'error': 'amount ต้องเป็นตัวเลข'}, 400)
            return
        # float() รับ "nan"/"inf"/"-inf" โดยไม่โยน ValueError และ NaN/Infinity ลอดผ่าน `amount < 0`
        # ด้านล่างได้ (nan<0 และ inf<0 เป็น False ทั้งคู่) -- ถ้าปล่อยไป แถว payments จะบันทึกยอด
        # NaN/inf แล้ว SUM(amount) ของรายได้ทั้งร้านกลายเป็น NaN/inf ถาวร (เพี้ยนหนักกว่ายอดติดลบ
        # ที่โค้ดนี้กันไว้แล้วด้วยเหตุผลเดียวกัน) -- รับเฉพาะตัวเลขจำกัดเท่านั้น
        if not math.isfinite(amount):
            self.send_json({'error': 'amount ต้องเป็นตัวเลขจำกัด (ไม่รับ NaN/Infinity)'}, 400)
            return
        # amount=0 (หรือเว้นว่าง) = QR แบบให้ผู้จ่ายกรอกยอดเอง (generate_promptpay_payload
        # จะไม่ใส่ tag จำนวนเงิน) -- อนุญาต แต่ค่าติดลบไม่มีความหมาย: QR จะกลายเป็นแบบไม่ระบุยอด
        # เงียบๆ ขณะที่แถว payments กลับถูกบันทึกยอดติดลบ ทำให้ยอดรวมรายได้/สถิติเพี้ยน -- ปฏิเสธไป
        if amount < 0:
            self.send_json({'error': 'amount ต้องไม่ติดลบ (ใส่ 0 หรือเว้นว่างสำหรับ QR แบบให้ผู้จ่ายกรอกยอดเอง)'}, 400)
            return
        order_id = body.get('order_id')
        payload = generate_promptpay_payload(phone, amount)
        ref_code = base64.b32encode(os.urandom(5)).decode()[:8]

        conn = get_db()
        c = conn.cursor()
        c.execute("""INSERT INTO payments (order_id,method,amount,status,qr_payload,ref_code)
                     VALUES (?,?,?,?,?,?)""",
                  (order_id, 'promptpay', amount, 'pending', payload, ref_code))
        pid = c.lastrowid
        conn.commit()
        conn.close()

        # Return payload for frontend to render QR
        qr_url = f"https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={urllib.parse.quote(payload)}"
        self.send_json({
            'id': pid,
            'payload': payload,
            'qr_url': qr_url,
            'ref_code': ref_code,
            'amount': amount,
            'phone': phone
        })

    def _confirm_payment(self, body):
        pay_id = body.get('id')
        # เดิมยิง UPDATE ด้วย id อะไรก็ได้ (รวม None ตอนไม่ส่ง id มา) แล้วตอบ success:True เสมอ
        # แม้ไม่มีแถวไหนถูกแก้เลย -- แอดมินกดยืนยันการชำระของใบที่ไม่มีอยู่/พิมพ์ id ผิด ก็เห็นว่า
        # "สำเร็จ" ทั้งที่ไม่มีอะไรเกิดขึ้นจริง ตรวจว่ามีรายการชำระอยู่จริงก่อน ไม่งั้นตอบ 404
        conn = get_db()
        c = conn.cursor()
        row = c.execute("SELECT id, order_id FROM payments WHERE id=?", (pay_id,)).fetchone()
        if row is None:
            conn.close()
            self.send_json({'error': 'ไม่พบรายการชำระเงินนี้'}, 404)
            return
        c.execute("UPDATE payments SET status='paid' WHERE id=?", (pay_id,))
        # เดิมยืนยันการชำระอัปเดตแค่แถว payments -- ออเดอร์ที่ผูกอยู่ค้างสถานะ 'pending' ตลอดไป
        # POS จึงแสดงว่า "จ่ายแล้ว" แต่ออเดอร์ยังค้างคิว และ pending_orders บน dashboard ค้างเกิน
        # จริง เลื่อนออเดอร์ pending -> paid เมื่อยืนยันการชำระ เฉพาะเมื่อยังเป็น 'pending' เท่านั้น
        # (WHERE status='pending') เพื่อไม่ทับสถานะที่เดินหน้าไปแล้ว (shipped/delivered) หรือปลุก
        # ออเดอร์ที่ยกเลิกไปแล้วกลับมา ไม่กระทบสต๊อก/ยอดใช้จ่ายลูกค้าเพราะ side effect เหล่านั้นผูก
        # กับ transition 'cancelled' ใน _update_order_status เท่านั้น ('paid' ไม่แตะสต๊อก)
        order_updated = False
        if row['order_id'] is not None:
            c.execute("UPDATE orders SET status='paid' WHERE id=? AND status='pending'", (row['order_id'],))
            order_updated = c.rowcount > 0
        conn.commit()
        conn.close()
        self.send_json({'success': True, 'id': row['id'], 'status': 'paid', 'order_updated': order_updated})

    # ──────────────────────────────────────────
    # LINE WEBHOOK
    # ──────────────────────────────────────────

    def _line_webhook(self, body):
        events = body.get('events', [])
        conn = get_db()
        c = conn.cursor()
        for event in events:
            user_id = event.get('source', {}).get('userId', '')
            event_type = event.get('type', '')
            # บาง event (group/room หรือ event ที่ไม่มี user source) ไม่มี userId -- เดิม follow ที่ไม่มี
            # userId จะสร้างลูกค้าขยะ "LINE User " (ชื่อ/line_user_id ว่าง) และ message ก็ log แถวขยะ
            # ที่ผูกกับใครไม่ได้ ข้ามไปถ้าไม่มี userId เพราะทั้งสองเคสต้องใช้ userId ในการอ้างลูกค้า
            if not user_id:
                continue
            if event_type == 'follow':
                # Add new customer from LINE
                c.execute("SELECT id FROM customers WHERE line_user_id=?", (user_id,))
                existing = c.fetchone()
                if not existing:
                    c.execute("""INSERT INTO customers (name,line_user_id,line_display_name,tag)
                                 VALUES (?,?,?,?)""",
                              (f"LINE User {user_id[:8]}", user_id, user_id[:8], 'LINE'))
                    new_cid = c.lastrowid
                    # A message event can arrive before its follow (a re-messaging user, or a follow
                    # event we never received): those rows were logged with customer_id=NULL but keep
                    # the line_user_id. _get_customer's history queries WHERE customer_id=?, so without
                    # this back-link the user's earlier messages would be invisible in their own thread
                    # even after they become a customer. Claim the orphaned messages for the new record.
                    c.execute("UPDATE line_messages SET customer_id=? WHERE line_user_id=? AND customer_id IS NULL",
                              (new_cid, user_id))
            elif event_type == 'message':
                msg_text = event.get('message', {}).get('text', '')
                c.execute("SELECT id FROM customers WHERE line_user_id=?", (user_id,))
                row = c.fetchone()
                cid = row[0] if row else None
                c.execute("""INSERT INTO line_messages (customer_id,line_user_id,message,direction)
                             VALUES (?,?,?,?)""", (cid, user_id, msg_text, 'in'))
        conn.commit()
        conn.close()
        self.send_json({'status': 'ok'})

    def _line_broadcast(self, body):
        message = body.get('message', '')
        channel_token = body.get('channel_token', '')

        # ตรวจข้อความก่อนยิง/บันทึก -- เดิมไม่ตรวจเลย: ข้อความว่าง (หรือมีแต่ช่องว่าง) กับข้อความ
        # ยาวเกิน 5000 ตัวอักษร ล้วนถูก LINE API ปฏิเสธด้วย HTTP 400 อยู่แล้ว แต่โค้ดกลับยิง API
        # ที่รู้อยู่แล้วว่าล้มเหลว และในโหมด simulate (ไม่มี token) ยัง INSERT log การ broadcast
        # ที่ว่างเปล่าแล้วตอบ success -- ทำให้ประวัติ/สถิติมีรายการ broadcast ปลอมที่ไม่เคยส่งอะไร
        # ตรวจก่อนตามแนวเดียวกับ _create_order/_create_product แล้วตอบ 400 ที่อ่านได้
        if not (message or '').strip():
            self.send_json({'error': 'message ต้องไม่ว่าง'}, 400)
            return
        if len(message) > 5000:
            self.send_json({'error': 'message ยาวเกิน 5000 ตัวอักษร (เกินลิมิตข้อความของ LINE)'}, 400)
            return

        # Log broadcast attempt
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM customers WHERE line_user_id != '' AND line_user_id IS NOT NULL")
        line_count = c.fetchone()[0]
        # If no real token, simulate
        if channel_token and len(channel_token) > 20:
            try:
                req_data = json.dumps({
                    "messages": [{"type": "text", "text": message}]
                }).encode('utf-8')
                req = urllib.request.Request(
                    f'{LINE_API_BASE}/v2/bot/message/broadcast',
                    data=req_data,
                    headers={
                        'Content-Type': 'application/json',
                        'Authorization': f'Bearer {channel_token}'
                    }
                )
                urllib.request.urlopen(req, timeout=10)
                status = 'sent'
            except Exception as e:
                # เดิม: ยิง API ล้มเหลว (token ผิด/เน็ตล่ม/LINE ตอบ error) แต่ยัง INSERT log broadcast
                # เป็น 'out' แล้วตอบ success:True -- เจ้าของร้านเห็นว่า "ส่งโปรโมชั่นถึง N คนแล้ว" +
                # มีประวัติ ทั้งที่ลูกค้าไม่ได้รับอะไรเลย ตอนนี้: ไม่บันทึก log ที่ไม่ได้ส่งจริง และ
                # ตอบ 502 ที่อ่านได้ (ต่างจาก simulate mode ที่ตั้งใจ log เพราะไม่มี token = โหมดทดสอบ)
                conn.close()
                self.send_json({'error': f'ส่ง broadcast ไม่สำเร็จ: {str(e)}', 'success': False}, 502)
                return
        else:
            status = 'simulated (ไม่มี Channel Token จริง)'
        # Save broadcast log — reached only when the message was actually sent ('sent') or when
        # running without a token (simulate mode). A genuine send-failure returns above and is
        # NOT logged, so the broadcast history can't show a promo that never went out.
        c.execute("""INSERT INTO line_messages (customer_id,line_user_id,message,direction)
                     VALUES (NULL,'BROADCAST',?,?)""", (message, 'out'))
        conn.commit()
        conn.close()
        self.send_json({'success': True, 'status': status, 'recipients': line_count})

    def _get_line_messages(self, query={}):
        conn = get_db()
        c = conn.cursor()
        c.execute("""SELECT lm.*, c.name as customer_name, c.line_display_name
                     FROM line_messages lm LEFT JOIN customers c ON c.id=lm.customer_id
                     ORDER BY lm.created_at DESC LIMIT 50""")
        messages = [dict(r) for r in c.fetchall()]
        conn.close()
        self.send_json({'messages': messages})

    # ──────────────────────────────────────────
    # TIKTOK
    # ──────────────────────────────────────────

    def _get_tiktok_orders(self, query={}):
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM tiktok_orders ORDER BY created_at DESC")
        orders = [dict(r) for r in c.fetchall()]
        conn.close()
        self.send_json({'orders': orders, 'total': len(orders)})

    def _get_tiktok_ads(self, query={}):
        conn = get_db()
        c = conn.cursor()
        c.execute("""SELECT campaign_name,
                            SUM(impressions) as impressions, SUM(clicks) as clicks,
                            SUM(spend) as spend, SUM(revenue) as revenue,
                            CASE WHEN SUM(spend)>0 THEN ROUND(SUM(revenue)/SUM(spend),2) ELSE 0 END as roas
                     FROM tiktok_ads GROUP BY campaign_name ORDER BY revenue DESC""")
        campaigns = [dict(r) for r in c.fetchall()]
        c.execute("""SELECT date, SUM(spend) as spend, SUM(revenue) as revenue
                     FROM tiktok_ads GROUP BY date ORDER BY date DESC LIMIT 30""")
        daily = [dict(r) for r in c.fetchall()]
        conn.close()
        self.send_json({'campaigns': campaigns, 'daily': daily})

    # ──────────────────────────────────────────
    # ANALYTICS
    # ──────────────────────────────────────────

    def _get_analytics(self, query={}):
        conn = get_db()
        c = conn.cursor()
        # ?days=abc เดิมโยน ValueError → คำขอตายแบบ empty reply (do_GET ไม่มี try/except)
        try:
            days = int(query.get('days', 30))
        except (TypeError, ValueError):
            days = 30
        days = max(1, min(365, days))
        start = (date.today() - timedelta(days=days)).isoformat()

        c.execute("""SELECT date(created_at) as day,
                            COALESCE(SUM(total),0) as revenue,
                            COUNT(*) as orders
                     FROM orders WHERE date(created_at)>=? AND status!='cancelled'
                     GROUP BY date(created_at) ORDER BY day""", (start,))
        revenue_trend = [dict(r) for r in c.fetchall()]

        c.execute("""SELECT date(created_at) as day, COUNT(*) as new_customers
                     FROM customers WHERE date(created_at)>=?
                     GROUP BY date(created_at) ORDER BY day""", (start,))
        customer_trend = [dict(r) for r in c.fetchall()]

        c.execute("""SELECT channel, COUNT(*) as orders, COALESCE(SUM(total),0) as revenue
                     FROM orders WHERE status!='cancelled'
                     GROUP BY channel""")
        by_channel = [dict(r) for r in c.fetchall()]

        # Join orders and exclude cancelled ones, same as every other query in this
        # endpoint (revenue_trend / by_channel / total_revenue all filter status!='cancelled').
        # Without the join a cancelled order still counted its qty + revenue here, inflating
        # the best-seller list — same bug fixed in _get_dashboard_stats.
        c.execute("""SELECT p.name, p.category, SUM(oi.qty) as sold,
                            SUM(oi.qty*oi.price) as revenue
                     FROM order_items oi
                     JOIN products p ON p.id=oi.product_id
                     JOIN orders o ON o.id=oi.order_id
                     WHERE o.status!='cancelled'
                     GROUP BY oi.product_id ORDER BY revenue DESC LIMIT 10""")
        top_products = [dict(r) for r in c.fetchall()]

        c.execute("SELECT COALESCE(SUM(total),0) FROM orders WHERE status!='cancelled'")
        total_revenue = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM orders WHERE status!='cancelled'")
        total_orders = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM customers")
        total_customers = c.fetchone()[0]

        conn.close()
        self.send_json({
            'revenue_trend': revenue_trend,
            'customer_trend': customer_trend,
            'by_channel': by_channel,
            'top_products': top_products,
            'total_revenue': total_revenue,
            'total_orders': total_orders,
            'total_customers': total_customers
        })

    # ──────────────────────────────────────────
    # SETTINGS
    # ──────────────────────────────────────────

    def _get_settings(self):
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT key, value FROM settings")
        rows = {r[0]: r[1] for r in c.fetchall()}
        conn.close()
        self.send_json(rows)

    def _save_settings(self, body):
        if not isinstance(body, dict):
            self.send_json({'error': 'settings ต้องเป็น object ของ key/value'}, 400)
            return
        conn = get_db()
        c = conn.cursor()
        for key, value in body.items():
            c.execute("INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)", (key, str(value)))
        conn.commit()
        conn.close()
        self.send_json({'success': True})


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    print(f"""
╔═══════════════════════════════════════╗
║          Smart-E Server               ║
║  E-Commerce + LINE + TikTok + Pay     ║
╠═══════════════════════════════════════╣
║  URL: http://localhost:{PORT}           ║
║  API: http://localhost:{PORT}/api/      ║
╚═══════════════════════════════════════╝
    """)
    server = http.server.HTTPServer(('0.0.0.0', PORT), SmartEHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
