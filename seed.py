"""
Smart-E - Seed Mock Data
Run: python3 seed.py
"""
import sqlite3
import random
import os
from datetime import datetime, date, timedelta

DB_PATH = os.path.join(os.path.expanduser("~"), "smart_e.db")

PRODUCTS = [
    ("ครีมบำรุงผิวหน้า Vitamin C", "ครีมบำรุงผิวหน้าสูตรพิเศษ วิตามินซีเข้มข้น", 490, 150, "สกินแคร์"),
    ("เซรั่มไฮยาลูรอน", "เซรั่มเข้มข้น เพิ่มความชุ่มชื้น 72 ชั่วโมง", 890, 80, "สกินแคร์"),
    ("ครีมกันแดด SPF50+", "กันแดดเนื้อบางเบา ไม่อุดตัน PA++++", 350, 200, "สกินแคร์"),
    ("มาสก์หน้าคอลลาเจน 10 แผ่น", "มาสก์ผ้าคอลลาเจนบริสุทธิ์ ชุ่มชื้นทันที", 299, 300, "มาสก์"),
    ("สบู่อาบน้ำออร์แกนิค", "สบู่ธรรมชาติ 100% สูตร Shea Butter", 180, 500, "ผลิตภัณฑ์อาบน้ำ"),
    ("แชมพูลดการหลุดร่วง", "แชมพูสมุนไพรไทย ลดผมร่วง เพิ่มปริมาณ", 280, 180, "เส้นผม"),
    ("โลชั่นบำรุงผิวกาย", "โลชั่นบำรุงผิวกาย กลิ่นดอกซากุระ 400ml", 220, 250, "ผลิตภัณฑ์อาบน้ำ"),
    ("คลีนซิ่งออยล์", "น้ำมันทำความสะอาดเครื่องสำอาง สูตรอ่อนโยน", 420, 120, "ทำความสะอาด"),
    ("โทนเนอร์น้ำตบหน้า", "โทนเนอร์บำรุงผิว เนื้อน้ำเบาบาง สำหรับทุกสภาพผิว", 380, 90, "สกินแคร์"),
    ("ฟิลเลอร์ริ้วรอย Retinol", "ครีมลดริ้วรอย Retinol 0.3% เห็นผลใน 4 สัปดาห์", 750, 60, "สกินแคร์"),
    ("น้ำตาลขัดผิว Coffee Scrub", "สครับผิวกาย กากกาแฟออร์แกนิค", 195, 400, "ผลิตภัณฑ์อาบน้ำ"),
    ("มาสก์โคลนภูเขาไฟ", "มาสก์โคลนภูเขาไฟ ดูดซับไขมันส่วนเกิน", 260, 200, "มาสก์"),
]

CUSTOMERS = [
    ("สมหญิง ใจดี", "somying@gmail.com", "0812345678", "Uf1234567890abcdef", "สมหญิง", "VIP"),
    ("มานะ รักงาน", "mana@hotmail.com", "0823456789", "Uf2345678901bcdefg", "มานะ", "ประจำ"),
    ("วันดี สุขสม", "wandee@yahoo.com", "0834567890", "", "", "ทั่วไป"),
    ("ประเสริฐ ดีมาก", "prasert@gmail.com", "0845678901", "Uf3456789012cdefgh", "เอ็ม", "ประจำ"),
    ("ลดา ฟ้าใส", "lada@outlook.com", "0856789012", "", "", "ทั่วไป"),
    ("สุชาติ แม่นยำ", "suchat@gmail.com", "0867890123", "Uf4567890123defghi", "ต้อม", "VIP"),
    ("นภาพร พรหมสวัสดิ์", "naphaporn@gmail.com", "0878901234", "", "", "ทั่วไป"),
    ("กิตติชัย ไชยยา", "kittichai@hotmail.com", "0889012345", "Uf5678901234efghij", "กิ๊ต", "ประจำ"),
    ("อรุณี วงศ์ดี", "arunee@gmail.com", "0890123456", "", "", "ใหม่"),
    ("ธนพล สมบูรณ์", "thanapon@gmail.com", "0801234567", "Uf6789012345fghijk", "เบิ้ม", "VIP"),
    ("ปรียา ชาญวิชัย", "preeya@yahoo.com", "0811234568", "", "", "ใหม่"),
    ("ชนากานต์ ปิยะมิตร", "chanakan@gmail.com", "0822345679", "Uf7890123456ghijkl", "นก", "ประจำ"),
]

CHANNELS = ['web', 'line', 'tiktok']
STATUS_LIST = ['pending', 'confirmed', 'shipped', 'delivered', 'cancelled']
TIKTOK_CAMPAIGNS = [
    "สกินแคร์ฤดูร้อน 2024",
    "Flash Sale ลดกระหน่ำ 50%",
    "New Arrivals - มาสก์คอลลาเจน",
    "Brand Awareness - Smart-E",
    "Retargeting - VIP Customers",
]

def random_date(days_back=90):
    d = date.today() - timedelta(days=random.randint(0, days_back))
    h = random.randint(8, 22)
    m = random.randint(0, 59)
    return f"{d} {h:02d}:{m:02d}:00"

def seed():
    # Import and init DB first
    import sys
    sys.path.insert(0, os.path.dirname(__file__))
    from server import init_db
    init_db()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Check if already seeded
    c.execute("SELECT COUNT(*) FROM products")
    if c.fetchone()[0] > 0:
        print("✅ ข้อมูล mock ถูก seed แล้ว (ไม่ต้อง seed ซ้ำ)")
        conn.close()
        return

    print("🌱 กำลัง seed ข้อมูล mock...")

    # Products
    prod_ids = []
    for name, desc, price, stock, cat in PRODUCTS:
        c.execute("""INSERT INTO products (name,description,price,stock,category,created_at)
                     VALUES (?,?,?,?,?,?)""",
                  (name, desc, price, stock, cat, random_date(180)))
        prod_ids.append(c.lastrowid)

    # Customers
    cust_ids = []
    for name, email, phone, line_uid, line_name, tag in CUSTOMERS:
        c.execute("""INSERT INTO customers (name,email,phone,line_user_id,line_display_name,tag,created_at)
                     VALUES (?,?,?,?,?,?,?)""",
                  (name, email, phone, line_uid, line_name, tag, random_date(90)))
        cust_ids.append(c.lastrowid)

    # Orders (120 orders over 90 days)
    for _ in range(120):
        cid = random.choice(cust_ids)
        c.execute("SELECT name FROM customers WHERE id=?", (cid,))
        cname = c.fetchone()[0]
        channel = random.choice(CHANNELS)
        weights = [0.5, 0.3, 0.1, 0.05, 0.05]
        status = random.choices(STATUS_LIST, weights=weights)[0]
        n_items = random.randint(1, 3)
        items = random.sample(list(zip(prod_ids, PRODUCTS)), min(n_items, len(PRODUCTS)))
        total = 0
        created = random_date(90)
        c.execute("""INSERT INTO orders (customer_id,customer_name,status,channel,total,created_at)
                     VALUES (?,?,?,?,0,?)""", (cid, cname, status, channel, created))
        oid = c.lastrowid
        for pid, prod_data in items:
            qty = random.randint(1, 3)
            price = prod_data[2]  # price
            total += qty * price
            c.execute("""INSERT INTO order_items (order_id,product_id,product_name,qty,price)
                         VALUES (?,?,?,?,?)""", (oid, pid, prod_data[0], qty, price))
        c.execute("UPDATE orders SET total=? WHERE id=?", (total, oid))
        c.execute("UPDATE customers SET total_orders=total_orders+1, total_spent=total_spent+? WHERE id=?",
                  (total, cid))

    # Payments (for delivered/shipped orders)
    c.execute("SELECT id, total FROM orders WHERE status IN ('delivered','shipped')")
    for oid, total in c.fetchall():
        status = 'paid' if random.random() > 0.1 else 'pending'
        c.execute("""INSERT INTO payments (order_id,method,amount,status,created_at)
                     VALUES (?,?,?,?,datetime('now','localtime'))""",
                  (oid, random.choice(['promptpay','credit_card','transfer']), total, status))

    # LINE messages
    line_customers = [(cust_ids[i], CUSTOMERS[i][3]) for i in range(len(CUSTOMERS)) if CUSTOMERS[i][3]]
    msgs_in = ["สวัสดีค่ะ อยากถามเรื่องสินค้า", "ราคาครีมหน้าเท่าไหร่คะ", "สั่งซื้อได้ที่ไหนคะ",
               "ของมาถึงแล้ว ขอบคุณมากค่ะ 😊", "มีแชมพูขนาดใหญ่ไหมคะ"]
    msgs_out = ["สวัสดีค่ะ มีอะไรให้ช่วยไหมคะ?", "ราคา 490 บาทค่ะ 😊", "สั่งซื้อได้ที่ลิงก์นี้เลยนะคะ",
                "ดีใจที่ลูกค้าพอใจค่ะ ขอบคุณที่อุดหนุนนะคะ ❤️", "มีขนาด 200ml และ 400ml นะคะ"]
    for cid, line_uid in line_customers:
        for i in range(random.randint(2, 5)):
            c.execute("""INSERT INTO line_messages (customer_id,line_user_id,message,direction,created_at)
                         VALUES (?,?,?,?,?)""",
                      (cid, line_uid, random.choice(msgs_in), 'in', random_date(30)))
            c.execute("""INSERT INTO line_messages (customer_id,line_user_id,message,direction,created_at)
                         VALUES (?,?,?,?,?)""",
                      (cid, line_uid, random.choice(msgs_out), 'out', random_date(30)))

    # TikTok Orders
    tiktok_items = [("ครีมวิตามินซี x2", 980), ("เซรั่มไฮยาลูรอน x1", 890), ("มาสก์คอลลาเจน x3", 897)]
    for i in range(30):
        items_json = str(random.choice(tiktok_items))
        total = float(items_json.split(',')[1].strip().rstrip(')'))
        status = random.choice(['pending','processing','shipped','delivered'])
        c.execute("""INSERT INTO tiktok_orders (tiktok_order_id,customer_name,items_json,total,status,created_at)
                     VALUES (?,?,?,?,?,?)""",
                  (f"TT{100000+i}", f"TikTok User {i+1}", items_json, total, status, random_date(30)))

    # TikTok Ads
    for day_offset in range(30):
        d = (date.today() - timedelta(days=day_offset)).isoformat()
        for campaign in TIKTOK_CAMPAIGNS:
            impressions = random.randint(5000, 50000)
            clicks = int(impressions * random.uniform(0.02, 0.08))
            spend = round(random.uniform(200, 2000), 2)
            revenue = round(spend * random.uniform(1.5, 6), 2)
            c.execute("""INSERT INTO tiktok_ads (campaign_name,impressions,clicks,spend,revenue,date)
                         VALUES (?,?,?,?,?,?)""",
                      (campaign, impressions, clicks, spend, revenue, d))

    conn.commit()
    conn.close()
    print("✅ Seed สำเร็จ! เพิ่มข้อมูล: 12 สินค้า, 12 ลูกค้า, 120 ออเดอร์, 30 TikTok orders, 150 Ad records")

if __name__ == '__main__':
    seed()
