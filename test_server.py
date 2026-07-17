#!/usr/bin/env python3
"""Regression guard for smart-e's server.py — boots the real server against a
throwaway SQLite db on an alt port and asserts the money/stock/auth invariants
that earlier fixes established (each was verified live once; this makes them
repeatable so they can't silently regress). Pure stdlib, no test framework.

Run:  python3 test_server.py      (exit 0 = pass, 1 = fail)
"""
import json, os, subprocess, sys, tempfile, time, urllib.error, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get('TEST_PORT', '8987'))
KEY = 'test-admin-key'
BASE = f'http://127.0.0.1:{PORT}'
passed = failed = 0


def check(cond, msg):
    global passed, failed
    if cond:
        passed += 1; print(f'  ✅ {msg}')
    else:
        failed += 1; print(f'  ❌ {msg}')


def req(method, path, body=None, key=KEY):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    r.add_header('Content-Type', 'application/json')
    if key is not None:
        r.add_header('X-Admin-Key', key)
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw


def stock(pid):
    return req('GET', f'/api/products/{pid}')[1]['stock']


def spent(cid):
    return req('GET', f'/api/customers/{cid}')[1]['total_spent']


def orders_count(cid):
    return req('GET', f'/api/customers/{cid}')[1]['total_orders']


def top_product(name):
    # returns {'sold':..,'revenue':..} for the named product from the dashboard, or None
    rows = req('GET', '/api/dashboard/stats')[1]['top_products']
    return next((r for r in rows if r['name'] == name), None)


def top_product_analytics(name):
    # same, from /api/analytics (a second top-products query with the same cancel filter)
    rows = req('GET', '/api/analytics')[1]['top_products']
    return next((r for r in rows if r['name'] == name), None)


def parse_tlv(s):
    """Parse an EMVCo QR string into {tag: value}. Top-level only."""
    out = {}
    i = 0
    while i < len(s):
        tag = s[i:i + 2]
        ln = int(s[i + 2:i + 4])
        out[tag] = s[i + 4:i + 4 + ln]
        i = i + 4 + ln
    return out


def crc16_ccitt(payload):
    """CRC-16/CCITT-FALSE over the payload up to and including '6304' — the EMVCo
    checksum a banking app recomputes; if it doesn't match, every app rejects the QR."""
    crc = 0xFFFF
    for ch in payload.encode('utf-8'):
        crc ^= ch << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if (crc & 0x8000) else (crc << 1)
            crc &= 0xFFFF
    return f"{crc:04X}"


def main():
    dbfd, dbpath = tempfile.mkstemp(suffix='.db'); os.close(dbfd); os.remove(dbpath)
    env = {**os.environ, 'SMART_E_DB': dbpath, 'PORT': str(PORT), 'ADMIN_KEY': KEY}
    proc = subprocess.Popen([sys.executable, os.path.join(HERE, 'server.py')],
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        # wait for boot
        for _ in range(50):
            try:
                urllib.request.urlopen(BASE + '/api/products', timeout=2); break
            except urllib.error.HTTPError:
                break  # server is up (even a 401/200 means it answered)
            except Exception:
                time.sleep(0.2)

        print('\n=== auth gate ===')
        st, _ = req('GET', '/api/products', key=None)
        check(st == 401, f'no X-Admin-Key -> 401 (got {st})')
        st, _ = req('GET', '/api/products', key='wrong')
        check(st == 401, f'wrong key -> 401 (got {st})')
        st, _ = req('GET', '/api/products')
        check(st == 200, f'correct key -> 200 (got {st})')

        print('\n=== order input validation ===')
        pid = req('POST', '/api/products', {'name': 'T', 'price': 100, 'stock': 5})[1]['id']
        check(stock(pid) == 5, 'product created with stock 5')
        st, _ = req('POST', '/api/orders', {'items': 'notalist'})
        check(st == 400, f'items not a list -> 400 (got {st})')
        st, _ = req('POST', '/api/orders', {'items': [{'product_id': pid, 'qty': 'x', 'price': 1}]})
        check(st == 400, f'non-numeric qty -> 400 (got {st})')
        st, _ = req('POST', '/api/orders', {'items': [{'product_id': pid, 'qty': 0, 'price': 1}]})
        check(st == 400, f'qty < 1 -> 400 (got {st})')
        st, _ = req('POST', '/api/orders', {'items': [{'product_id': pid, 'qty': 1, 'price': -5}]})
        check(st == 400, f'negative price -> 400 (got {st})')

        print('\n=== phantom-stock guard (oversell + cancel must not conjure stock) ===')
        st, _ = req('POST', '/api/orders', {'items': [{'product_id': pid, 'product_name': 'T', 'qty': 10, 'price': 100}]})
        check(st == 400, f'oversell qty 10 vs stock 5 -> 400 (got {st})')
        check(stock(pid) == 5, 'stock unchanged (still 5) after rejected oversell')
        st, order = req('POST', '/api/orders', {'items': [{'product_id': pid, 'product_name': 'T', 'qty': 3, 'price': 100}]})
        check(st == 201 and stock(pid) == 2, f'valid qty 3 -> 201, stock 5->2 (got {st}, stock {stock(pid)})')
        oid = order['id']
        req('PUT', f'/api/orders/{oid}/status', {'status': 'cancelled'})
        check(stock(pid) == 5, 'cancel restores stock 2->5 symmetrically (no phantom)')
        st, _ = req('POST', '/api/orders', {'items': [
            {'product_id': pid, 'product_name': 'T', 'qty': 3, 'price': 100},
            {'product_id': pid, 'product_name': 'T', 'qty': 3, 'price': 100}]})
        check(st == 400, f'two qty-3 line items of one product vs stock 5 -> 400 (got {st})')
        check(stock(pid) == 5, 'stock unchanged after rejected duplicate-item oversell')

        print('\n=== status-toggle stock accounting (no free stock by flipping status) ===')
        # _update_order_status restores stock on ->cancelled and re-deducts on cancelled->active,
        # gated by `now_cancelled != was_cancelled`. That gate is what stops an admin from minting
        # free stock by cancelling the same order twice (or the reverse). Implemented but untested
        # until now — pin it. Fresh product so earlier assertions' stock state stays isolated.
        pid2 = req('POST', '/api/products', {'name': 'T2', 'price': 50, 'stock': 4})[1]['id']
        st, o2 = req('POST', '/api/orders', {'items': [{'product_id': pid2, 'product_name': 'T2', 'qty': 3, 'price': 50}]})
        oid2 = o2['id']
        check(st == 201 and stock(pid2) == 1, f'order qty 3 -> stock 4->1 (got {st}, stock {stock(pid2)})')
        req('PUT', f'/api/orders/{oid2}/status', {'status': 'cancelled'})
        check(stock(pid2) == 4, 'cancel restores stock 1->4')
        req('PUT', f'/api/orders/{oid2}/status', {'status': 'cancelled'})
        check(stock(pid2) == 4, 'cancel AGAIN is idempotent -> stock stays 4 (not conjured to 7)')
        req('PUT', f'/api/orders/{oid2}/status', {'status': 'confirmed'})
        check(stock(pid2) == 1, 'un-cancel (cancelled->confirmed) re-deducts 3 -> stock 4->1')
        req('PUT', f'/api/orders/{oid2}/status', {'status': 'shipped'})
        check(stock(pid2) == 1, 'active->active (confirmed->shipped) leaves stock untouched (stays 1)')
        st, _ = req('PUT', f'/api/orders/{oid2}/status', {'status': 'bogus'})
        check(st == 400, f'invalid status value -> 400 (got {st})')
        check(stock(pid2) == 1, 'stock untouched after a rejected invalid-status update')

        print('\n=== customer spend accounting (cancel must return spend, symmetric with stock) ===')
        # _create_order bumps the customer's total_orders/total_spent; cancelling an order
        # restores stock but historically left total_spent inflated forever, so a customer who
        # only ever cancels floats to the top of the total_spent-ranked list. Spend must move
        # symmetrically with the order's active state, exactly like stock does above.
        cid = req('POST', '/api/customers', {'name': 'สมชาย ทดสอบ'})[1]['id']
        check(spent(cid) == 0 and orders_count(cid) == 0, 'new customer starts at 0 spent / 0 orders')
        pid3 = req('POST', '/api/products', {'name': 'T3', 'price': 120, 'stock': 10})[1]['id']
        st, o3 = req('POST', '/api/orders', {'customer_id': cid, 'items': [{'product_id': pid3, 'product_name': 'T3', 'qty': 2, 'price': 120}]})
        oid3 = o3['id']
        check(st == 201 and spent(cid) == 240 and orders_count(cid) == 1, f'order 2x120 -> spent 0->240, orders 1 (got spent {spent(cid)}, orders {orders_count(cid)})')
        req('PUT', f'/api/orders/{oid3}/status', {'status': 'cancelled'})
        check(spent(cid) == 0 and orders_count(cid) == 0, f'cancel returns spend 240->0 and orders 1->0 (got spent {spent(cid)}, orders {orders_count(cid)})')
        req('PUT', f'/api/orders/{oid3}/status', {'status': 'cancelled'})
        check(spent(cid) == 0 and orders_count(cid) == 0, 'cancel AGAIN is idempotent -> spend stays 0 (not -240)')
        req('PUT', f'/api/orders/{oid3}/status', {'status': 'confirmed'})
        check(spent(cid) == 240 and orders_count(cid) == 1, f'un-cancel re-adds spend 0->240, orders ->1 (got spent {spent(cid)}, orders {orders_count(cid)})')

        print('\n=== dashboard top-products excludes cancelled orders (same as every other metric) ===')
        # today/monthly/channels/daily revenue all filter status!='cancelled'; top_products used
        # to NOT, so a product ordered then cancelled still counted its qty+revenue and could rank
        # as a best-seller that never actually sold. Pin the consistency.
        pid4 = req('POST', '/api/products', {'name': 'TopProd', 'price': 100, 'stock': 100})[1]['id']
        # one real (kept) order: qty 2 -> sold 2, revenue 200
        req('POST', '/api/orders', {'items': [{'product_id': pid4, 'product_name': 'TopProd', 'qty': 2, 'price': 100}]})
        tp = top_product('TopProd')
        check(tp is not None and tp['sold'] == 2 and tp['revenue'] == 200, f"kept order counts: sold 2 / rev 200 (got {tp})")
        # a second order that gets cancelled: qty 5 -> must NOT be counted
        st, oc = req('POST', '/api/orders', {'items': [{'product_id': pid4, 'product_name': 'TopProd', 'qty': 5, 'price': 100}]})
        req('PUT', f"/api/orders/{oc['id']}/status", {'status': 'cancelled'})
        tp = top_product('TopProd')
        check(tp is not None and tp['sold'] == 2 and tp['revenue'] == 200, f"cancelled order excluded: still sold 2 / rev 200, not 7/700 (got {tp})")
        # /api/analytics has its own top-products query — it must apply the same filter
        ta = top_product_analytics('TopProd')
        check(ta is not None and ta['sold'] == 2 and ta['revenue'] == 200, f"/api/analytics also excludes cancelled: sold 2 / rev 200 (got {ta})")

        print('\n=== product delete guards sales history (no orphaned order_items / lost reports) ===')
        # SQLite has FK off, so a hard DELETE of a sold product would orphan its order_items
        # and erase its past sales from every report. Deleting a never-sold product is fine;
        # deleting a nonexistent one must 404 (not fake success); deleting a sold one must 409.
        pid5 = req('POST', '/api/products', {'name': 'Disposable', 'price': 10, 'stock': 5})[1]['id']
        st, _ = req('DELETE', f'/api/products/{pid5}')
        check(st == 200, f'delete a never-sold product -> 200 (got {st})')
        check(req('GET', f'/api/products/{pid5}')[0] == 404, 'the deleted product is really gone (404)')
        st, _ = req('DELETE', '/api/products/999999')
        check(st == 404, f'delete a nonexistent product -> 404, not fake success (got {st})')
        pid6 = req('POST', '/api/products', {'name': 'Sold', 'price': 30, 'stock': 10})[1]['id']
        req('POST', '/api/orders', {'items': [{'product_id': pid6, 'product_name': 'Sold', 'qty': 1, 'price': 30}]})
        st, body = req('DELETE', f'/api/products/{pid6}')
        check(st == 409, f'delete a product with sales history -> 409 refused (got {st})')
        check(req('GET', f'/api/products/{pid6}')[0] == 200, 'the sold product still exists (history preserved)')

        print('\n=== missing payment confirm -> 404 (not false success) ===')
        st, _ = req('POST', '/api/payments/999999/confirm', {})
        check(st == 404, f'confirm nonexistent payment -> 404 (got {st})')

        print('\n=== confirming a payment advances its linked order pending -> paid ===')
        # A POS operator creates an order, shows a PromptPay QR for it, then confirms once the
        # customer pays. Before this, confirm only flipped the payments row and the order stayed
        # 'pending' forever -- so the order sat in the queue and dashboard pending_orders was
        # inflated even though it was paid. Confirming should carry the linked order pending->paid.
        def order_status(target_id):
            _st, resp = req('GET', '/api/orders')
            for o in (resp.get('orders', []) if isinstance(resp, dict) else []):
                if o.get('id') == target_id:
                    return o.get('status')
            return None
        pidP = req('POST', '/api/products', {'name': 'PayFlow', 'price': 90, 'stock': 5})[1]['id']
        oidP = req('POST', '/api/orders', {'items': [{'product_id': pidP, 'product_name': 'PayFlow', 'qty': 1, 'price': 90}]})[1]['id']
        check(order_status(oidP) == 'pending', 'new order starts pending')
        payP = req('POST', '/api/payments/qr', {'phone': '0812345678', 'amount': 90, 'order_id': oidP})[1]['id']
        st, cbody = req('POST', '/api/payments/confirm', {'id': payP})
        check(st == 200 and cbody.get('order_updated') is True, f'confirm reports order_updated=True (got {st}, {cbody.get("order_updated")})')
        check(order_status(oidP) == 'paid', f'linked order advanced pending -> paid (got {order_status(oidP)})')
        # a QR with no order_id must still confirm fine and simply not touch any order
        payNo = req('POST', '/api/payments/qr', {'phone': '0812345678', 'amount': 50})[1]['id']
        st, cbody2 = req('POST', '/api/payments/confirm', {'id': payNo})
        check(st == 200 and cbody2.get('order_updated') is False, f'orderless payment confirms with order_updated=False (got {st}, {cbody2.get("order_updated")})')
        # confirming again must NOT regress an order that already moved past pending
        req('PUT', f'/api/orders/{oidP}/status', {'status': 'shipped'})
        req('POST', '/api/payments/confirm', {'id': payP})
        check(order_status(oidP) == 'shipped', 'a re-confirm does not drag a shipped order back to paid')

        print('\n=== LINE broadcast validates the message before sending/logging ===')
        # A broadcast is a real outbound action. An empty/whitespace message and a >5000-char
        # message are both rejected by LINE's API (HTTP 400), so firing them is a guaranteed-failed
        # call -- and in simulate mode (no token) the old code still logged a blank broadcast as a
        # success. Guard before the send/log, like every other _create_* handler.
        st, _ = req('POST', '/api/line/broadcast', {'message': ''})
        check(st == 400, f'empty broadcast message -> 400 (got {st})')
        st, _ = req('POST', '/api/line/broadcast', {'message': '   \n  '})
        check(st == 400, f'whitespace-only broadcast message -> 400 (got {st})')
        st, _ = req('POST', '/api/line/broadcast', {'message': 'x' * 5001})
        check(st == 400, f'over-5000-char broadcast message -> 400 (got {st})')
        st, b = req('POST', '/api/line/broadcast', {'message': 'โปรโมชั่นวันนี้ ลด 20%'})
        check(st == 200 and b.get('success') is True, f'a valid broadcast still succeeds (got {st})')
        check(str(b.get('status', '')).startswith('simulated'), 'no real token -> simulated (not an actual send)')

        print('\n=== PromptPay QR payload (EMVCo structure + CRC + static/dynamic method) ===')
        # The QR is what a customer actually scans to pay. If the CRC-16 or TLV structure is
        # wrong, every banking app rejects it. And the Point of Initiation Method (tag 01) must
        # match reuse semantics: "12" = dynamic/single-use when an amount is embedded, "11" =
        # static/reusable when the payer fills in the amount (the amount=0 case _create_qr
        # supports). It was hardcoded "12" for both, so a reusable "fill-in-amount" QR was
        # advertised as single-use (some apps blackhole a reused "12"). Assert both cases here.
        st, qr = req('POST', '/api/payments/qr', {'phone': '0812345678', 'amount': 150})
        check(st == 200 and 'payload' in qr, f'qr create with amount -> 200 + payload (got {st})')
        d = parse_tlv(qr['payload'])
        check(d.get('00') == '01', 'tag00 payload-format-indicator == "01"')
        check(d.get('01') == '12', f'tag01 == "12" (dynamic) when amount embedded (got {d.get("01")!r})')
        check(d.get('53') == '764', 'tag53 currency == "764" (THB)')
        check(d.get('54') == '150.00', f'tag54 amount == "150.00" (got {d.get("54")!r})')
        check(d.get('58') == 'TH', 'tag58 country == "TH"')
        check(d.get('29', '').startswith('0016A000000677010111'),
              'tag29 merchant account carries the PromptPay AID')
        p = qr['payload']
        check(p[-4:] == crc16_ccitt(p[:-4]), f'CRC-16 valid (appended {p[-4:]})')

        st, qr0 = req('POST', '/api/payments/qr', {'phone': '0812345678'})  # no amount
        check(st == 200, f'qr create without amount -> 200 (got {st})')
        d0 = parse_tlv(qr0['payload'])
        check(d0.get('01') == '11', f'tag01 == "11" (static/reusable) when no amount (got {d0.get("01")!r})')
        check('54' not in d0, 'no tag54 amount on a fill-in-amount QR')
        p0 = qr0['payload']
        check(p0[-4:] == crc16_ccitt(p0[:-4]), f'CRC-16 valid on no-amount QR (appended {p0[-4:]})')

        print('\n=== PromptPay target resolution (right sub-tag + no double-66 mangling) ===')
        # The merchant id inside tag 29 is where the money actually goes. It must resolve to
        # the correct EMVCo sub-tag and value: a mobile in ANY form -> ("01", 0066+9 digits);
        # a 13-digit national/tax ID -> ("02", as-is); a 15-digit e-wallet -> ("03", as-is).
        # The old code always used "01" and blindly prefixed "0066", so an intl-form number
        # ("66..."/"+66...") became "006666..." — an invalid target the merchant never receives.
        def merchant_subfield(payload):
            tag29 = parse_tlv(payload).get('29', '')
            sub = parse_tlv(tag29)  # sub-tags share the TLV shape
            for t in ('01', '02', '03'):
                if t in sub:
                    return t, sub[t]
            return None, None
        cases = [
            ('0812345678',      '01', '0066812345678', 'local mobile 0-prefixed'),
            ('66812345678',     '01', '0066812345678', 'intl mobile 66-prefixed (no double 66)'),
            ('+66 81-234-5678', '01', '0066812345678', 'intl mobile with punctuation'),
            ('0066812345678',   '01', '0066812345678', 'already-canonical mobile unchanged'),
            ('1234567890123',   '02', '1234567890123', '13-digit national/tax ID -> sub-tag 02'),
            ('123456789012345', '03', '123456789012345', '15-digit e-wallet -> sub-tag 03'),
        ]
        for phone, want_tag, want_val, label in cases:
            st, q = req('POST', '/api/payments/qr', {'phone': phone, 'amount': 10})
            got_tag, got_val = merchant_subfield(q['payload']) if st == 200 else (None, None)
            check(st == 200 and (got_tag, got_val) == (want_tag, want_val),
                  f'{label}: {phone!r} -> ({got_tag},{got_val}) want ({want_tag},{want_val})')
            check(st == 200 and q['payload'][-4:] == crc16_ccitt(q['payload'][:-4]),
                  f'{label}: CRC-16 valid')

        print(f'\n=== RESULT: {passed} passed, {failed} failed ===')
        return 1 if failed else 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        for p in (dbpath, dbpath + '-wal', dbpath + '-shm'):
            try:
                os.remove(p)
            except OSError:
                pass


if __name__ == '__main__':
    sys.exit(main())
