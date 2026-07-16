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

        print('\n=== missing payment confirm -> 404 (not false success) ===')
        st, _ = req('POST', '/api/payments/999999/confirm', {})
        check(st == 404, f'confirm nonexistent payment -> 404 (got {st})')

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
