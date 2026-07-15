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

        print('\n=== missing payment confirm -> 404 (not false success) ===')
        st, _ = req('POST', '/api/payments/999999/confirm', {})
        check(st == 404, f'confirm nonexistent payment -> 404 (got {st})')

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
