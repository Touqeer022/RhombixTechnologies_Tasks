#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

rm -rf client_data server_data/files server_data/users.json server_data/files.json server_data/audit_log.jsonl
mkdir -p client_data

python3 server.py > server.log 2>&1 &
SERVER_PID=$!
sleep 1

echo "=== register alice (admin) ==="
python3 client.py register alice AlicePass123! --role admin

echo "=== register bob ==="
python3 client.py register bob BobPass456!

echo "=== create test file ==="
echo "Top secret internship report - Touqeer, Rhombix Technologies" > /tmp/report.txt

echo "=== alice uploads, shares with bob ==="
python3 client.py upload alice AlicePass123! /tmp/report.txt --to bob

FILE_ID=$(python3 client.py list bob BobPass456! | head -n1 | awk '{print $1}')
echo "=== bob lists visible files ==="
python3 client.py list bob BobPass456!

echo "=== bob downloads file_id=$FILE_ID ==="
python3 client.py download bob BobPass456! "$FILE_ID" /tmp/bob_downloads

echo "=== verify downloaded content ==="
cat /tmp/bob_downloads/report.txt

echo "=== attempt: unauthorized user (mallory) tries to download ==="
python3 client.py register mallory MalloryPass789!
python3 client.py download mallory MalloryPass789! "$FILE_ID" /tmp/mallory_downloads || true

echo "=== admin (alice) checks audit logs ==="
python3 client.py logs alice AlicePass123!

echo "=== raw ciphertext on server (should be unreadable) ==="
head -c 200 server_data/files/*.bin; echo

kill $SERVER_PID 2>/dev/null || true
