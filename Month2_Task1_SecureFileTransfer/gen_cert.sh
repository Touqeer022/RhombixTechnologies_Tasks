#!/usr/bin/env bash
# Generates a self-signed TLS certificate for the server's transport layer.
# This secures the socket connection itself (defense in depth); the actual
# file confidentiality/integrity comes from the E2E AES-GCM + RSA-OAEP
# layer in crypto_utils.py, which the server can never decrypt regardless
# of the transport.
#
# For real deployments, replace this with a certificate from a trusted CA
# (e.g. Let's Encrypt) instead of a self-signed one.

set -e
cd "$(dirname "$0")/server_data"

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key -out server.crt -days 365 \
  -subj "/CN=localhost" 2>/dev/null

echo "Generated server_data/server.crt and server_data/server.key"
