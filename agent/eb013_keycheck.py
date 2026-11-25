#!/usr/bin/env python3
"""EB013 key check (diagnostic only). Derives the public key from ISSUER_PRIVATE_KEY and compares it with ISSUER_PUBLIC_KEY.
Prints only lengths, a match flag and the DERIVED PUBLIC key (public by design). Never prints the private key."""
import base64, os, sys
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
priv_s = os.environ.get("ISSUER_PRIVATE_KEY", "")
pub_s = os.environ.get("ISSUER_PUBLIC_KEY", "")
print("private secret set=%s length=%d" % (bool(priv_s), len(priv_s)))
print("public variable set=%s length=%d" % (bool(pub_s), len(pub_s)))
try:
    raw = base64.b64decode(priv_s)
    print("private decodes to %d bytes (needs 32)" % len(raw))
    derived = base64.b64encode(Ed25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)).decode()
except Exception as e:
    print("private key unusable: %s" % type(e).__name__); sys.exit(1)
print("derived public key: %s" % derived)
print("MATCH=%s" % (derived == pub_s.strip()))
