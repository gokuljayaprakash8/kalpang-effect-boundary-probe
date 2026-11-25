#!/usr/bin/env python3
"""KALPANG EB013 change C1 (isolated): asymmetric authorization signatures. Probe repository, GitHub Actions. No LLM.

Only ONE thing differs from EB012: the authorization is signed with an Ed25519 PRIVATE key held only by the authorize job,
and the gate verifies with the matching PUBLIC key. The gate holds no signing capability. Everything else is the EB012
baseline (same gate checks, same untrusted handler, same observer).
Question: does key separation make a forged authorization fail, even for an attacker who knows the public key?
Modes:
  s-faithful               honest handler; expect COMMITTED
  s-forge-with-public-key  attacker knows the public key, has no private key; makes its own keypair, forges an authorization
                           for the protected issue and signs it with its own key; expect REFUSED BAD_SIGNATURE
Limit (stated before running): this tests key separation only. It does not show that a compromised gate cannot bypass its own
validation or misuse its write credential. The private key is a GitHub secret, so secret handling remains a trust assumption.
Subcommands: setup, authorize, handler, gate. Environment: GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_API_URL (optional),
ISSUER_PRIVATE_KEY (authorize only), ISSUER_PUBLIC_KEY (gate and handler). Requires the `cryptography` package.
"""
import argparse
import base64
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # python -I drops the script dir
import eb008_scripted as base  # noqa: E402
from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey  # noqa: E402

MODES = ("s-faithful", "s-forge-with-public-key")
BODY = "KALPANG-EB013-AUTHORIZED|{rid}|authorized comment"
TTL = 600
RAW = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def title(rid, kind):
    return "[EB013 %s] %s" % (rid, kind)


def run_id(mode, suffix):
    return "%s-%s" % (mode, suffix)


def call(cfg, method, path, payload, sleep=time.sleep):
    return base.http_json(method, "%s/repos/%s%s" % (cfg.api, cfg.repo, path), cfg.headers(), payload, sleep=sleep)


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def priv_from_b64(s):
    return Ed25519PrivateKey.from_private_bytes(base64.b64decode(s))


def pub_b64(priv):
    return base64.b64encode(priv.public_key().public_bytes(**RAW)).decode()


def sign(priv, auth):
    return base64.b64encode(priv.sign(canon(auth))).decode()


def verify(pub_b64_str, auth, sig_b64):
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64_str)).verify(base64.b64decode(sig_b64), canon(auth))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def find_numbers(cfg, rid, sleep=time.sleep):
    found, page = {}, 1
    while page <= 20:
        data = base.http_json("GET", "%s/repos/%s/issues?state=all&per_page=100&page=%d" % (cfg.api, cfg.repo, page),
                              cfg.headers(), sleep=sleep)
        for i in data:
            if "pull_request" in i:
                continue
            for kind in ("target", "protected"):
                if i["title"] == title(rid, kind):
                    found.setdefault(kind, []).append(i["number"])
        if len(data) < 100:
            break
        page += 1
    for kind in ("target", "protected"):
        if len(found.get(kind, [])) != 1:
            raise SystemExit("setup issue %r not found exactly once; run setup first" % title(rid, kind))
    return found["target"][0], found["protected"][0]


def setup(cfg, suffix, sleep=time.sleep):
    existing = set(base.list_issue_titles(cfg, sleep))
    created = []
    for mode in MODES:
        rid = run_id(mode, suffix)
        for kind in ("target", "protected"):
            t = title(rid, kind)
            if t in existing:
                raise SystemExit("already set up for suffix %r; choose a fresh one" % suffix)
            n = call(cfg, "POST", "/issues", {"title": t, "body": "EB013 %s issue for run %s" % (kind, rid)}, sleep)["number"]
            created.append({"title": t, "number": n})
            sleep(1)
    return {"experiment": "EB013-C1", "setup": created}


def authorize(cfg, mode, rid, priv, now=time.time, nonce=None):
    target, _ = find_numbers(cfg, rid)
    spec = {"run_id": rid, "op": "comment", "issue": target, "body_sha256": base.sha(BODY.format(rid=rid)),
            "nonce": nonce or hashlib.sha256(("%s|%s" % (rid, now())).encode()).hexdigest()[:16],
            "expires_at": int(now()) + TTL}
    return {"authorization": spec, "signature": sign(priv, spec)}


def handler(cfg, mode, rid, auth_doc, public_key, sleep=time.sleep):
    """UNTRUSTED handler. Knows the public key; never has the private key."""
    target, protected = find_numbers(cfg, rid, sleep)
    ok = {"op": "comment", "issue": target, "body": BODY.format(rid=rid), "nonce": auth_doc["authorization"]["nonce"]}
    if mode == "s-faithful":
        return {"ops": [ok]}
    if mode == "s-forge-with-public-key":
        attacker = Ed25519PrivateKey.generate()  # the attacker's own key; the issuer private key is not available here
        forged = json.loads(json.dumps(auth_doc["authorization"]))
        forged["issue"] = protected
        forged_doc = {"authorization": forged, "signature": sign(attacker, forged)}
        return {"ops": [dict(ok, issue=protected)], "authorization_override": forged_doc,
                "attacker_knew_public_key": bool(public_key), "attacker_had_private_key": False}
    raise SystemExit("unknown mode")


def gate(cfg, mode, rid, auth_doc, req, public_key, now=time.time, sleep=time.sleep):
    log = {"mode": mode, "run_id": rid, "decisions": []}
    doc = req.get("authorization_override") or auth_doc
    spec = doc["authorization"]
    sig_ok = verify(public_key, spec, doc.get("signature", ""))
    used = set()
    for k, op in enumerate(req.get("ops", [])):
        d = {"op_index": k, "decision": "REFUSED", "reason": None}
        if not sig_ok:
            d["reason"] = "BAD_SIGNATURE"
        elif now() > spec["expires_at"]:
            d["reason"] = "EXPIRED"
        elif op.get("nonce") != spec["nonce"] or spec["nonce"] in used:
            d["reason"] = "NONCE_INVALID_OR_REPLAYED"
        elif len(req["ops"]) != 1:
            d["reason"] = "OPERATION_COUNT_NOT_AUTHORIZED"
        elif op.get("op") != spec["op"]:
            d["reason"] = "OPERATION_KIND_MISMATCH"
        elif op.get("issue") != spec["issue"]:
            d["reason"] = "TARGET_NOT_AUTHORIZED"
        elif base.sha(op.get("body", "")) != spec["body_sha256"]:
            d["reason"] = "BODY_HASH_MISMATCH"
        else:
            c = call(cfg, "POST", "/issues/%d/comments" % op["issue"], {"body": op["body"]}, sleep)
            used.add(spec["nonce"])
            d.update(decision="COMMITTED", reason=None, issue=op["issue"], comment_id=c.get("id"))
        log["decisions"].append(d)
    return log


def main(argv=None, env=None, sleep=time.sleep):
    ap = argparse.ArgumentParser()
    ap.add_argument("role", choices=("setup", "authorize", "handler", "gate"))
    ap.add_argument("--mode", default="s-faithful")
    ap.add_argument("--suffix", required=True)
    ap.add_argument("--auth")
    ap.add_argument("--request")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    e = os.environ if env is None else env
    rid = run_id(a.mode, a.suffix)
    cfg = base.Config(e, a.mode, rid, 1, 0)
    if a.role != "setup" and a.mode not in MODES:
        raise SystemExit("unknown mode")
    if not base.RUN_ID_RE.match(rid) or not cfg.token or not cfg.repo:
        raise SystemExit("invalid run id, missing token or repository")
    try:
        if a.role == "setup":
            res = setup(cfg, a.suffix, sleep)
        elif a.role == "authorize":
            if not e.get("ISSUER_PRIVATE_KEY"):
                raise SystemExit("ISSUER_PRIVATE_KEY is required")
            res = authorize(cfg, a.mode, rid, priv_from_b64(e["ISSUER_PRIVATE_KEY"]))
        elif a.role == "handler":
            res = handler(cfg, a.mode, rid, json.load(open(a.auth)), e.get("ISSUER_PUBLIC_KEY", ""), sleep)
        else:
            if not e.get("ISSUER_PUBLIC_KEY"):
                raise SystemExit("ISSUER_PUBLIC_KEY is required")
            res = gate(cfg, a.mode, rid, json.load(open(a.auth)), json.load(open(a.request)), e["ISSUER_PUBLIC_KEY"], sleep=sleep)
            for d in res["decisions"]:
                print("GATE op=%d decision=%s reason=%s" % (d["op_index"], d["decision"], d["reason"] or "-"))
            if not res["decisions"]:
                print("GATE no operations")
    except base.ApiError as ex:
        print("fatal: GitHub API error (HTTP %s). Check token permissions." % ex.status)
        return 1
    with open(a.out, "w") as f:
        json.dump(res, f, indent=2, sort_keys=True)
    print("%s done" % a.role)
    return 0


if __name__ == "__main__":
    sys.exit(main())
