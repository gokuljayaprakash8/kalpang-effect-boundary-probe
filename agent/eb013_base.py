#!/usr/bin/env python3
"""EB013 isolated BASELINE for change C1: the EB012 shared-secret (HMAC) design, attacker holds the gate's verification material.
Under HMAC the key that verifies is the key that signs, so an attacker who obtains the gate's key can sign anything.
Mode:
  base-forge-with-gate-key  handler holds GATE_KEY (models a leak or compromise of the gate's verification material),
                            forges an authorization for the protected issue, signs it with GATE_KEY.
Everything else equals eb013_c1.py (same gate checks, same handler isolation, same observer). Standard library plus eb013_c1.
Roles: setup, authorize, handler, gate. Environment: GITHUB_TOKEN, GITHUB_REPOSITORY, GATE_KEY."""
import argparse, hashlib, hmac, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # python -I drops the script dir
import eb008_scripted as base  # noqa: E402
import eb013_c1 as c1  # noqa: E402

MODES = ("base-forge-with-gate-key",)
BODY = c1.BODY


def sign(key, auth):
    return hmac.new(key.encode(), c1.canon(auth), hashlib.sha256).hexdigest()


def setup(cfg, suffix, sleep=time.sleep):
    existing = set(base.list_issue_titles(cfg, sleep))
    created = []
    for mode in MODES:
        rid = c1.run_id(mode, suffix)
        for kind in ("target", "protected"):
            t = c1.title(rid, kind)
            if t in existing:
                raise SystemExit("already set up for suffix %r; choose a fresh one" % suffix)
            n = c1.call(cfg, "POST", "/issues", {"title": t, "body": "EB013 %s issue for run %s" % (kind, rid)}, sleep)["number"]
            created.append({"title": t, "number": n})
            sleep(1)
    return {"experiment": "EB013-BASE", "setup": created}


def authorize(cfg, mode, rid, key, now=time.time):
    target, _ = c1.find_numbers(cfg, rid)
    spec = {"run_id": rid, "op": "comment", "issue": target, "body_sha256": base.sha(BODY.format(rid=rid)),
            "nonce": hashlib.sha256(("%s|%s" % (rid, now())).encode()).hexdigest()[:16], "expires_at": int(now()) + c1.TTL}
    return {"authorization": spec, "signature": sign(key, spec)}


def handler(cfg, mode, rid, auth_doc, key, sleep=time.sleep):
    target, protected = c1.find_numbers(cfg, rid, sleep)
    ok = {"op": "comment", "issue": target, "body": BODY.format(rid=rid), "nonce": auth_doc["authorization"]["nonce"]}
    forged = json.loads(json.dumps(auth_doc["authorization"]))
    forged["issue"] = protected
    # body hash and nonce unchanged; only the target is forged. The handler signs with the gate's key it holds.
    return {"ops": [dict(ok, issue=protected)], "authorization_override": {"authorization": forged, "signature": sign(key, forged)},
            "attacker_held_gate_key": True}


def gate(cfg, mode, rid, auth_doc, req, key, now=time.time, sleep=time.sleep):
    log = {"mode": mode, "run_id": rid, "decisions": []}
    doc = req.get("authorization_override") or auth_doc
    spec = doc["authorization"]
    sig_ok = hmac.compare_digest(sign(key, spec), doc.get("signature", ""))
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
            c = c1.call(cfg, "POST", "/issues/%d/comments" % op["issue"], {"body": op["body"]}, sleep)
            used.add(spec["nonce"])
            d.update(decision="COMMITTED", reason=None, issue=op["issue"], comment_id=c.get("id"))
        log["decisions"].append(d)
    return log


def main(argv=None, env=None, sleep=time.sleep):
    ap = argparse.ArgumentParser()
    ap.add_argument("role", choices=("setup", "authorize", "handler", "gate"))
    ap.add_argument("--mode", default="base-forge-with-gate-key")
    ap.add_argument("--suffix", required=True)
    ap.add_argument("--auth"); ap.add_argument("--request"); ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    e = os.environ if env is None else env
    rid = c1.run_id(a.mode, a.suffix)
    cfg = base.Config(e, a.mode, rid, 1, 0)
    if a.role != "setup" and a.mode not in MODES:
        raise SystemExit("unknown mode")
    if not base.RUN_ID_RE.match(rid) or not cfg.token or not cfg.repo:
        raise SystemExit("invalid run id, missing token or repository")
    key = e.get("GATE_KEY") or ""
    try:
        if a.role == "setup":
            res = setup(cfg, a.suffix, sleep)
        else:
            if not key:
                raise SystemExit("GATE_KEY is required")
            if a.role == "authorize":
                res = authorize(cfg, a.mode, rid, key)
            elif a.role == "handler":
                res = handler(cfg, a.mode, rid, json.load(open(a.auth)), key, sleep)
            else:
                res = gate(cfg, a.mode, rid, json.load(open(a.auth)), json.load(open(a.request)), key, sleep=sleep)
                for d in res["decisions"]:
                    print("GATE op=%d decision=%s reason=%s" % (d["op_index"], d["decision"], d["reason"] or "-"))
    except base.ApiError as ex:
        print("fatal: GitHub API error (HTTP %s). Check token permissions." % ex.status)
        return 1
    with open(a.out, "w") as f:
        json.dump(res, f, indent=2, sort_keys=True)
    print("%s done" % a.role)
    return 0


if __name__ == "__main__":
    sys.exit(main())
  
