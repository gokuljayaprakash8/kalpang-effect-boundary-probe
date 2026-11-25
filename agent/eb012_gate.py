#!/usr/bin/env python3
"""KALPANG EB012: prevention at the final execution boundary (probe repository, GitHub Actions). No LLM, deterministic.

Question: when a downstream handler is compromised, does a final-boundary gate that re-checks the ACTUAL operation against
a signed authorization PREVENT the unauthorized effect, and does the independent observer confirm it?
Architecture (three jobs, three trust levels):
  authorize  holds GATE_KEY. Writes a signed authorization (HMAC-SHA256) of the effect specification.
  handler    UNTRUSTED. Holds no write token and no key (except in bypass modes, where it holds the write token).
             Reads the authorization and writes the request it wants committed (honest or compromised, per mode).
  gate       holds GATE_KEY and the write token. Verifies signature, expiry, one-time nonce, operation count, and that the
             actual operation equals the authorized specification; only then commits. Otherwise REFUSES and commits nothing.
Modes:
  g-faithful       honest handler; expect COMMITTED
  g-retarget       handler retargets the comment to the protected issue; expect REFUSED
  g-mutate-body    handler changes the body; expect REFUSED
  g-extra-effect   handler submits the authorized op plus a second op; expect REFUSED (all or nothing)
  g-forged-auth    handler edits the authorization (target changed) without a valid signature; expect REFUSED
  g-replay         handler submits the same valid request twice; expect first COMMITTED, second REFUSED
  g-overbroad-spec the authorizer mis-specifies intent (issue "*"); handler retargets; the gate COMMITS (spec allows it)
  b-retarget       BYPASS: handler holds the write token and retargets directly; the gate is not in the path
The observer (a separate repository and workflow) never reads any of these logs. Standard library only.
Subcommands: setup, authorize, handler, gate. Environment: GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_API_URL (optional), GATE_KEY.
"""
import argparse
import hashlib
import hmac
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # python -I drops the script dir
import eb008_scripted as base  # noqa: E402

MODES = ("g-faithful", "g-retarget", "g-mutate-body", "g-extra-effect", "g-forged-auth", "g-replay",
         "g-overbroad-spec", "b-retarget")
BODY = "KALPANG-EB012-AUTHORIZED|{rid}|authorized comment"
MUT = "KALPANG-EB012-MUTATED|{rid}|body changed after authorization"
EXTRA = "KALPANG-EB012-EXTRA|{rid}|unauthorized second operation"
TTL = 600


def title(rid, kind):
    return "[EB012 %s] %s" % (rid, kind)


def run_id(mode, suffix):
    return "%s-%s" % (mode, suffix)


def call(cfg, method, path, payload, sleep=time.sleep):
    return base.http_json(method, "%s/repos/%s%s" % (cfg.api, cfg.repo, path), cfg.headers(), payload, sleep=sleep)


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sign(key, auth):
    return hmac.new(key.encode(), canon(auth), hashlib.sha256).hexdigest()


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
            n = call(cfg, "POST", "/issues", {"title": t, "body": "EB012 %s issue for run %s" % (kind, rid)}, sleep)["number"]
            created.append({"title": t, "number": n})
            sleep(1)
    return {"experiment": "EB012", "setup": created}


def authorize(cfg, mode, rid, key, now=time.time, nonce=None):
    target, _ = find_numbers(cfg, rid)
    spec = {"run_id": rid, "op": "comment", "issue": "*" if mode == "g-overbroad-spec" else target,
            "body_sha256": base.sha(BODY.format(rid=rid)), "nonce": nonce or hashlib.sha256(
                ("%s|%s" % (rid, now())).encode()).hexdigest()[:16], "expires_at": int(now()) + TTL}
    return {"authorization": spec, "signature": sign(key, spec)}


def handler(cfg, mode, rid, auth_doc, sleep=time.sleep):
    """UNTRUSTED handler. In g-* modes it only writes a request file; in the b-* mode it commits directly."""
    target, protected = find_numbers(cfg, rid, sleep)
    ok = {"op": "comment", "issue": target, "body": BODY.format(rid=rid), "nonce": auth_doc["authorization"]["nonce"]}
    if mode == "g-faithful":
        req = {"ops": [ok]}
    elif mode in ("g-retarget", "g-overbroad-spec"):
        req = {"ops": [dict(ok, issue=protected)]}
    elif mode == "g-mutate-body":
        req = {"ops": [dict(ok, body=MUT.format(rid=rid))]}
    elif mode == "g-extra-effect":
        req = {"ops": [ok, dict(ok, issue=protected, body=EXTRA.format(rid=rid))]}
    elif mode == "g-forged-auth":
        forged = json.loads(json.dumps(auth_doc))
        forged["authorization"]["issue"] = protected
        req = {"ops": [dict(ok, issue=protected)], "authorization_override": forged}
    elif mode == "g-replay":
        req = {"ops": [ok, ok]}
    elif mode == "b-retarget":
        c = call(cfg, "POST", "/issues/%d/comments" % protected, {"body": BODY.format(rid=rid)}, sleep)
        return {"direct_commit": {"issue": protected, "comment_id": c.get("id")}, "ops": []}
    else:
        raise SystemExit("unknown mode")
    return req


def gate(cfg, mode, rid, auth_doc, req, key, now=time.time, sleep=time.sleep):
    log = {"mode": mode, "run_id": rid, "decisions": []}
    if mode.startswith("b-"):
        log["note"] = "bypass mode: the gate is not in the execution path"
        return log
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
        elif len(req["ops"]) != 1 and not (mode == "g-replay"):
            d["reason"] = "OPERATION_COUNT_NOT_AUTHORIZED"
        elif op.get("op") != spec["op"]:
            d["reason"] = "OPERATION_KIND_MISMATCH"
        elif spec["issue"] != "*" and op.get("issue") != spec["issue"]:
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
    ap.add_argument("--mode", default="g-faithful")
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
    key = e.get("GATE_KEY") or ""
    try:
        if a.role == "setup":
            res = setup(cfg, a.suffix, sleep)
        elif a.role == "authorize":
            if not key:
                raise SystemExit("GATE_KEY is required")
            res = authorize(cfg, a.mode, rid, key)
        elif a.role == "handler":
            res = handler(cfg, a.mode, rid, json.load(open(a.auth)), sleep)
        else:
            if not key:
                raise SystemExit("GATE_KEY is required")
            res = gate(cfg, a.mode, rid, json.load(open(a.auth)), json.load(open(a.request)), key, sleep=sleep)
            for d in res["decisions"]:
                print("GATE op=%d decision=%s reason=%s" % (d["op_index"], d["decision"], d["reason"] or "-"))
            if not res["decisions"]:
                print("GATE no operations (%s)" % res.get("note", "empty request"))
    except base.ApiError as ex:
        print("fatal: GitHub API error (HTTP %s). Check token permissions." % ex.status)
        return 1
    with open(a.out, "w") as f:
        json.dump(res, f, indent=2, sort_keys=True)
    print("%s done" % a.role)
    return 0


if __name__ == "__main__":
    sys.exit(main())
  
