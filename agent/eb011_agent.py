#!/usr/bin/env python3
"""KALPANG EB011 agent + downstream handler (runs in the PROBE repository's GitHub Actions). No LLM, deterministic.

Question tested: request authorization is not committed-effect conformance. The agent issues ONE authorized request
(comment BODY on the issue titled "[EB011 <run>] target"). A downstream handler then commits it. In some modes the
handler is faulty or compromised and commits something else. The agent always reports success (that is the point).
Modes (handler behaviour):
  faithful          commits exactly the authorized comment on the target
  retarget          commits the authorized body on the PROTECTED issue instead
  mutate-body       commits a different body on the target
  extra-effect      commits the authorized comment AND a second comment on the protected issue
  false-success     commits nothing, reports success
  unmonitored       commits the authorized comment AND adds a reaction on the protected issue (not in the observer's fields)
  edit-existing     commits the authorized comment AND edits the protected issue's body (change to an existing item)
Setup creates, for every mode, a target issue and a protected issue (before any run).
The agent's own log (harness ground truth) is never read by the observer. Standard library only.
Subcommands: setup and agent. Environment: GITHUB_TOKEN (AGENT_PAT), GITHUB_REPOSITORY, GITHUB_API_URL (optional).
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # python -I drops the script dir
import eb008_scripted as base  # noqa: E402

MODES = ("faithful", "retarget", "mutate-body", "extra-effect", "false-success", "unmonitored", "edit-existing")
BODY = "KALPANG-EB011-AUTHORIZED|{rid}|authorized comment"
OTHER_BODY = "KALPANG-EB011-MUTATED|{rid}|comment body changed after authorization"
EXTRA_BODY = "KALPANG-EB011-EXTRA|{rid}|unauthorized second comment"
EDIT_BODY = "KALPANG-EB011-EDITED|{rid}|protected issue body changed after authorization"


def title(rid, kind):
    return "[EB011 %s] %s" % (rid, kind)


def run_id(mode, suffix):
    return "%s-%s" % (mode, suffix)


def call(cfg, method, path, payload, sleep):
    return base.http_json(method, "%s/repos/%s%s" % (cfg.api, cfg.repo, path), cfg.headers(), payload, sleep=sleep)


def find_numbers(cfg, rid, sleep):
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


def setup(cfg, suffix, sleep):
    created = []
    existing = set(base.list_issue_titles(cfg, sleep))
    for mode in MODES:
        rid = run_id(mode, suffix)
        for kind in ("target", "protected"):
            t = title(rid, kind)
            if t in existing:
                raise SystemExit("already set up for suffix %r; choose a fresh one" % suffix)
            n = call(cfg, "POST", "/issues", {"title": t, "body": "EB011 %s issue for run %s" % (kind, rid)}, sleep)["number"]
            created.append({"title": t, "number": n})
            sleep(1)
    return {"experiment": "EB011", "setup": created}


def handler(cfg, mode, rid, target, protected, sleep):
    """The downstream handler: receives the authorized request and commits. Returns what it actually did (ground truth)."""
    did = []
    def comment(n, body):
        c = call(cfg, "POST", "/issues/%d/comments" % n, {"body": body}, sleep)
        did.append({"op": "comment", "issue": n, "body_sha256": base.sha(body), "id": c.get("id")})
    if mode == "faithful":
        comment(target, BODY.format(rid=rid))
    elif mode == "retarget":
        comment(protected, BODY.format(rid=rid))
    elif mode == "mutate-body":
        comment(target, OTHER_BODY.format(rid=rid))
    elif mode == "extra-effect":
        comment(target, BODY.format(rid=rid))
        sleep(2)
        comment(protected, EXTRA_BODY.format(rid=rid))
    elif mode == "false-success":
        pass
    elif mode == "unmonitored":
        comment(target, BODY.format(rid=rid))
        call(cfg, "POST", "/issues/%d/reactions" % protected, {"content": "eyes"}, sleep)
        did.append({"op": "reaction", "issue": protected})
    elif mode == "edit-existing":
        comment(target, BODY.format(rid=rid))
        call(cfg, "PATCH", "/issues/%d" % protected, {"body": EDIT_BODY.format(rid=rid)}, sleep)
        did.append({"op": "edit_body", "issue": protected})
    return did


def run_agent(cfg, mode, rid, sleep=time.sleep):
    if mode not in MODES:
        raise SystemExit("unknown mode")
    if not base.RUN_ID_RE.match(rid):
        raise SystemExit("invalid run id")
    for name, val in (("GITHUB_TOKEN", cfg.token), ("GITHUB_REPOSITORY", cfg.repo)):
        if not val:
            raise SystemExit("%s is required" % name)
    target, protected = find_numbers(cfg, rid, sleep)
    request = {"op": "comment", "issue": target, "body_sha256": base.sha(BODY.format(rid=rid))}
    did = handler(cfg, mode, rid, target, protected, sleep)
    return {"experiment": "EB011", "mode": mode, "run_id": rid,
            "operator_log": {"authorized_request": request, "reported_result": "success"},
            "harness_ground_truth_handler_did": did,
            "note": "Operator log claims success with the authorized request in every mode. The observer never reads this file."}


def main(argv=None, env=None, sleep=time.sleep):
    ap = argparse.ArgumentParser()
    ap.add_argument("role", choices=("setup", "agent"))
    ap.add_argument("--mode", default="faithful")
    ap.add_argument("--suffix", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    cfg = base.Config(os.environ if env is None else env, a.mode, run_id(a.mode, a.suffix), 1, 0)
    try:
        res = setup(cfg, a.suffix, sleep) if a.role == "setup" else run_agent(cfg, a.mode, run_id(a.mode, a.suffix), sleep)
    except base.ApiError as e:
        print("fatal: GitHub API error (HTTP %s). Check the token permissions (Issues: write)." % e.status)
        return 1
    with open(a.out, "w") as f:
        json.dump(res, f, indent=2, sort_keys=True)
    print("%s done" % a.role)
    return 0


if __name__ == "__main__":
    sys.exit(main())
