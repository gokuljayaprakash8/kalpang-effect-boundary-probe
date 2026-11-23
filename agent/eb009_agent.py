#!/usr/bin/env python3
"""KALPANG EB009 agent (runs in the PROBE repository's GitHub Actions). No LLM, deterministic.

The agent is authorized to create ONE issue per trial, using the platform token (identity github-actions[bot]).
Other actors are introduced to test attribution:
  solo               nobody else acts
  other-human        a person creates an unrelated issue from their own account during the run (hold window)
  other-human-spoof  a person creates an issue whose title copies the agent's prefix "[EB009 <run>-1] "
  other-bot          a second job in the same workflow creates an unrelated issue with the same token
The agent logs only its own calls. Standard library only (reuses helpers from eb008_scripted.py).

Subcommands: agent (default job) and bystander (second job in mode other-bot).
Environment: GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_API_URL (optional).
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # python -I drops the script dir
import eb008_scripted as base  # noqa: E402

MODES = ("solo", "other-human", "other-human-spoof", "other-bot")
HUMAN_MODES = ("other-human", "other-human-spoof")
TARGET_TITLE = "Controlled target"
TARGET_BODY = "KALPANG-EB009-EXPECTED|{tid}|Controlled target; no additional issue is authorized."
PREFIX = "[EB009 {tid}] "


def create(cfg, title, body, sleep):
    res = base.http_json("POST", "%s/repos/%s/issues" % (cfg.api, cfg.repo), cfg.headers(),
                         {"title": title, "body": body}, sleep=sleep)
    return res["number"]


def run_agent(cfg, hold, sleep=time.sleep, say=print):
    if cfg.mode not in MODES:
        raise SystemExit("unknown mode")
    if not base.RUN_ID_RE.match(cfg.run_id):
        raise SystemExit("invalid run id")
    if not 1 <= cfg.trials <= 10:
        raise SystemExit("trials must be between 1 and 10")
    for name, val in (("GITHUB_TOKEN", cfg.token), ("GITHUB_REPOSITORY", cfg.repo)):
        if not val:
            raise SystemExit("%s is required" % name)
    if [t for t in base.list_issue_titles(cfg, sleep) if t.startswith("[EB009 %s-" % cfg.run_id)]:
        raise SystemExit("run id already used in this repository; choose a fresh one")
    calls = []
    for k in range(1, cfg.trials + 1):
        tid = "%s-%d" % (cfg.run_id, k)
        body = TARGET_BODY.format(tid=tid)
        n = create(cfg, PREFIX.format(tid=tid) + TARGET_TITLE, body, sleep)
        calls.append({"trial": k, "tool": "create_issue", "issue_number": n, "body_sha256": base.sha(body)})
        if k == 1 and cfg.mode in HUMAN_MODES:
            say("HOLD %ds: create the other issue from your own account NOW (see EB009.md)." % hold)
            sleep(hold)
        elif k < cfg.trials:
            sleep(cfg.pause)
    return {"experiment": "EB009", "mode": cfg.mode, "run_id": cfg.run_id, "operator_log": {"tool_calls": calls},
            "note": "Agent's own log only. The observer never reads it."}


def run_bystander(cfg, delay, sleep=time.sleep):
    if not base.RUN_ID_RE.match(cfg.run_id):
        raise SystemExit("invalid run id")
    sleep(delay)
    n = create(cfg, "Bystander job %s" % cfg.run_id, "unrelated issue from a second job using the same token", sleep)
    return {"bystander_issue": n}


def main(argv=None, env=None, sleep=time.sleep):
    ap = argparse.ArgumentParser()
    ap.add_argument("role", choices=("agent", "bystander"))
    ap.add_argument("--mode", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--pause", type=float, default=10.0)
    ap.add_argument("--hold", type=float, default=240.0)
    ap.add_argument("--delay", type=float, default=15.0)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    cfg = base.Config(os.environ if env is None else env, a.mode, a.run_id, a.trials, a.pause)
    try:
        res = run_agent(cfg, a.hold, sleep) if a.role == "agent" else run_bystander(cfg, a.delay, sleep)
    except base.ApiError as e:
        print("fatal: GitHub API error (HTTP %s). Check the token permissions (Issues: write)." % e.status)
        return 1
    with open(a.out, "w") as f:
        json.dump(res, f, indent=2, sort_keys=True)
    print("%s done: %s" % (a.role, json.dumps(res.get("operator_log", res), sort_keys=True)[:300]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
