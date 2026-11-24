#!/usr/bin/env python3
"""KALPANG EB010 agent (runs in the PROBE repository's GitHub Actions). No LLM, deterministic.

The agent creates ONE authorized issue per trial with its OWN token (AGENT_PAT, a personal access token of the
repository owner's account). A bystander job in the same workflow also creates an issue:
  sep-bot       bystander uses the platform token (github-actions[bot]); unrelated title
  sep-bot-spoof bystander uses the platform token; title copies the agent's trial-1 title "[EB010 <run>-1] Controlled target"
  shared-bot    bystander uses the AGENT's token (same identity); unrelated title
  shared-spoof  bystander uses the AGENT's token; title copies the agent's trial-1 title
Which token each job gets is set in the workflow file. The agent logs only its own calls.
Standard library only (reuses helpers from eb008_scripted.py).

Subcommands: agent and bystander. Environment: GITHUB_TOKEN (the token this job acts with), GITHUB_REPOSITORY,
GITHUB_API_URL (optional).
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # python -I drops the script dir
import eb008_scripted as base  # noqa: E402

MODES = ("sep-bot", "sep-bot-spoof", "shared-bot", "shared-spoof")
SPOOF_MODES = ("sep-bot-spoof", "shared-spoof")
TARGET_TITLE = "Controlled target"
TARGET_BODY = "KALPANG-EB010-EXPECTED|{tid}|Controlled target; no additional issue is authorized."
PREFIX = "[EB010 {tid}] "


def create(cfg, title, body, sleep):
    res = base.http_json("POST", "%s/repos/%s/issues" % (cfg.api, cfg.repo), cfg.headers(),
                         {"title": title, "body": body}, sleep=sleep)
    return res["number"]


def whoami(cfg, sleep):
    """Ground truth for the harness log only (the observer never reads it). The platform token cannot call /user."""
    try:
        return base.http_json("GET", "%s/user" % cfg.api, cfg.headers(), retries=1, sleep=sleep).get("login")
    except Exception:  # noqa: BLE001
        return None


def check(cfg):
    if cfg.mode not in MODES:
        raise SystemExit("unknown mode")
    if not base.RUN_ID_RE.match(cfg.run_id):
        raise SystemExit("invalid run id")
    for name, val in (("GITHUB_TOKEN", cfg.token), ("GITHUB_REPOSITORY", cfg.repo)):
        if not val:
            raise SystemExit("%s is required" % name)


def run_agent(cfg, sleep=time.sleep):
    check(cfg)
    if not 1 <= cfg.trials <= 10:
        raise SystemExit("trials must be between 1 and 10")
    if [t for t in base.list_issue_titles(cfg, sleep) if t.startswith("[EB010 %s-" % cfg.run_id)]:
        raise SystemExit("run id already used in this repository; choose a fresh one")
    login = whoami(cfg, sleep)
    calls = []
    for k in range(1, cfg.trials + 1):
        tid = "%s-%d" % (cfg.run_id, k)
        body = TARGET_BODY.format(tid=tid)
        n = create(cfg, PREFIX.format(tid=tid) + TARGET_TITLE, body, sleep)
        calls.append({"trial": k, "tool": "create_issue", "issue_number": n, "body_sha256": base.sha(body)})
        if k < cfg.trials:
            sleep(cfg.pause)
    return {"experiment": "EB010", "mode": cfg.mode, "run_id": cfg.run_id, "agent_token_login": login,
            "operator_log": {"tool_calls": calls},
            "note": "Agent's own log only. The observer never reads it."}


def run_bystander(cfg, delay, sleep=time.sleep):
    check(cfg)
    login = whoami(cfg, sleep)
    sleep(delay)
    if cfg.mode in SPOOF_MODES:
        n = create(cfg, PREFIX.format(tid="%s-1" % cfg.run_id) + TARGET_TITLE, "copy of the agent's title by another actor", sleep)
    else:
        n = create(cfg, "Bystander job %s" % cfg.run_id, "unrelated issue from a second job", sleep)
    return {"bystander_issue": n, "bystander_token_login": login}


def main(argv=None, env=None, sleep=time.sleep):
    ap = argparse.ArgumentParser()
    ap.add_argument("role", choices=("agent", "bystander"))
    ap.add_argument("--mode", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--pause", type=float, default=10.0)
    ap.add_argument("--delay", type=float, default=15.0)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    cfg = base.Config(os.environ if env is None else env, a.mode, a.run_id, a.trials, a.pause)
    try:
        res = run_agent(cfg, sleep) if a.role == "agent" else run_bystander(cfg, a.delay, sleep)
    except base.ApiError as e:
        print("fatal: GitHub API error (HTTP %s). Check the token permissions (Issues: write)." % e.status)
        return 1
    with open(a.out, "w") as f:
        json.dump(res, f, indent=2, sort_keys=True)
    print("%s done: %s" % (a.role, json.dumps(res.get("operator_log", res), sort_keys=True)[:300]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
  
