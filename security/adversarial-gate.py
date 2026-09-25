#!/usr/bin/env python3
# adversarial-gate.py — deterministic bookkeeping for the adversarial-gate skill (build #2, 2026-07-15).
#
# The LLM loop (generator ↔ red-team evaluator) is orchestrated by Forge per
# skills/adversarial-gate/skill.md. THIS helper owns the NON-LLM parts so the loop's control flow is
# deterministic + auditable (not vibes): it logs each round's per-criterion scores and decides
# STOP vs CONTINUE (all-pass / plateau / cap). Zero Claude tokens.
#
# Usage:
#   adversarial-gate.py decide --task <t> --round <n> --scores '{"c1":1,"c2":0}' [--cap 3] [--threshold 1]
#       -> prints exactly one verdict: PASS | CONTINUE | STOP-PLATEAU | STOP-CAP  (and logs the round)
#   adversarial-gate.py reset --task <t>          # clear a task's round history (start a fresh gate)
#   adversarial-gate.py history --task <t>        # show the recorded rounds
import argparse, json, os
from datetime import datetime

LOG = os.path.expanduser("$HOME/agent-os/logs/adversarial-gate.log")
STATE_DIR = os.path.expanduser("~/.adversarial-gate")


def _hist_path(task):
    return os.path.join(STATE_DIR, f"{task}.json")


def decide(task, rnd, scores, cap, threshold):
    os.makedirs(STATE_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    hist = []
    hp = _hist_path(task)
    if os.path.exists(hp):
        try:
            hist = json.load(open(hp))
        except Exception:
            hist = []
    minscore = min(scores.values()) if scores else 0
    passed = len(scores) > 0 and all(v >= threshold for v in scores.values())
    hist.append({"round": rnd, "min": minscore, "scores": scores, "passed": passed})
    json.dump(hist, open(hp, "w"))
    with open(LOG, "a") as fh:
        fh.write(f"{datetime.now().isoformat(timespec='seconds')} task={task} round={rnd} "
                 f"min={minscore} pass={passed} scores={json.dumps(scores, ensure_ascii=False)}\n")
    if passed:
        return "PASS"
    if rnd >= cap:
        return "STOP-CAP"
    # plateau: the worst-criterion score did NOT improve vs the previous round (revision isn't helping)
    mins = [h["min"] for h in hist]
    if len(mins) >= 2 and mins[-1] <= mins[-2]:
        return "STOP-PLATEAU"
    return "CONTINUE"


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("decide")
    d.add_argument("--task", required=True)
    d.add_argument("--round", type=int, required=True)
    d.add_argument("--scores", required=True, help='JSON dict, e.g. {"factual":1,"tone":0}')
    d.add_argument("--cap", type=int, default=3)
    d.add_argument("--threshold", type=float, default=1)
    r = sub.add_parser("reset"); r.add_argument("--task", required=True)
    h = sub.add_parser("history"); h.add_argument("--task", required=True)
    a = ap.parse_args()
    if a.cmd == "decide":
        print(decide(a.task, a.round, json.loads(a.scores), a.cap, a.threshold))
    elif a.cmd == "reset":
        p = _hist_path(a.task)
        if os.path.exists(p):
            os.remove(p)
        print("reset")
    elif a.cmd == "history":
        p = _hist_path(a.task)
        print(open(p).read() if os.path.exists(p) else "[]")


if __name__ == "__main__":
    main()
