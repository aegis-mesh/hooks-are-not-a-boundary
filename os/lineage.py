#!/usr/bin/env python3
"""Attribute kernel-observed actions back to the agent, from Endpoint Security.

Reads a stream of eslogger events (JSONL: one JSON object per line, as written by
`eslogger exec fork open ...`) and answers the question a hook cannot: for every
action that touched the credential or sent data, which agent process is
responsible? It compares three attribution signals:

  ppid-walk    the live parent chain at the moment of the event. BREAKS when a
               process is re-parented (a backgrounded job whose parent exits is
               re-parented to launchd, pid 1), which is exactly scenario C5.
  fork-lineage the parent recorded at fork time, captured by the kernel before
               any re-parenting. Survives C5.
  responsible  the kernel's responsible_audit_token: macOS tracks a
               "responsible process" across re-parenting and exec. Survives C5.

The finding: the data-path hook sees none of these actions; the OS attributes
them all to the agent, and the two re-parent-proof signals recover the one that
the naive parent-walk loses.

eslogger's exact field names vary by macOS version, so extraction is defensive
and `--probe` prints the keys of the first events to calibrate on real output.
Pass --agent-pid (the pid of the agent process the capture launched) one or more
times; attribution is "does any signal's chain reach an agent pid".
"""
import argparse
import json
import sys


def _find(d, *paths):
    """Return the first present value among dotted paths, else None."""
    for path in paths:
        cur = d
        ok = True
        for key in path.split("."):
            if isinstance(cur, dict) and key in cur:
                cur = cur[key]
            else:
                ok = False
                break
        if ok:
            return cur
    return None


def _pid(token):
    if isinstance(token, dict):
        return token.get("pid")
    return token


def extract(ev):
    """Pull the fields we need from one eslogger event (ES JSON schema).

    The event name is the single key of ev["event"] ("exec"/"fork"/"open"); the
    numeric ev["event_type"] is ignored. The kernel records, on every process:
    ppid (live, re-parented to 1 when the parent exits), original_ppid and
    parent_audit_token (the parent at fork time, preserved across re-parenting),
    and responsible_audit_token (the responsible process).
    """
    body = ev.get("event")
    if not isinstance(body, dict) or not body:
        return None
    name = next(iter(body))
    inner = body[name] or {}
    proc = ev.get("process") or {}

    def common(p):
        return {
            "ppid": p.get("ppid"),
            "oppid": p.get("original_ppid"),
            "ptok": _pid(p.get("parent_audit_token")),
            "resp": _pid(p.get("responsible_audit_token")),
            "path": (p.get("executable") or {}).get("path"),
        }

    out = {"type": name}
    if name == "exec":
        tgt = inner.get("target") or {}
        src = tgt if tgt.get("audit_token") else proc
        out["pid"] = _pid(src.get("audit_token"))
        c = common(src)
        out.update(c)
        out["path"] = (tgt.get("executable") or {}).get("path") or c["path"]
        args = inner.get("args")
        out["args"] = " ".join(args) if isinstance(args, list) else (args or "")
    elif name == "fork":
        child = inner.get("child") or {}
        out["child"] = _pid(child.get("audit_token"))
        out["parent"] = _pid(proc.get("audit_token"))
    elif name in ("open", "create", "write"):
        out["type"] = "open"
        out["pid"] = _pid(proc.get("audit_token"))
        out.update(common(proc))
        f = inner.get("file") or inner.get("target") or {}
        out["path"] = f.get("path") if isinstance(f, dict) else (f or inner.get("path"))
        out["exec_path"] = (proc.get("executable") or {}).get("path")
    else:
        return None
    return out


def build(events):
    proc = {}        # pid -> {ppid(exec-time), resp, path, args}
    fork_parent = {} # child pid -> parent pid (recorded at fork time)
    actions = []     # dicts: {pid, what, live_ppid, resp} - the action's own view
    seen_pids = set()
    for ev in events:
        e = extract(ev)
        if not e:
            continue
        if e["type"] == "exec" and e.get("pid") is not None:
            proc[e["pid"]] = {"ppid": e.get("ppid"), "oppid": e.get("oppid"),
                               "ptok": e.get("ptok"), "resp": e.get("resp"),
                               "path": e.get("path") or "", "args": e.get("args") or ""}
        elif e["type"] == "fork" and e.get("child") is not None:
            fork_parent[e["child"]] = e.get("parent")
        elif e["type"] == "open":
            path = e.get("path") or ""
            if e.get("pid") is not None:
                proc.setdefault(e["pid"], {"ppid": e.get("ppid"), "oppid": e.get("oppid"),
                                           "ptok": e.get("ptok"), "resp": e.get("resp"),
                                           "path": e.get("exec_path") or "", "args": ""})
            if e.get("pid") is not None and any(h in path for h in CRED_HINT):
                # the live parent AT THE TIME OF THE OPEN - this is what a naive
                # parent-walk sees, and it is lost when the process re-parented.
                actions.append({"pid": e["pid"], "what": "opened credential",
                                "live_ppid": e.get("ppid"), "resp": e.get("resp")})
                seen_pids.add(e["pid"])
    # network-tool / interpreter execs are likely senders; add any not already an action
    for pid, info in proc.items():
        if pid not in seen_pids and any(h in (info.get("path") or "") for h in NET_HINT):
            actions.append({"pid": pid, "what": f"ran {info['path'].split('/')[-1]}",
                            "live_ppid": info.get("ppid"), "resp": info.get("resp")})
    return proc, fork_parent, actions


def reaches_from(start, agents, step, maxhops=64):
    """Walk from `start` via `step`; True if an agent pid is reached (start incl.)."""
    seen = set()
    cur = start
    for _ in range(maxhops):
        if cur in agents:
            return True
        if cur is None or cur in seen:
            break
        seen.add(cur)
        cur = step(cur)
    return False


def attribute(action, proc, fork_parent, agents):
    pid, live_ppid, resp = action["pid"], action.get("live_ppid"), action.get("resp")
    # 1. naive parent-walk: from the live parent at action time, up the chain.
    #    Re-parenting (live_ppid -> launchd) severs this.
    v_ppid = (pid in agents) or reaches_from(live_ppid, agents,
                                             lambda p: (proc.get(p) or {}).get("ppid"))
    # 2. fork-lineage: the parent recorded at fork time (original_ppid /
    #    parent_audit_token), captured by the kernel before any re-parenting.
    def fork_step(p):
        info = proc.get(p) or {}
        return info.get("oppid") or info.get("ptok") or fork_parent.get(p) or info.get("ppid")
    v_fork = reaches_from(pid, agents, fork_step)
    # 3. responsible process: the kernel's responsible_audit_token chain.
    v_resp = reaches_from(resp, agents, lambda p: (proc.get(p) or {}).get("resp")) \
        if resp is not None else False
    return v_ppid, v_fork, v_resp


CRED_HINT = (".aws/credentials", "/credentials", "id_rsa", ".netrc")
NET_HINT = ("/curl", "/python", "/nc", "/wget", "/git")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("events", help="eslogger JSONL file")
    ap.add_argument("--agent-pid", type=int, action="append", default=[], dest="agents")
    ap.add_argument("--probe", action="store_true", help="print keys of first events and exit")
    a = ap.parse_args()

    raw = []
    with open(a.events) as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                raw.append(json.loads(ln))
            except Exception:
                pass
    if a.probe:
        for ev in raw[:5]:
            print(json.dumps(ev, indent=2)[:1500])
            print("----")
        return 0

    agents = set(a.agents)
    proc, fork_parent, actions = build(raw)
    # de-duplicate actions by pid, keeping the credential-open view if present
    by_pid = {}
    for act in actions:
        if act["pid"] not in by_pid or act["what"] == "opened credential":
            by_pid[act["pid"]] = act

    print(f"agent pids: {sorted(agents)}   processes: {len(proc)}   actions: {len(by_pid)}\n")
    print(f"{'pid':>7}  {'what':22} {'ppid-walk':10} {'fork-line':10} {'responsible':11}")
    print("-" * 70)
    n = att_ppid = att_fork = att_resp = att_any = reparent = 0
    for pid, act in sorted(by_pid.items()):
        vp, vf, vr = attribute(act, proc, fork_parent, agents)
        n += 1
        att_ppid += vp; att_fork += vf; att_resp += vr
        if vp or vf or vr:
            att_any += 1
        if not vp and (vf or vr):   # ppid lost it, a re-parent-proof signal kept it
            reparent += 1
        print(f"{pid:>7}  {act['what']:22} {'reach' if vp else 'LOST':10} {'reach' if vf else 'LOST':10} {'reach' if vr else 'LOST':11}")
    print("-" * 70)
    print(f"{n} kernel-observed actions | attributed to agent: {att_any}/{n}")
    print(f"  by ppid-walk: {att_ppid}  by fork-lineage: {att_fork}  by responsible: {att_resp}")
    print(f"  re-parented (ppid lost, OS recovered): {reparent}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
