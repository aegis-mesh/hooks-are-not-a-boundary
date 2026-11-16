# Hooks Are Not a Boundary — reproduction kit

Reproduces the measurements in the study *Hooks Are Not a Boundary*: the pre-tool
hook in Claude Code, Cursor, and Codex, held to one shared deny-list policy,
blocks the plainly written form of every attack and none of eight structural
evasions, identically across the three agents, while the operating system below
observes and attributes every evaded action.

Everything runs against a **fake canary credential** (`AKIACANARY0000000000`) and
a **local server bound to `127.0.0.1`**. Nothing reads a real home folder or
sends anything off the machine.

## What's here

| Path | What it is |
|---|---|
| `policy/guard_core.py` | one shared credential-exfil / persistence deny-list |
| `policy/policy_server.py` | the same deny-list served over HTTP, for the "break the hook" scenario: stop it and every hook that depends on it errors, then fails open |
| `adapters/` | three adapters that speak each vendor's documented hook contract (Claude `PreToolUse`, Cursor `beforeShellExecution`/`beforeReadFile`, Codex `PreToolUse`) and route the one policy |
| `drivers/run_matrix.py` | the deterministic matrix: feed each hook the exact tool call, record the decision, and on an allow perform the action and check the outcome |
| `drivers/test_adapters.py`, `drivers/test_policy_server.py` | unit tests for the three hook contracts and for the policy-server break-the-hook result |
| `live/` | wires each agent's real hook and drives the real `claude` / `cursor-agent` / `codex` binaries |
| `os/lineage.py` | process-lineage attribution over Endpoint Security (`eslogger`) events, with `test_lineage.py` |
| `sandbox/sandbox_axis.sh` | Codex OS sandbox: network send under `workspace-write` vs `danger-full-access` |
| `setup_lab.sh`, `run_bundle.sh` | build the lab and run the parts you ask for |
| `evidence/` | the authors' own run output (matrix, receipts, attribution, sandbox) for comparison |

## Run it

The deterministic matrix needs no model, no network, and no privileges:

```bash
bash setup_lab.sh /tmp/hooklab
python3 drivers/run_matrix.py /tmp/hooklab
```

It prints the 8-technique by 3-agent matrix and writes `logs/matrix.csv`.

For the full set, from a terminal with **Full Disk Access** (the kernel capture
needs root; the sandbox test needs Seatbelt):

```bash
bash run_bundle.sh               # deterministic + live + OS + sandbox
bash run_bundle.sh --os --sandbox
bash run_bundle.sh --live        # uses your Claude / Cursor / Codex accounts
```

- **Live runs** drive the real agents and use your own accounts; a model
  refusing a step is a finding, not an error.
- **OS attribution** runs `eslogger` (root) and reconstructs the process tree;
  `os/lineage.py --probe` prints the first events so the parser can be matched to
  your macOS version.
- **Sandbox axis** runs under a plain terminal (Seatbelt is unavailable inside a
  sandboxed shell).

## Reproducing on a spare account

Use a throwaway VM or a spare user account. The policy, the three adapters, the
policy-server break-the-hook result, and the attribution analyser each ship with
unit tests (`python3 drivers/test_adapters.py`, `python3 drivers/test_policy_server.py`,
`python3 os/test_lineage.py`) that pass offline.

## Safety

- The key is a canary, not a real secret.
- The "attacker" is always `127.0.0.1`, a local server that only logs.
- Run on a spare account or VM for extra isolation. Do not point the hook or the
  payloads at a real home folder.

## License

MIT. See `LICENSE`.
