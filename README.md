# enumerate-entra.py

Read-only misconfiguration enumerator for Azure subscriptions and an Entra ID
tenant. It runs a fixed set of checks, prints one plain-text report, and records
for each area whether it was assessed and why.

`enumerate-entra.py` is one file and imports only the Python 3 standard library.
There is no packaging step and no third-party dependency. `selftest.py` sits
beside it and exercises the failure paths and the documented payload shapes.

## What it does

- Runs 319 checks against Azure Resource Graph, the ARM REST API and Microsoft
  Graph.
- Reads an AzureHound export for identity objects that Graph access does not
  reach.
- Reports each finding with `subject`, `scope`, `evidence`, `why` and a `repro`
  command.
- Prints a coverage table with, per check, the status and the number of objects
  examined and denied.
- Prints attack chains for escalation paths. Each chain has an id (`CH-01`) and
  the check that produced it, and the id appears in the detail block of every
  finding in that chain.

It sends GET requests and POST `/list` calls. It does not write to the tenant.

## Requirements

- `az` CLI, logged in, with `Reader` on the target subscriptions and
  `Global Reader` in the tenant. `Security Reader` covers conditional access and
  security policy, but role management, PIM and application checks report
  denials.
- Optional: an AzureHound JSON export for the offline identity checks.

## Usage

```bash
export SUBS="00000000-0000-0000-0000-000000000001,00000000-0000-0000-0000-000000000002"
python3 enumerate-entra.py --azurehound azurehound.json
```

```bash
python3 enumerate-entra.py \
  --subs "$SUBS" \
  --azurehound azurehound.json \
  --report audit-run.txt \
  --dot chains.dot \
  --baseline previous.txt \
  --fail-on high
```

## Options

| Option | Effect |
|---|---|
| `--subs a,b,c` | Comma-separated subscription ids. Defaults to `SUBS`, then to `az account list`. |
| `--azurehound FILE` | AzureHound JSON export for identity objects. |
| `--tenant ID` | Audit this tenant explicitly. A login from a different tenant exits 2 and prints the `az login --tenant` command, so results are not attributed to the wrong directory. |
| `--peer-tenant a,b` | Other tenants this login can read. Privileged role holders are compared with this tenant: the same object id privileged in both, guests holding roles there, and the same UPN privileged in both under different ids. A peer that cannot be read is recorded as a gap. |
| `--no-subs` | Tenant mode. No subscription list is read or required. Every check that reads subscription resources is recorded as `skipped`, including the Graph-backed ones. The Entra ID checks run normally. `az login` is still required for Graph. |
| `--no-az` | Skip every check that needs the CLI. The checks that read only the AzureHound export still run. Skipped checks are recorded as `skipped`. |
| `--no-entra` | Skip every Entra and Graph check, including the `sub-*` checks that call Graph. Skipped checks are recorded as `skipped`. |
| `--report FILE` | Write the same text report to a file. The file omits the final `report written:` line, which goes to stdout only. |
| `--dot FILE` | Write a graphviz rendering of the attack chains. Each chain has its own node, labelled with its `CH-nn` id. |
| `--baseline FILE` | One line per finding, `severity\|check\|subject\|subscription\|scope`. The first run writes the file; later runs print new, severity-changed and resolved entries. A run narrowed by `--check`, `--no-subs`, `--no-az`, `--no-entra`, `--include-vms` or `--peer-tenant` merges into the file instead of replacing it. A key that survives the merge is not reported as resolved. |
| `--check a,b` | Run only the named checks. An unknown name exits 2. |
| `--min-severity S` | Lowest severity to print. Does not affect `--fail-on`. |
| `--fail-on S` | Exit 1 when a finding or chain at or above `S` exists, regardless of `--min-severity`. |
| `--list-checks` | Print every check name and exit. |
| `--lint` | Run the lint gates and exit 1 on a violation. The gates are listed in `AGENTS.md`. |
| `--strict` | Exit 3 when a check is `partial`, `absent`, `error`, `truncated`, `throttled`, `degraded` or `failed`. `sampled` does not trigger it. |
| `--include-vms` | Include VM internals: disks, JIT status, extensions, custom data. |

Environment variables:

| Variable | Effect |
|---|---|
| `SUBS` | Default subscription list, comma-separated. |
| `GRAPH_ENDPOINT` | Override the Microsoft Graph base URL, for sovereign clouds. |
| `ARM_ENDPOINT` | Override the ARM base URL, for sovereign clouds. |

## Output

Output is plain text. There is no SARIF, JSON, CSV or Markdown. Scripts use the
exit code and the `--baseline` file.

Sections, in order:

1. `scope` — what is included and what is excluded.
2. `subscriptions`, `inventory`, `azurehound` — the denominators.
3. `new since baseline`, `severity changed since baseline` and `resolved since
   baseline`, when `--baseline` is used.
4. `coverage` — per check: status, examined, denied.
5. `truncated:` — pagination that was not followed, after the coverage table.
6. `blind spots` — checks that did not complete cleanly, with the reason.
7. `by subscription` — severity counts and resource totals.
8. `chains` — one line per chain: id, severity, name, owning check, path.
9. `findings` — one line per finding.
10. Per-finding detail blocks grouped by subscription. A block lists the chain
    ids its check produced in a `chains` line.
11. `attack chains` — one block per chain: id, severity, name, owning check,
    path, reason.

### Coverage status values

| Status | Meaning |
|---|---|
| `ok` | The check ran and every call succeeded. |
| `empty` | The check ran, nothing matched, nothing failed. |
| `partial` | Some calls were denied, so part of the area is unassessed. |
| `absent` | The API answered 404, or the check needed an input that was never loaded: the object or endpoint does not apply. |
| `truncated` | A page cap was reached; the remainder was not assessed. |
| `sampled` | A deliberate list cap; the number inspected is recorded in `detail`. |
| `degraded` | More than 40 % of the parsed fields were absent. |
| `throttled` | Rate limited after retries. |
| `error` | Transport or parse fault. |
| `failed` | The check raised an exception. |
| `skipped` | The check was excluded by `--no-subs`, `--no-az`, `--no-entra` or `--check`. |

A check that cannot read its input reports `partial`, `error` or `absent`. It
does not report `empty`.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Run completed, no gate triggered. |
| 1 | A finding or chain at or above `--fail-on` exists. |
| 2 | Bad arguments, unknown `--check` name, or no subscriptions. |
| 3 | `--strict` and at least one check did not complete cleanly. |

## Scope

In scope by default: subscription control plane (RBAC, policy, Key Vault,
storage, SQL, networking, App Service, AKS, Defender, backup, diagnostics,
Sentinel, Lighthouse), and tenant identity (conditional access, applications,
service principals, roles, PIM visibility, federation, guests).

Out of scope by default: VM internals (extensions, JIT, disk encryption,
custom data), Key Vault and other data planes, on-premises infrastructure,
sign-in history older than the retention window.

The tool probes data-plane access. A denied probe is recorded as a coverage gap.

## Self-test

```bash
python3 selftest.py
```

Two suites run in one process.

The failure-path suite stubs every transport call to return `None`, then runs
all checks. It asserts three things: no check raises, no check emits a `medium`,
`high` or `critical` finding, and no check that made a transport call reports
`ok` or `empty` with no findings.

The payload suite runs one check against a documented payload shape and asserts
the finding that must appear and the finding that must not, including the
evidence and the attribution where those are the part that would be wrong. It
covers the defects that a failure-path stub cannot see: a field read from the
wrong path, an enum value outside its domain, an identifier compared across two
namespaces.

It exits 1 and names the failing case or the offending check.

## Known limitations

- About 180 checks read raw API rows. A field spec turns a renamed field into an
  unknown state; a raw read does not.
- Pagination on the 23 direct REST calls is followed, but a page cap can still
  truncate; truncation is reported.
- PIM activation requests and their approval history are not read. Eligibility,
  role policy rules and PIM for Groups are.
- Key Vault secrets are not enumerated. Keys and certificates are read through
  the control plane.
- A partial AzureHound export produces false orphan findings. The tool detects a
  missing, empty or unparseable export, but not a complete-looking subset.
- An export that is missing, empty or unparseable makes every check that needs it
  report `absent`. It does not yield an identity verdict.

## Repository layout

| File | Content |
|---|---|
| `enumerate-entra.py` | The enumerator. |
| `selftest.py` | Failure-path and payload regression suites. See above. |
| `.lint-baseline` | Construct budget: total plus per-check counts. |
| `AGENTS.md` | Rules for changing the enumerator. |
| `README.md` | This file. |
| `LICENSE` | MIT. |
| `.gitignore` | Bytecode caches, tool caches, the default AzureHound export. |

## Files written

| Flag | File | Content |
|---|---|---|
| `--report` | text | The report. The final `report written:` line is not written. |
| `--dot` | dot | Attack chain graph. |
| `--baseline` | text | One `severity\|check\|subject\|subscription\|scope` line per finding. |
| `--lint` | `.lint-baseline` | Allowed construct count, total and per check. |

## License

MIT. See [LICENSE](LICENSE).
