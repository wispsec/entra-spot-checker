# enumerate-entra.py

Read-only misconfiguration enumerator for Azure subscriptions and an Entra ID
tenant. It answers a fixed set of audit questions, prints one human-readable
text report, and records why every area was or was not assessed.

One script, Python 3 standard library only. No packaging, no dependencies. A
self-test ships next to it.

## What it does

- Runs 315 checks against Azure Resource Graph, the ARM REST API, and Microsoft
  Graph.
- Reads an AzureHound export for identity objects that Graph access does not
  reach.
- Prints findings with `subject`, `scope`, `evidence`, `why`, and a `repro`
  command.
- Prints a coverage table that states, per check, what was examined and what
  was denied, absent, truncated, throttled, degraded or failed.
- Prints attack chains when a finding composes with another into an escalation
  path. Every chain carries an id (`CH-01`), the check that produced it, and the
  id is repeated in the detail block of each finding that belongs to it.

Read-only. It issues GET requests and a small number of POST `/list` calls.
It never writes to the tenant.

## Requirements

- `az` CLI, logged in, with at least `Reader` on the target subscriptions and
  `Global Reader` or `Security Reader` in the tenant.
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
| `--tenant ID` | Audit this tenant explicitly. If the current login belongs to a different tenant the run exits 2 with the `az login --tenant` command, so results are never attributed to the wrong directory. |
| `--peer-tenant a,b` | Other tenants this login can read. Their privileged role holders are compared with this tenant: the same object id privileged in both, guests holding roles there, and the same UPN privileged in both under different ids. Unreadable peers are reported, not assumed clean. |
| `--no-subs` | Tenant mode. No subscription list is read or required. Every `sub-*` check and every `sub-*` check that also reads Graph is recorded as `skipped`, and the Entra ID checks run normally. Implies nothing about the CLI: `az login` is still needed for Graph. |
| `--no-az` | Skip every check that needs the CLI. The checks that read only the AzureHound export still run and are the whole result. Skipped checks are recorded with status `skipped`. |
| `--no-entra` | Skip every Entra and Graph check, including the sub-* checks that call Graph. Skipped checks are recorded with status `skipped`. |
| `--report FILE` | Write the same text report to a file. The file is a byte-identical copy of stdout. |
| `--dot FILE` | Write a graphviz rendering of the attack chains. Each chain is its own node, labelled with its `CH-nn` id. |
| `--baseline FILE` | One line per finding, `severity|check|subject|subscription|scope`. First run writes it; later runs print new, severity-changed and resolved entries. A run narrowed by `--check`, `--no-subs`, `--no-az`, `--no-entra`, `--include-vms` or `--peer-tenant` merges into the file instead of replacing it, and a key that survives the merge is never reported as resolved. |
| `--check a,b` | Run only the named checks. Unknown names exit 2. |
| `--min-severity S` | Lowest severity to print. Does not affect `--fail-on`. |
| `--fail-on S` | Exit 1 when any finding at or above `S` exists, regardless of `--min-severity`. |
| `--list-checks` | Print every check name and exit. |
| `--lint` | Construct budget, check-name and finding-id gates. See Lint ratchet. |
| `--strict` | Exit 3 when any check is partial, absent, truncated, throttled, degraded or failed. A deliberate sample does not trigger it. |
| `--include-vms` | Include VM internals: disks, JIT status, extensions, custom data. |

Environment variables:

| Variable | Effect |
|---|---|
| `SUBS` | Default subscription list, comma-separated. |
| `GRAPH_ENDPOINT` | Override the Microsoft Graph base URL, for sovereign clouds. |
| `ARM_ENDPOINT` | Override the ARM base URL, for sovereign clouds. |

## Output

Text only. There is no SARIF, JSON, CSV or Markdown output. Findings are read
by a human; automation consumes the exit code and `--baseline`.

Report sections, in order:

1. `scope` — what is included and what is excluded.
2. `subscriptions`, `inventory`, `azurehound` — the denominators.
3. `new since baseline`, `severity changed since baseline` and `resolved since
   baseline`, when `--baseline` is used.
4. `truncated:` — pagination that was not followed.
5. `coverage` — per check: status, examined, denied.
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
| `skipped` | The check was excluded by `--no-az`, `--no-entra` or `--check`. |

`empty` never means "passed". A check that cannot read its input reports
`partial`, `error` or `absent`, never `empty`.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Run completed, no gate triggered. |
| 1 | A finding at or above `--fail-on` exists. |
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

Data-plane access is probed, not assumed. A denied probe is reported as a
scope limitation, not as a clean result.

## Design notes

- Findings anchor on a subscription and a scope. A check that receives zero
  resources reports `subscription-unexamined` instead of silence.
- Coverage is derived from the transport layer, not written by each check.
  Every API call records its result against the running check, so a check that
  forgets to report cannot claim a clean result, and a swallowed failure still
  shows as `partial`.
- One convention for a failed read: transport helpers return `None`, and `None`
  never becomes an empty container. A check either takes `unread()` and returns,
  or takes `unread_list()` where an empty result cannot change a verdict. Both
  record the gap, so a denied read lowers coverage instead of producing a
  finding.
- One convention for a comparison the run cannot decide: `tenant_rel()` returns
  `home`, `foreign` or `unknown`, never a boolean that folds `unknown` into
  `foreign`. `same_tenant()` is true only for a known home tenant. A caller that
  needs the distinction records the gap with `undecided()` and draws no verdict;
  an unread home tenant therefore never turns an internal delegation, a
  first-party application or a peer directory into an external one.
- One convention for a finding's subscription: `add()` takes the caller's value,
  else the subscription id inside its subject or scope. When neither yields one
  and the finding comes from a `sub-*` check, the run records an unattributed
  finding and the check reports `partial`, so a forgotten argument cannot pass
  as a tenant-level fact.
- One convention for a missing input: `load_ah()` returns a state
  (`ok`, `missing`, `empty`, `unreadable`). The identity index raises when a
  check reads from an unusable dataset, and the runner records `absent` for that
  check. An unreachable export never becomes "the export says nothing".
- Field parsing is explicit where a type has been migrated: `tri()` returns
  `True`, `False` or `None`, so an absent property never collapses into a
  compliant value.
- `--fail-on` reads all findings, not the `--min-severity` view.

## Lint ratchet

```bash
python3 enumerate-entra.py --lint
```

Five gates run. Any failure exits 1.

**Construct budget.** Banned inside `@check` bodies: `.get("`, `or []`,
`az(["rest"`, `DENIED[`, `== "false"`, `!= "true"`. `.lint-baseline` holds the
total plus a per-check count. A check that grows fails even when the total falls,
so one fix cannot hide a new violation in another check. Adding a banned
construct requires lowering the count elsewhere in the same check, or editing the
baseline in the diff.

**Check identity.** Every `note(...)` and `deny(...)` name must be a registered
check. A typo would create a phantom coverage row that `--strict` counts; the
gate rejects it instead.

**Failed reads.** `if X is None: X = []` after a transport call fails, as does
`lst(<read>)` and `<read> or []`. A failed read must go through `unread()` and
return, or through `unread_list()` where the empty result genuinely cannot
change a verdict.

**Scope declaration.** A call with `scoped=False` opts out of the automatic
`subscriptionId` filter. The gate requires the query to carry its own
`subscriptionId` predicate, or to be wrapped in `tenant_wide()` (the rows are
directory objects that carry no subscription id) or `filtered_in_python()` (the
caller narrows the rows after the call). A query that does neither fails.

**Finding identity.** Two stateless rules over the source. No register file.

- One finding, one spelling: two ids that are equal once hyphens and underscores
  are removed fail, so `storage-sharedkey-enabled` cannot sit next to
  `storage-shared-key-enabled`.
- Every id resolves to a register tag: an id that is neither in `FRAMEWORK` nor
  matched by a `PREFIX_RULES` token would be tagged `MISC-`, so it fails instead.

Ids that are computed at runtime are listed and covered by the spelling rule only.

## Failure-path self-test

```bash
python3 selftest.py
```

Stubs every transport call to return `None`, then runs all checks. Three
conditions must hold:

- No check raises.
- No check emits a `medium`, `high` or `critical` finding. A failed read cannot
  produce a verdict.
- No check that made a transport call reports `ok` or `empty` with no findings.

The test exits 1 and names the offending check. Run it after changing a check
that consumes a transport result.

## Known limitations

- About 186 checks still read raw API rows. Field-name drift produces unknown
  states rather than wrong verdicts only where a field spec exists.
- Pagination on the 24 direct REST calls is followed, but a page cap can still
  truncate; truncation is reported.
- PIM approval rules, activation duration and PIM for Groups are not readable
  through the endpoints this tool uses.
- Key Vault object-level expiry, stored access policies and similar data-plane
  facts require permissions this tool does not assume.
- A partial AzureHound export produces false orphan findings; the tool detects a
  missing, empty or unparseable export, but not a complete-looking subset.
- An export that is missing, empty or unparseable makes every check that needs it
  report `absent`; it never yields a clean identity verdict.

## Repository layout

| File | Content |
|---|---|
| `enumerate-entra.py` | The enumerator. |
| `selftest.py` | Failure-path regression test. See above. |
| `.lint-baseline` | Construct budget: total plus per-check counts. Committed; only ever lowered. |
| `README.md` | This file. |
| `LICENSE` | MIT. |

## Files written

| Flag | File | Content |
|---|---|---|
| `--report` | text | Copy of stdout. |
| `--dot` | dot | Attack chain graph. |
| `--baseline` | text | One `severity\|check\|subject\|subscription\|scope` line per finding. |
| `--lint` | `.lint-baseline` | Allowed construct count, total and per check. |

## License

MIT. See [LICENSE](LICENSE).
