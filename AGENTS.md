# Agent instructions

Guidance for agents that change the Azure and Entra ID enumerator. Read
`README.md` for what the tool does. This file states how to change it without
breaking it.

## Repository facts

- `enumerate-entra.py` is one 10,000-line Python file with 314 `@check` functions.
  Standard library only. No packaging step.
- `selftest.py` is the failure-path regression test. It imports the script by path.
- `.lint-baseline` is a committed gate file. It holds a total and one count per
  check.
- `README.md` and `LICENSE` are documentation. Keep them true.

## Ground rules

1. Do not add a dependency. The script must run on a stock Python 3.
2. Do not split the script into modules. One file is a design requirement.
3. Do not use `git stash`, a worktree or a feature branch. Several agents work in
   this tree.
4. Do not add generated or cache artifacts to `.gitignore`. It lists only
   bytecode caches, tool caches and the default AzureHound export.
5. Keep every edit inside the scope of the request. Report anything else.
6. Do not copy the source to a scratch path to try a change, and do not keep
   backup copies of it. Patch with `serena`, verify, then patch back or fix
   forward.

## Verification loop

Run these four steps after every edit batch. Do not report success without them.

```bash
python3 -m py_compile enumerate-entra.py      # must print nothing
python3 enumerate-entra.py --lint             # must exit 0
python3 selftest.py                           # must exit 0
python3 enumerate-entra.py --no-subs --azurehound /tmp/demo-ah.json   # must exit 0
```

The full run must show zero `Traceback`, zero `check-error` and zero `MISC-`
strings. `--strict` cannot pass in a sandbox without `az login`; a strict failure
that names transport errors is expected and is not a logic bug.

Apply edits through `serena` symbol tools, then read diagnostics with
`get_diagnostics_for_file`. Pyright must report no error and no warning.

## Structural invariants

These four conventions carry most of the correctness. Preserve them.

### A failed read is not an empty result

Transport helpers return `None` when a read fails. `None` never becomes `[]` or
`{}`.

- A check that needs the data takes `unread(rows, what, finding)` and returns when
  the result is `None`. The helper records the denial and an info finding.
- A check where an empty result cannot change a verdict takes
  `unread_list(rows, what, finding)`.
- `lst()` returns `[]` for a non-list. Never pass a transport result to it.

### A failed read must not be laundered through `lst()`

`lst(<read>)` fails the gate. `lst(local_name)` is the sanctioned coercion: it is
named, and the check already recorded the denial. A bare `X or []` on a local
name that holds a transport result fails.

### A three-state fact never becomes a boolean

`tenant_rel(value)` returns `home`, `foreign` or `unknown`. `same_tenant()` is
true only for a known home tenant; it is never the way to test "not us". A
comparison that cannot be decided calls `undecided(finding, evidence, why)`,
which records a denial and an info finding, and the caller draws no verdict.

### A finding carries its subscription

`add()` defaults `subscription` to the id inside the subject or scope. A `sub-*`
finding that yields neither is counted as unattributed and makes the check
`partial`. Pass the subscription explicitly in a per-subscription loop.

### A missing input is a state

`load_ah()` returns `(nodes, state, detail)`. `state` is `ok`, `missing`, `empty`
or `unreadable`. `Index` raises `DatasetUnavailable` when a check reads from a
dataset that is not `ok`. The runner records `absent` coverage for that check.
Never turn an unreadable input into a clean negative finding.

### Check identity comes from the registry

`REGISTRY_NAMES` is filled by the `@check` decorator. `note()` and `deny()` route
through `own()`, so a misspelled name is booked against the running check and
recorded in `PHANTOM`. Do not write a literal check name at a call site unless it
is the running check.

### Attribution is owned by `audit_scope()`

`CURRENT["check"]`, the suppression flag, `LAST_QUERY[check]` and `LAST_ERROR` are
shared state. Change them only inside `with audit_scope(...)`, or in the runner.
A helper that reads the API on behalf of a caller must not leave its own
attribution behind.

## Adding or changing a check

1. Register it with `@check("area-name")`. The name must be unique; registration
   raises on a duplicate.
2. Read data through `arg_rows`, `arg`, `graph`, `graph_all`, `per_sub`, `ca_all`,
   `arm` or `az`. Never call `subprocess` directly.
3. When a read fails, use `unread()` and return, or `unread_list()`. Do not
   continue with a value that only looks like data.
4. Call `note(name, examined)` with the count actually examined. A check that
   examined nothing and observed nothing must report `empty`, not `ok`.
5. Report findings with `add(severity, finding_id, subject, evidence, why, ...)`.
   Keep the evidence short and factual. State the observed value, not the
   conclusion. Pass `subscription` when the subject is a name rather than a
   resource id.
6. If a finding depends on a filtered list, call `sample()` when the cap is
   deliberate and `trunc()` or `capped()` when pagination stopped early.
7. Add the finding id to `FRAMEWORK` with a CWE and a register tag, or verify
   that a `PREFIX_RULES` token matches it. The lint gate rejects an untagged id.

## Finding ids

- An id names one misconfiguration. Do not invent a second spelling for an
  existing one: the lint gate compares ids with hyphens and underscores removed.
- An id that appears at two sites must mean the same thing and carry the same
  severity. Two ids for one misconfiguration is a defect.
- Severity vocabulary: `critical`, `high`, `medium`, `low`, `info`.

## Lint gates

`--lint` runs six gates and exits 1 on any failure.

| Gate | Rejects |
|---|---|
| Construct budget | A banned construct, per check and in total. |
| Check identity | A `note()` or `deny()` name that is not a registered check. |
| Failed reads | `if X is None: X = []` after a transport call, `lst(<read>)`, `<read> or []`, including on a local name that holds the result. |
| Scope declaration | A `scoped=False` query with no `subscriptionId` predicate, not wrapped in `tenant_wide()` or `filtered_in_python()`. |
| Finding identity | Two spellings of one id, an id with no register tag. |
| Finding severity | One id at two static severities: the same id must mean one misconfiguration at one severity. |

A gate failure is a code defect, not a baseline problem. Fix the code.

`.lint-baseline` shrinks on its own when a construct is removed. Growth needs an
explicit edit to the file, and only after the new construct is justified in the
change description. Never edit the file to silence a failure while the offending
construct stays in the code: the gate compares each check against its own stored
count, so a lowered total does not hide a check that grew.

## Coverage status values

Do not invent a status. The runner and `--strict` know this set: `ok`, `empty`,
`partial`, `absent`, `truncated`, `sampled`, `degraded`, `throttled`, `error`,
`failed`, `skipped`.

`empty` means the check ran, found nothing and failed at nothing. Any weaker
knowledge must use `partial`, `absent`, `truncated`, `degraded` or `error`.

## Reporting

State what changed, why, and the evidence. Quote command output rather than
asserting a result. If a claim cannot be verified in this sandbox, say so and name
the reason.

Do not describe a fix as complete when only a symptom is handled. Name the cause.
