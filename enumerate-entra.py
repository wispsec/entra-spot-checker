#!/usr/bin/env python3
"""enumerate-entra.py - Azure and Entra ID misconfiguration enumerator.

Output is a single human-readable text report on stdout.

Files written:
  --report FILE       the same text report
  --dot FILE          graphviz rendering of the attack chains
"""
import argparse
import ast
import atexit
import contextlib
import inspect
import ipaddress
import json
import os
import re
import calendar
import datetime
import subprocess
import sys
import time
from collections import Counter, defaultdict

SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
VM_ATTACHED = ("/networkInterfaces/", "/virtualMachines/", "/virtualMachineScaleSets/")
BUILTIN_ROLE_OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
BUILTIN_ROLE_UAA = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
# Application permissions that reach directory role control in one step.
GRAPH_TIER0 = ("RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All", "Application.ReadWrite.All")
GRAPH_DANGEROUS = GRAPH_TIER0 + ("Directory.ReadWrite.All", "User.ReadWrite.All", "Group.ReadWrite.All",
                                 "Sites.FullControl.All", "Mail.ReadWrite")
MS_TENANTS = ("72f988bf-86f1-41af-91ab-2d7cd011db47", "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
               "cdc5aeea-15c5-4db6-b079-fcadd2505dc2", "33e01921-4d64-4f8c-a055-5bdaffd5e33d")
# Application permissions, per resource app, that an owner can hijack by adding a credential.
TAKEOVER_ROLES = {
    GRAPH_APP_ID: ("", GRAPH_DANGEROUS),
    "00000002-0000-0ff1-ce00-000000000000": ("Exchange:", ("full_access_as_app", "Exchange.ManageAsApp")),
    "00000003-0000-0ff1-ce00-000000000000": ("SharePoint:", ("Sites.FullControl.All",)),
}
HOME_TENANT = {"id": "", "name": ""}
TENANT_NAMES = {}
TENANT_FAILED = set()


def upn_canonical(value):
    text = str(value or "").strip()
    low = text.lower()
    pos = low.find("#ext#")
    if pos >= 0:
        before = text[:pos]
        after = text[pos + 5:]
        if "@" in after:
            after = after.rsplit("@", 1)[0]
        body = before if "_" in before else (after if "_" in after else (before or after))
        body = body.strip("_#")
        if not body:
            return ""
        if "_" in body:
            local, _, domain = body.rpartition("_")
            return (local + "@" + domain).lower()
        return body.lower()
    return low


@contextlib.contextmanager
def audit_scope(check=None, suppress=None):
    """Run helper code without letting it steal the caller's attribution.

    Saves and restores the current check, the suppression flag, that check's
    repro query and the last transport error. Nested use is safe.
    """
    keep_check = CURRENT["check"]
    keep_suppress = CURRENT.get("suppress", False)
    keep_error = dict(LAST_ERROR)
    keep_query = LAST_QUERY.get(keep_check, "") if keep_check else ""
    if check is not None:
        CURRENT["check"] = check
    if suppress is not None:
        CURRENT["suppress"] = suppress
    try:
        yield
    finally:
        CURRENT["check"] = keep_check
        CURRENT["suppress"] = keep_suppress
        LAST_ERROR.clear()
        LAST_ERROR.update(keep_error)
        if keep_check:
            if keep_query:
                LAST_QUERY[keep_check] = keep_query
            else:
                LAST_QUERY.pop(keep_check, None)


def tenant_rel(value):
    """Which directory a value names: home, foreign, or unknown when the home tenant was never read."""
    tid = str(value or "").strip().lower()
    home = str(HOME_TENANT["id"]).strip().lower()
    if not tid or not home:
        return "unknown"
    return "home" if tid == home else "foreign"


def same_tenant(value):
    """True only when the value is known to name the audited tenant."""
    return tenant_rel(value) == "home"


def tenant_name(tenant_id):
    tid = str(tenant_id or "").strip().lower()
    if not tid or not re.match(r"^[0-9a-f-]{36}$", tid):
        return ""
    if tid in TENANT_NAMES:
        return TENANT_NAMES[tid]
    if tid in TENANT_FAILED or len(TENANT_NAMES) >= 40:
        return ""
    with audit_scope(suppress=True):
        doc = graph("tenantRelationships/findTenantInformationByTenantId(tenantId='" + tid + "')")
    if doc is None:
        if az_kind() == "absent":
            TENANT_FAILED.add(tid)
        return ""
    label = str(val(dig(doc, "displayName"), ""))
    domain = str(val(dig(doc, "defaultDomainName"), ""))
    TENANT_NAMES[tid] = label + (" (" + domain + ")" if domain and domain.lower() != label.lower() else "")
    return TENANT_NAMES[tid]
KNOWN_FIC_ISSUERS = ("https://token.actions.githubusercontent.com", "https://oidc.prod-aks.azure.com",
                     "https://app.terraform.io", "https://gitlab.com", "https://spire.local")
LIKELIHOOD = {"info": 1, "low": 1, "medium": 2, "high": 3, "critical": 4}
IMPACT = {"info": 1, "low": 1, "medium": 2, "high": 3, "critical": 4}

FINDINGS = []
CHAINS = []
COVERAGE = {}
DENIED = defaultdict(int)
CFG = {"azurehound": "azurehound.json"}
TOKENS = {}
RESOURCE_BY_HOST = (
    ("graph.microsoft.com", "https://graph.microsoft.com"),
    ("management.azure.com", "https://management.azure.com"),
    ("vault.azure.net", "https://vault.azure.net"),
    ("servicebus.windows.net", "https://servicebus.azure.net"),
    ("documents.azure.com", "https://cosmos.azure.com"),
    ("database.windows.net", "https://database.windows.net"),
    ("cognitiveservices.azure.com", "https://cognitiveservices.azure.com"),
    ("search.windows.net", "https://search.azure.com"),
    ("azconfig.io", "https://appconfig.azure.com"),
)


def tenant_token(resource):
    tid = str(CFG.get("tenant") or "")
    if not tid:
        return ""
    key = tid + "|" + resource
    if key in TOKENS:
        return TOKENS[key]
    try:
        proc = subprocess.run(["az", "account", "get-access-token", "--tenant", tid, "--resource", resource,
                               "--query", "accessToken", "-o", "tsv"], capture_output=True, text=True, timeout=90)
    except FileNotFoundError:
        global AZ_OK
        AZ_OK = False
        LAST_ERROR.update(kind="unavailable", detail="az binary not found")
        _tally_transport(kind="unavailable")
        TOKENS[key] = ""
        return ""
    except (OSError, subprocess.SubprocessError) as exc:
        LAST_ERROR.update(kind="unavailable", detail=("az token request failed: " + str(exc))[:200])
        _tally_transport(kind="unavailable")
        TOKENS[key] = ""
        return ""
    token = (proc.stdout or "").strip()
    if not token:
        LAST_ERROR.update(kind="denied", detail=(proc.stderr or "no token for tenant " + tid)[:200])
    TOKENS[key] = token
    return token


def resource_for(url):
    host = str(url).split("//")[-1].split("/")[0].lower()
    for suffix, resource in RESOURCE_BY_HOST:
        if host.endswith(suffix):
            return resource
    return "https://management.azure.com"


def retarget(args):
    tid = str(CFG.get("tenant") or "")
    if not tid:
        return args
    if args and args[0] == "graph" and len(args) > 2 and args[1] == "query":
        query = ""
        first = 1000
        skip = ""
        dropped = []
        idx = 0
        while idx < len(args):
            if args[idx] == "-q" and idx + 1 < len(args):
                query = args[idx + 1]
                idx += 2
                continue
            if args[idx] == "--first" and idx + 1 < len(args):
                first = num(args[idx + 1], 1000)
                idx += 2
                continue
            if args[idx] == "--skip-token" and idx + 1 < len(args):
                skip = args[idx + 1]
                idx += 2
                continue
            if args[idx].startswith("--"):
                dropped.append(args[idx])
            idx += 1
        if dropped:
            print("warning: graph query scope argument dropped by the REST rewrite: " + ",".join(sorted(set(dropped))), file=sys.stderr)
        body = {"query": query, "options": {"resultFormat": "objectArray", "$top": first}}
        if skip:
            body["options"]["$skipToken"] = skip
        return retarget(["rest", "--method", "post", "--url",
                         ARM_BASE + "/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01",
                         "--body", json.dumps(body)])
    if args and args[0] == "rest":
        url = ""
        if "--url" in args:
            pos = args.index("--url")
            if pos + 1 < len(args):
                url = args[pos + 1]
        if "--headers" in args:
            return args
        token = tenant_token(resource_for(url))
        if not token:
            return None
        return args + ["--headers", "Authorization=Bearer " + token]
    return args
CACHE = {}
CACHE_URL = {}
TRUNC_KEYS = set()
EXHAUSTED = {}
GUEST_PARTIAL = set()
TRUNCATED = []
TRUNC_CHECKS = set()
CURRENT = {"check": "", "subs": [], "suppress": False}
LAST_QUERY = {}
OFFLINE_REPRO = {
    "entra-dynamic-groups": "jq -r '.. | objects | select(has(\"membershipRule\")) | [.displayName, .membershipRule] | @tsv' azurehound.json",
    "entra-immutableid": "jq -r '.data[] | select(.kind==\"AZUser\") | [.properties.onPremisesImmutableId, .properties.userPrincipalName] | @tsv' azurehound.json | sort | uniq -D -w 40",
    "entra-password-policy": "jq -r '.data[] | select(.kind==\"AZUser\") | select(.properties.passwordPolicies|tostring|test(\"DisablePasswordExpiration\")) | .properties.userPrincipalName' azurehound.json",
    "entra-synced-admins": "jq -r '.data[] | select(.kind==\"AZUser\") | select(.properties.onPremisesSyncEnabled==true) | .properties.userPrincipalName' azurehound.json",
    "entra-breakglass": "jq -r '.data[] | select(.kind==\"AZUser\") | select(.properties.displayName|test(\"break|emergency|notfall\";\"i\")) | .properties.displayName' azurehound.json",
    "entra-nested-role-groups": "az rest --url \"https://graph.microsoft.com/v1.0/groups/<group-id>/transitiveMembers?$select=id,displayName\"",
}


AZ_OK = True
NO_ENTRA = False
SECRET_PAT = re.compile(r"(?i)(password|passwd|pwd|secret|apikey|api_key|accesskey|accountkey|sas|token|credential)")
SECRET_NOISE = re.compile(r"(?i)(keyvaulturi|keyvault|secreturi|secretname|keyname|tokenurl|tenantid|endpoint)")
SECRET_MATERIAL = re.compile(r"(?i)(accountkey=|sharedaccesskey=|sharedkey=|password=|pwd=|client_secret=|sig=|sas=|apikey=|api_key=|connectionstring=)")


GRAPH_BASE = os.environ.get("GRAPH_ENDPOINT", "https://graph.microsoft.com").rstrip("/")
ARM_BASE = os.environ.get("ARM_ENDPOINT", "https://management.azure.com").rstrip("/")
LAST_ERROR = {"kind": "", "detail": "", "booked": ""}
CHECK_ERR = {}
TRANSPORT: dict = {}


def _transport_entry(check):
    entry = TRANSPORT.get(check)
    if entry is None:
        entry = {"calls": 0, "rows": 0, "fail": Counter(), "trunc": False}
        TRANSPORT[check] = entry
    return entry


def _tally_transport(data=None, kind=None, truncated=False, count_call=True):
    chk = CURRENT["check"]
    if not chk or CURRENT.get("suppress"):
        return
    entry = _transport_entry(chk)
    if count_call:
        entry["calls"] += 1
    if kind:
        entry["fail"][kind] += 1
    if truncated:
        entry["trunc"] = True
    if isinstance(data, dict):
        for key in ("value", "data"):
            rows = data.get(key)
            if isinstance(rows, list):
                entry["rows"] = int(entry["rows"]) + len(rows)
    elif isinstance(data, list):
        entry["rows"] = int(entry["rows"]) + len(data)


ABSENT_TOKENS = ("resourcenotfound", "resource not found for the segment", "not applicable to target tenant",
                 "no http resource was found", "account is not provisioned", "missingprovider",
                 "aadb2c", "authentication_requestfromnonpremiumtenantorb2ctenant")
DENIED_TOKENS = ("(403", "forbidden", "authorizationfailed", "does not have authorization", "accessdenied",
                 "authorization_requestdenied", "unauthorized", "authorization_error", "permissionscopenotgranted",
                 "insufficient privileges", "not authorized", "required scopes", "don't have the required")


def _classify(stderr):
    t = (stderr or "").lower()
    if re.search(r"\(\s*(429|too many requests)\)", t) or "throttl" in t:
        return "throttled"
    if "please run 'az login'" in t or "not logged in" in t:
        return "unauthenticated"
    if any(k in t for k in DENIED_TOKENS):
        return "denied"
    if re.search(r"\(\s*404\)", t) or any(k in t for k in ABSENT_TOKENS):
        return "absent"
    return "error"


def az(args, timeout=150, retries=3):
    global AZ_OK
    LAST_ERROR.update(kind="", detail="", booked="")
    args = retarget(args)
    if args is None:
        if not LAST_ERROR.get("kind"):
            LAST_ERROR.update(kind="denied", detail="no token for tenant " + str(CFG.get("tenant")))
        _tally_transport(kind=LAST_ERROR.get("kind") or "denied")
        return None
    cmd = ["az"] + args + ["-o", "json", "--only-show-errors"]
    delay = 1.5
    for attempt in range(retries):
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError:
            AZ_OK = False
            LAST_ERROR.update(kind="unavailable", detail="az binary not found")
            _tally_transport(kind="unavailable")
            return None
        except subprocess.TimeoutExpired:
            LAST_ERROR.update(kind="unavailable", detail="az timed out after " + str(timeout) + "s")
            _tally_transport(kind="unavailable")
            return None
        if p.returncode == 0:
            try:
                parsed = json.loads(p.stdout) if p.stdout.strip() else {}
            except json.JSONDecodeError:
                LAST_ERROR.update(kind="error", detail="unparseable output")
                _tally_transport(kind="error")
                mark_failure()
                return None
            _tally_transport(parsed)
            return parsed
        kind = _classify(p.stderr)
        LAST_ERROR.update(kind=kind, detail=(p.stderr or "")[:200])
        transient = kind == "throttled" or re.search(r"\(\s*(500|502|503|504)\)", (p.stderr or "").lower())
        if transient and attempt < retries - 1:
            time.sleep(delay)
            delay *= 2
            continue
        _tally_transport(kind=kind)
        if kind in ("error", "unavailable", "unauthenticated") and not CURRENT.get("suppress"):
            chk = CURRENT["check"]
            if chk:
                CHECK_ERR[chk] = (kind, LAST_ERROR.get("detail", "")[:120])
                c = COVERAGE.setdefault(chk, {"examined": 0, "denied": 0, "status": "ok"})
                c["status"] = "error"
                c["detail"] = LAST_ERROR.get("detail", "")[:120]
        return None
    return None


def az_kind():
    """Kind of the last transport failure, or "" when the last call succeeded."""
    return LAST_ERROR.get("kind") or ""


def own(name):
    """The check name a coverage or denial record belongs to.

    A name that is not a registered check is a typo, not a new check. It is recorded
    and attributed to the check that is running, so no phantom coverage row appears.
    """
    if not name:
        return CURRENT["check"]
    if name in REGISTRY_NAMES:
        return name
    PHANTOM.append((CURRENT["check"], str(name)))
    return CURRENT["check"]


def deny(check, n=1):
    """Record n denials for a check and return the running total."""
    check = own(check)
    COVERAGE.setdefault(check, {"examined": 0, "denied": 0, "status": "ok"})
    DENIED[check] += n
    return DENIED[check]


def denied_now(check):
    """Record a transport failure for check, whatever the current check happens to be.

    Every kind is booked: a denial counts against the check, an error or throttle
    sets its status. Returns True when the failure was a denial.
    """
    with audit_scope(check=check or CURRENT["check"]):
        mark_failure()
    return az_kind() == "denied"


def mark_failure():
    chk = CURRENT["check"]
    if not chk or CURRENT.get("suppress") or LAST_ERROR.get("booked") == chk:
        return
    LAST_ERROR["booked"] = chk
    kind = az_kind() or "error"
    CHECK_ERR[chk] = (kind, LAST_ERROR.get("detail", "")[:120])
    c = COVERAGE.setdefault(chk, {"examined": 0, "denied": 0, "status": "ok"})
    if kind in ("error", "unavailable", "unauthenticated"):
        c["status"] = "error"
        c["detail"] = LAST_ERROR.get("detail", "")[:120]
    elif kind == "throttled":
        c["status"] = "throttled"
        c["detail"] = "rate limited after retries; area not assessed"
    elif kind != "absent":
        DENIED[chk] += 1


CA_CACHE = {}
CA_PATH_POLICIES = ("identity/conditionalAccess/policies", "conditionalAccessPolicies")
CA_PATH_LOCATIONS = ("identity/conditionalAccess/namedLocations", "conditionalAccess/namedLocations")


def ca_all(kind="policies", limit=5):
    if kind in CA_CACHE:
        return CA_CACHE[kind]
    paths = CA_PATH_POLICIES if kind == "policies" else CA_PATH_LOCATIONS
    first = None
    for idx, path in enumerate(paths):
        rows = graph_all(path, limit=limit)
        if rows is None:
            continue
        if rows:
            for other in paths[idx + 1:]:
                second = graph_all(other, limit=limit)
                if second is not None and len(second) != len(rows):
                    add("low", "ca-path-discrepancy", kind, path + "=" + str(len(rows)) + " " + other + "=" + str(len(second)), "the canonical and legacy endpoints disagree; verify the tenant state before trusting either")
                    break
            CA_CACHE[kind] = rows
            return rows
        if first is None:
            first = rows
    if first is not None:
        CA_CACHE[kind] = first
        return first
    return None


def ca_complete():
    """True when the cached policy list was read without hitting a page cap."""
    return not any(p in TRUNCATED for p in CA_PATH_POLICIES)


def graph(path, beta=False):
    key = "graph:" + ("beta:" if beta else "") + path
    if key in CACHE:
        if CURRENT["check"] and not CURRENT.get("suppress"):
            LAST_QUERY[CURRENT["check"]] = "az rest --url " + repr(CACHE_URL.get(key, GRAPH_BASE + ("/beta/" if beta else "/v1.0/") + path.lstrip("/")))
        return CACHE[key]
    base = GRAPH_BASE + "/beta/" if beta else GRAPH_BASE + "/v1.0/"
    url = path if path.startswith("http") else base + path.lstrip("/")
    if CURRENT["check"] and not CURRENT.get("suppress"):
        LAST_QUERY[CURRENT["check"]] = "az rest --url " + repr(url)
    out = az(["rest", "--url", url])
    if out is None:
        mark_failure()
        return None
    partial = False
    if isinstance(out, dict) and out.get("@odata.nextLink") and isinstance(out.get("value"), list):
        items = list(out["value"])
        nxt = out.get("@odata.nextLink")
        pages = 0
        while nxt and pages < 20:
            page = az(["rest", "--url", nxt])
            if page is None:
                partial = True
                break
            items.extend(page.get("value") or [])
            nxt = page.get("@odata.nextLink")
            pages += 1
        if nxt:
            partial = True
        out = dict(out)
        out["value"] = items
        out.pop("@odata.nextLink", None)
        out.pop("@odata.deltaLink", None)
    if partial:
        if url not in TRUNCATED:
            TRUNCATED.append(url)
        _tally_transport(truncated=True, count_call=False)
        if CURRENT["check"] and not CURRENT.get("suppress"):
            TRUNC_CHECKS.add(CURRENT["check"])
            c = COVERAGE.setdefault(CURRENT["check"], {"examined": 0, "denied": 0, "status": "ok"})
            if c["status"] not in ("partial", "error"):
                c["status"] = "truncated"
    else:
        CACHE[key] = out
        CACHE_URL[key] = url
    return out


def graph_all(path, limit=25, beta=False, max_pages=None):
    pages_cap = limit if max_pages is None else max_pages
    key = "all:" + ("beta:" if beta else "") + str(pages_cap) + ":" + path
    if key in CACHE:
        if key in TRUNC_KEYS:
            if path not in TRUNCATED:
                TRUNCATED.append(path)
            if CURRENT["check"] and not CURRENT.get("suppress"):
                TRUNC_CHECKS.add(CURRENT["check"])
            _tally_transport(truncated=True)
        if CURRENT["check"] and not CURRENT.get("suppress"):
            LAST_QUERY[CURRENT["check"]] = "az rest --url " + repr(CACHE_URL.get(key, GRAPH_BASE + ("/beta/" if beta else "/v1.0/") + path.lstrip("/")))
        return CACHE[key]
    items = []
    base = GRAPH_BASE + "/beta/" if beta else GRAPH_BASE + "/v1.0/"
    url = base + path.lstrip("/")
    if CURRENT["check"] and not CURRENT.get("suppress"):
        LAST_QUERY[CURRENT["check"]] = "az rest --url " + repr(url)
    seen = 0
    pages = 0
    while url and seen < pages_cap:
        page = az(["rest", "--url", url])
        if page is None:
            if pages == 0:
                mark_failure()
                return None
            if path not in TRUNCATED:
                TRUNCATED.append(path)
            if CURRENT["check"] and not CURRENT.get("suppress"):
                TRUNC_CHECKS.add(CURRENT["check"])
            _tally_transport(truncated=True)
            CACHE[key] = items
            CACHE_URL[key] = url
            TRUNC_KEYS.add(key)
            return items
        pages += 1
        if pages == 1 and not isinstance(page, dict):
            mark_failure()
            return None
        if pages == 1 and "value" not in page and not dig(page, "@odata.nextLink"):
            LAST_ERROR.update(kind="error", detail="response without a value array")
            _tally_transport(kind="error")
            mark_failure()
            return None
        items.extend(lst(dig(page, "value")))
        url = page.get("@odata.nextLink")
        seen += 1
    if url:
        if path not in TRUNCATED:
            TRUNCATED.append(path)
        if CURRENT["check"] and not CURRENT.get("suppress"):
            TRUNC_CHECKS.add(CURRENT["check"])
        _tally_transport(truncated=True)
        CACHE[key] = items
        CACHE_URL[key] = GRAPH_BASE + ("/beta/" if beta else "/v1.0/") + path.lstrip("/")
        TRUNC_KEYS.add(key)
        return items
    CACHE[key] = items
    CACHE_URL[key] = GRAPH_BASE + ("/beta/" if beta else "/v1.0/") + path.lstrip("/")
    return items


def _stamp(value):
    """Epoch seconds from an ISO 8601 value, an offset, or a /Date() number. None when unreadable."""
    raw = str(value or "").strip()
    if not raw:
        return None
    match = re.match(r"^/Date\((-?\d+)\)/?$", raw)
    if match:
        return int(match.group(1)) / 1000.0
    text = re.sub(r"\.\d+", "", raw)
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.datetime.fromisoformat(text)
    except ValueError:
        parsed = None
        for fmt, size in (("%Y-%m-%dT%H:%M:%S", 19), ("%Y-%m-%d", 10)):
            try:
                parsed = datetime.datetime.strptime(text[:size], fmt)
                break
            except ValueError:
                continue
        if parsed is None:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.timestamp()


def _iso(stamp):
    """ISO 8601 UTC text for an epoch value, for evidence strings."""
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(stamp)))
    except (TypeError, ValueError, OverflowError, OSError):
        return "unknown"


def _expired(value):
    stamp = _stamp(value)
    if stamp is None:
        return None
    return stamp < time.time()


def finalize_coverage():
    for name in sorted(set(COVERAGE) | set(TRANSPORT)):
        c = COVERAGE.setdefault(name, {"examined": 0, "denied": 0, "status": "ok"})
        t = _transport_entry(name) if name in TRANSPORT else None
        if t and t["calls"]:
            if int(t["rows"]) > int(c["examined"]):
                c["examined"] = int(t["rows"])
            kinds = t["fail"]
            if kinds.get("error") or kinds.get("unavailable") or kinds.get("unauthenticated"):
                c["status"] = "error"
                c["detail"] = c.get("detail") or "transport fault"
            elif kinds.get("throttled"):
                c["status"] = "throttled"
                c["detail"] = "rate limited; area not assessed"
            elif kinds.get("denied"):
                DENIED[name] = max(DENIED[name], kinds["denied"])
                if c["status"] not in ("error", "absent"):
                    c["status"] = "partial"
            elif kinds.get("absent") and c["status"] == "ok" and not c["examined"]:
                c["status"] = "absent"
            if t["trunc"] and c["status"] in ("ok", "empty"):
                c["status"] = "truncated"
        if name in GUEST_PARTIAL and c["status"] in ("ok", "empty", "absent"):
            c["status"] = "partial"
            c["detail"] = "guest list was truncated; guest-scoped results are incomplete"
        if EXHAUSTED.get(name) and c["status"] in ("ok", "empty", "absent"):
            c["status"] = "partial"
            c["detail"] = "identity resolution budget exhausted; some objects were not assessed"
        misses = [u for u in UNATTRIBUTED if u[0] == name]
        if misses and c["status"] in ("ok", "empty", "absent"):
            c["status"] = "partial"
            c["detail"] = str(len(misses)) + " findings carry no subscription attribution"
        c["denied"] = DENIED[name]
        if c["status"] == "failed":
            continue
        if DENIED[name] and c["status"] not in ("error", "absent", "throttled", "truncated", "degraded"):
            c["status"] = "partial"
        if c["examined"] and c["status"] == "empty":
            c["status"] = "ok"
        if not c["examined"] and c["status"] == "ok":
            emitted = [f for f in FINDINGS if f.get("source") == name or f["check"] == name]
            if emitted:
                c["status"] = "ok"
                c["detail"] = c.get("detail") or "findings recorded without an examined count"
            else:
                c["status"] = "empty"
        p = PARSE.get(name)
        if p and c["status"] in ("ok", "empty"):
            total = p["resolved"] + p["missing"]
            if total >= 5 and p["missing"] / float(total) > 0.4:
                c["status"] = "degraded"
                c["detail"] = str(p["missing"]) + "/" + str(total) + " parsed fields absent"


def val(value, default=None):
    return default if value is MISSING or value is None else value


DATASET_NOTED = {"done": False}


def report_dataset_gaps():
    """One finding for the identity checks that could not run, however many there were."""
    if not DATASET_GAPS or DATASET_NOTED["done"]:
        return
    DATASET_NOTED["done"] = True
    keep = CURRENT["check"]
    CURRENT["check"] = "no-azurehound-dataset"
    add("info", "no-azurehound-dataset", "tenant", str(len(DATASET_GAPS)) + " identity checks unassessed", "run with a readable --azurehound export to assess identity objects")
    CURRENT["check"] = keep


def lst(value):
    return value if isinstance(value, list) else []


def arm(url, method="get"):
    if CURRENT["check"] and not CURRENT.get("suppress"):
        LAST_QUERY[CURRENT["check"]] = "az rest --method " + method + " --url " + repr(url)
    out = az(["rest", "--method", method, "--url", url])
    if out is None:
        mark_failure()
    return out


def subq(subs):
    return ",".join("'%s'" % s for s in subs)


def _arg_truncated(query, shown, total):
    """Record an incomplete Resource Graph result, with the owner only when one is active."""
    if query not in TRUNCATED:
        TRUNCATED.append(query)
    chk = CURRENT["check"]
    if chk and not CURRENT.get("suppress"):
        TRUNC_CHECKS.add(chk)
        c = COVERAGE.setdefault(chk, {"examined": 0, "denied": 0, "status": "ok"})
        if c["status"] not in ("partial", "error"):
            c["status"] = "truncated"
    if total and shown < total:
        print("truncated: Resource Graph returned " + str(shown) + " of " + str(total) + " rows", file=sys.stderr)


def arg(query, timeout=200, max_pages=10):
    rows = []
    token = None
    total = 0
    pages = 0
    while pages < max_pages:
        pages += 1
        args = ["graph", "query", "-q", query, "--first", "1000"]
        if token:
            args += ["--skip-token", token]
        data = az(args, timeout=timeout)
        if data is None:
            if not rows:
                return None
            _arg_truncated(query, len(rows), 0)
            return {"data": rows}
        page_rows = data.get("data")
        if isinstance(page_rows, list):
            rows.extend(page_rows)
        elif isinstance(page_rows, dict):
            rows.append(page_rows)
        try:
            total = int(data.get("totalRecords") or 0)
        except (TypeError, ValueError):
            total = 0
        token = data.get("$skipToken") or data.get("skipToken")
        if not token:
            break
    if token or (total and len(rows) < total):
        _arg_truncated(query, len(rows), total)
    return {"data": rows}


def _within_quotes(query):
    """True for every offset that sits inside a string literal, quotes included."""
    marks = [False] * (len(query) + 1)
    quote = ""
    for i, ch in enumerate(query):
        if quote:
            marks[i] = True
            if ch == quote:
                quote = ""
        elif ch in ("'", '"'):
            quote = ch
            marks[i] = True
    return marks


TENANT_WIDE = []

PYTHON_FILTERED = []


def filtered_in_python(query):
    """Mark a query whose rows the caller narrows after the call.

    For a denominator that must stay wider than the audited scope: an Owner
    assigned at a management group carries no subscriptionId, while its scope
    string still names the subscriptions below it. The caller keeps those rows.
    """
    if query not in PYTHON_FILTERED:
        PYTHON_FILTERED.append(query)
    return query


def tenant_wide(query):
    """Mark a query whose rows legitimately span subscriptions.

    Role definitions and other directory objects carry no subscriptionId, so the
    automatic filter would delete every built-in row. Only queries listed here may
    pass scoped=False without filtering themselves.
    """
    if query not in TENANT_WIDE:
        TENANT_WIDE.append(query)
    return query


def _scoped(query, subs):
    """Add a subscription filter as its own stage, before any stage that drops the column."""
    if not subs:
        return query
    if re.search(r"\|\s*where\s+subscriptionid\s+(not\s+in\b|!in\b|in\b|==|=)", query, re.IGNORECASE):
        return query
    clause = "| where subscriptionId in (" + subq(subs) + ")"
    lowered = query.lower()
    quoted = _within_quotes(query)
    marker = -1
    for match in re.finditer(r"\|\s*(project-away|project|summarize|distinct|extend|mv-expand|mv-apply|top|take|limit|join|count|search|parse|serialize|make-series|reduce)\b", lowered):
        if not quoted[match.start()] and (marker == -1 or match.start() < marker):
            marker = match.start()
    if marker == -1:
        return query.rstrip() + " " + clause
    head = query[:marker].rstrip()
    tail = query[marker:].lstrip()
    return head + " " + clause + " | " + tail.lstrip("| ")


def arg_rows(query, subs, scoped=True):
    if scoped:
        query = _scoped(query, subs)
    if CURRENT["check"] and not CURRENT.get("suppress"):
        LAST_QUERY[CURRENT["check"]] = "az graph query -q " + repr(query)
    data = arg(query)
    if data is None:
        mark_failure()
        return None
    rows = data.get("data") or []
    return rows


def per_sub(subs, path, api, pick):
    out = {}
    for s in subs:
        url = ARM_BASE + "/subscriptions/" + s + "/" + path + "?api-version=" + api
        if CURRENT["check"] and not CURRENT.get("suppress"):
            LAST_QUERY[CURRENT["check"]] = "az rest --url " + repr(url)
        doc = az(["rest", "--url", url])
        if doc is None:
            out[s] = None
            continue
        items = pick(doc)
        if not isinstance(items, list):
            items = [] if items is None else [items]
        nxt = doc.get("@odata.nextLink") or doc.get("nextLink")
        pages = 0
        lost = False
        while nxt and pages < 20:
            page = az(["rest", "--url", nxt])
            if page is None:
                lost = True
                break
            extra = pick(page)
            if isinstance(extra, list):
                items.extend(extra)
            elif extra is not None:
                items.append(extra)
            nxt = page.get("@odata.nextLink") or page.get("nextLink")
            pages += 1
        if lost or nxt:
            if url not in TRUNCATED:
                TRUNCATED.append(url)
            if CURRENT["check"] and not CURRENT.get("suppress"):
                TRUNC_CHECKS.add(CURRENT["check"])
        out[s] = items
    return out


def unread(rows, what, finding):
    """rows unchanged, or None after the gap is recorded.

    A failed read is not an empty result. The caller must return without drawing a
    verdict, so no absence of data becomes an absence of risk.
    """
    if rows is not None:
        return rows
    check = CURRENT["check"]
    deny(check)
    add("info", finding, "tenant", what + " unreadable", "this area was not assessed; no verdict is drawn from an unread source")
    return None


def unread_list(rows, what, finding):
    """An empty container for counts and inventories, with the gap recorded.

    Only for uses that cannot change a verdict. Anything that decides a finding
    must take unread() and return instead.
    """
    out = unread(rows, what, finding)
    return [] if out is None else out


def undecided(finding, evidence, why):
    """Record a comparison the run could not decide, and draw no verdict from it.

    The fact that would settle it was never read: an empty home tenant, an absent
    field, a value outside its declared domain. Info only, plus a denial so the
    check cannot report ok.
    """
    deny(CURRENT["check"])
    add("info", finding, "tenant", evidence, why)


def note(check, examined, denied=0):
    check = own(check)
    c = COVERAGE.setdefault(check, {"examined": 0, "denied": 0, "status": "ok"})
    c["examined"] = max(c["examined"], examined or 0)
    if denied:
        kind = CHECK_ERR.get(check, ("", ""))[0] or az_kind()
        if kind in ("error", "unavailable", "unauthenticated"):
            c["status"] = "error"
            c["detail"] = LAST_ERROR.get("detail", "")[:120]
        elif kind == "throttled":
            c["status"] = "throttled"
            c["detail"] = "rate limited; area not assessed"
        elif kind == "absent" and not c["examined"]:
            c["status"] = "absent"
        else:
            DENIED[check] = max(DENIED[check], denied)
    c["denied"] = DENIED[check]
    if DENIED[check] and c["status"] not in ("absent", "error"):
        c["status"] = "partial"
    elif not c["examined"] and c["status"] == "ok":
        c["status"] = "empty"
    if check in TRUNC_CHECKS and c["status"] == "ok":
        c["status"] = "truncated"


ANY_TOKENS = ("*", "any", "internet")


def _network(text):
    """A network object for a CIDR or a bare address. None when unreadable."""
    try:
        return ipaddress.ip_network(str(text or "").strip().lower(), strict=False)
    except (ValueError, TypeError):
        return None


def is_any_text(text):
    """True for the any-token spellings."""
    return str(text or "").strip().lower() in ANY_TOKENS


def cidr_covers(outer, inner):
    """True when the outer range contains the inner range, in either address family."""
    if is_any_text(inner):
        return any_source(outer)
    net_inner = _network(inner)
    if net_inner is None:
        return False
    if is_any_text(outer):
        return True
    net_outer = _network(outer)
    if net_outer is None or net_inner.version != net_outer.version:
        return False
    start = int(net_inner.network_address)
    end = int(net_inner.broadcast_address)
    return int(net_outer.network_address) <= start and end <= int(net_outer.broadcast_address)


def port_span(text):
    """(low, high) for a port, a range, or an any-token. None when unreadable."""
    raw = str(text or "").strip().lower()
    if raw in ("*", "any"):
        return (0, 65535)
    if not raw:
        return None
    low, _, high = raw.partition("-")
    if low.isdigit() and (not high or high.isdigit()):
        start = int(low)
        end = int(high) if high else start
        return (start, end) if start <= end else None
    return None


def port_covers(outer, inner):
    """True when the outer port span contains the inner span."""
    span_outer = port_span(outer)
    span_inner = port_span(inner)
    if span_outer is None or span_inner is None:
        return False
    return span_outer[0] <= span_inner[0] and span_inner[1] <= span_outer[1]


def any_source(text):
    """True when an address expression admits every address, IPv4 or IPv6."""
    if is_any_text(text):
        return True
    net = _network(text)
    return net is not None and net.prefixlen == 0


def on_off(value):
    """Normalised state for the state strings different resource providers use."""
    text = str(val(value, "")).strip().lower()
    if text in ("enabled", "alwayson", "true", "on", "yes", "1"):
        return "on"
    if text in ("disabled", "false", "off", "no", "0"):
        return "off"
    return "unknown"


def immutability(value):
    """Vault immutability: on when Locked, off when Disabled or Unlocked, unknown otherwise."""
    text = str(val(value, "")).strip().lower()
    if text == "locked":
        return "on"
    if text in ("disabled", "unlocked"):
        return "off"
    return "unknown"


def sample(check, shown, total, what="records"):
    """Record a deliberate sample: the area is assessed, the listed remainder is not."""
    if total and shown < total:
        c = COVERAGE.setdefault(check, {"examined": 0, "denied": 0, "status": "ok"})
        c["detail"] = "sampled " + str(shown) + " of " + str(total) + " " + str(what)
        if c["status"] in ("ok", "empty"):
            c["status"] = "sampled"


def capped(check, shown, what="pages"):
    """Record a page cap, where the true total is unknown and larger than shown."""
    if not check:
        return
    TRUNC_CHECKS.add(check)
    c = COVERAGE.setdefault(check, {"examined": 0, "denied": 0, "status": "ok"})
    if c["status"] not in ("partial", "error"):
        c["status"] = "truncated"
        c["detail"] = str(shown) + " " + str(what) + " read; further pages existed"


def trunc(check, shown, total, what="records"):
    if total and shown < total:
        TRUNC_CHECKS.add(check)
        c = COVERAGE.setdefault(check, {"examined": 0, "denied": 0, "status": "ok"})
        if c["status"] not in ("partial", "error"):
            c["status"] = "truncated"
            c["detail"] = str(shown) + " of " + str(total) + " " + str(what)


FRAMEWORK = {
    "subscription-owner-group": ("CWE-269", "ID-"),
    "subscription-owner-serviceprincipal": ("CWE-269", "ID-"),
    "subscription-owner-count": ("CWE-269", "ID-"),
    "implicit-access-token": ("CWE-522", "APP-"),
    "implicit-id-token": ("CWE-522", "APP-"),
    "management-group-owner": ("CWE-269", "ID-"),
    "azure-lighthouse-delegation": ("CWE-284", "ID-"),
    "classic-coadministrator": ("CWE-269", "ID-"),
    "keyvault-open-network": ("CWE-284", "KV-"),
    "keyvault-purge-protection-off": ("CWE-693", "KV-"),
    "keyvault-access-policy-model": ("CWE-778", "KV-"),
    "keyvault-broad-policy": ("CWE-269", "KV-"),
    "orphaned-keyvault-policy": ("CWE-672", "ID-"),
    "storage-public-blob-access": ("CWE-284", "ST-"),
    "storage-anonymous-container": ("CWE-284", "ST-"),
    "storage-shared-key-enabled": ("CWE-522", "ST-"),
    "storage-legacy-tls": ("CWE-326", "ST-"),
    "sql-public-endpoint": ("CWE-284", "SQL-"),
    "sql-firewall-wide-open": ("CWE-284", "SQL-"),
    "sql-allow-azure-services": ("CWE-284", "SQL-"),
    "sql-auditing-disabled": ("CWE-778", "SQL-"),
    "sql-tde-disabled": ("CWE-311", "SQL-"),
    "sql-orphaned-administrator": ("CWE-672", "ID-"),
    "nsg-internet-inbound": ("CWE-284", "NW-"),
    "policy-exemption": ("CWE-693", "GOV-"),
    "policy-not-enforced": ("CWE-693", "GOV-"),
    "deployment-history-secret": ("CWE-522", "SEC-"),
    "no-resource-locks": ("CWE-693", "GOV-"),
    "no-activity-log-export": ("CWE-778", "LOG-"),
    "no-entra-log-export": ("CWE-778", "LOG-"),
    "entra-no-log-export": ("CWE-778", "LOG-"),
    "entra-log-categories-missing": ("CWE-778", "LOG-"),
    "defender-free-tier": ("CWE-693", "GOV-"),
    "appservice-http-allowed": ("CWE-319", "APP-"),
    "appservice-ftp-enabled": ("CWE-319", "APP-"),
    "appservice-remote-debug": ("CWE-489", "APP-"),
    "managed-identity-privileged-role": ("CWE-269", "ID-"),
    "orphaned-arm-role-assignment": ("CWE-672", "ID-"),
    "orphaned-app-role-assignment": ("CWE-672", "ID-"),
    "backup-soft-delete-off": ("CWE-693", "GOV-"),
    "dynamic-group-steerable": ("CWE-269", "ID-"),
    "dynamic-group-holds-role": ("CWE-269", "ID-"),
    "ca-policy-report-only": ("CWE-693", "CA-"),
    "ca-exclusion-dynamic-group": ("CWE-693", "CA-"),
    "ca-policy-has-exclusions": ("CWE-693", "CA-"),
    "ca-legacy-auth-not-blocked": ("CWE-284", "CA-"),
    "federated-identity-credential": ("CWE-345", "APP-"),
    "app-preauthorization-chain": ("CWE-269", "APP-"),
    "app-redirect-uri-weak": ("CWE-601", "APP-"),
    "app-secret-expired": ("CWE-324", "APP-"),
    "app-audience-collision": ("CWE-287", "APP-"),
    "write-consent-grant": ("CWE-441", "APP-"),
    "high-priv-app-owned-by-human": ("CWE-269", "APP-"),
    "shared-device-key": ("CWE-287", "ID-"),
    "subscription-unexamined": ("CWE-1059", "SCOPE-"),
    "azurehound-unreadable": ("CWE-1059", "TOOL-"),
    "azurehound-nodes-skipped": ("CWE-1059", "TOOL-"),
    "grant-scope-names-unresolved": ("CWE-1059", "TOOL-"),
    "controlplane-key-readable": ("CWE-522", "SEC-"),
    "password-expiry-disabled": ("CWE-287", "AUTH-"),
    "password-expiry-enforced": ("CWE-287", "AUTH-"),
    "tap-enabled-scope": ("CWE-287", "AUTH-"),
    "principal-can-grant-access": ("CWE-269", "ID-"),
    "privileged-principal-type-unknown": ("CWE-1059", "ID-"),
    "peer-overlap-unassessed": ("CWE-1059", "ID-"),
    "peer-principal-type-unaligned": ("CWE-1059", "ID-"),
    "standing-ga-template-unresolved": ("CWE-1059", "ID-"),
    "home-realm-unassessed": ("CWE-1059", "CA-"),
    "foreign-publishers-unassessed": ("CWE-1059", "CA-"),
    "administrative-units-unassessed": ("CWE-1059", "ID-"),
    "compliance-standards-unreadable": ("CWE-1059", "DEF-"),
    "dine-identity-assignments-unreadable": ("CWE-1059", "GOV-"),
    "kv-certificates-unreadable": ("CWE-1059", "KV-"),
    "nsg-rule-source-unknown": ("CWE-1059", "NW-"),
    "keyvault-firewall-rule-unknown": ("CWE-1059", "KV-"),
    "storage-firewall-rule-unknown": ("CWE-1059", "ST-"),
    "lighthouse-tenant-unknown": ("CWE-1059", "ID-"),
    "lighthouse-assignment-tenant-unknown": ("CWE-1059", "ID-"),
    "federated-identity-tenant-unknown": ("CWE-1059", "ID-"),
    "enterprise-app-owner-unknown": ("CWE-1059", "ID-"),
    "app-owner-tenant-unknown": ("CWE-1059", "ID-"),
    "cross-tenant-delegation-unknown": ("CWE-1059", "ID-"),
    "peer-tenant-home-unknown": ("CWE-1059", "ID-"),
    "policy-assignments-unreadable": ("CWE-1059", "GOV-"),
    "policy-definitions-unreadable": ("CWE-1059", "GOV-"),
    "policy-donotenforce-unreadable": ("CWE-1059", "GOV-"),
    "policy-disabled-definitions-unreadable": ("CWE-1059", "GOV-"),
    "policy-audit-definitions-unreadable": ("CWE-1059", "GOV-"),
    "tenant-root-assignments-unreadable": ("CWE-1059", "ID-"),
    "storage-blobservices-unreadable": ("CWE-1059", "ST-"),
    "vm-extensions-unreadable": ("CWE-1059", "VM-"),
    "vm-disks-unreadable": ("CWE-1059", "VM-"),
    "vm-jit-pricing-unreadable": ("CWE-1059", "VM-"),
    "vm-snapshots-unreadable": ("CWE-1059", "VM-"),
}


PREFIX_RULES = (
    ("keyvault", "KV-"), ("storage", "ST-"), ("sql", "SQL-"), ("aks", "AKS-"),
    ("ca-", "CA-"), ("named-location", "CA-"), ("security-defaults", "GOV-"),
    ("breakglass", "GOV-"), ("cba", "AUTH-"), ("auth-method", "AUTH-"), ("per-user-mfa", "AUTH-"),
    ("x509", "AUTH-"), ("mfa-registration", "AUTH-"), ("licences", "GOV-"),
    ("federation", "FED-"), ("domain", "FED-"), ("linked-ident", "AUTH-"),
    ("audit-signal", "LOG-"), ("cross-tenant", "EXT-"), ("governance", "GOV-"),
    ("pim", "GOV-"), ("group-settings", "GOV-"), ("organization", "GOV-"),
    ("saml", "APP-"), ("appgw-", "NW-"), ("appservice", "APP-"), ("app-policy", "APP-"), ("app-published", "APP-"),
    ("app-", "APP-"), ("sp-", "APP-"), ("deleted-app", "APP-"),
    ("consent", "APP-"), ("privileged-sp", "APP-"), ("agent-ident", "ID-"),
    ("device", "ID-"), ("dynamic-group", "ID-"), ("group", "ID-"), ("scoped-role", "ID-"),
    ("guest", "ID-"), ("synced", "ID-"), ("password-policy", "ID-"), ("dormant", "ID-"),
    ("immutableid", "ID-"), ("immutable-id", "ID-"), ("legacy-graph", "ID-"), ("custom-roles", "GOV-"),
    ("custom-role", "GOV-"), ("rbac", "ID-"), ("arm-orphans", "ID-"), ("orphans", "ID-"),
    ("managed-identities", "ID-"), ("automation", "AUTO-"), ("webapp", "APP-"), ("appsetting", "APP-"),
    ("appservice", "APP-"), ("webacl", "APP-"), ("basic-auth", "APP-"), ("webhooks", "AUTO-"),
    ("private-endpoints", "NW-"), ("private-dns", "NW-"), ("network-topology", "NW-"),
    ("nsg", "NW-"), ("subnet", "NW-"), ("waf", "NW-"), ("flowlogs", "NW-"), ("public-ips", "NW-"),
    ("firewall", "NW-"), ("vnet", "NW-"), ("loganalytics", "LOG-"), ("sentinel", "LOG-"),
    ("diagnostics", "LOG-"), ("activity-alerts", "LOG-"), ("defender", "GOV-"),
    ("policy", "GOV-"), ("locks", "GOV-"), ("deny-assignments", "GOV-"), ("management-groups", "GOV-"),
    ("backup", "BCK-"), ("storage-lifecycle", "ST-"), ("template-specs", "GOV-"),
    ("deployments", "SEC-"), ("owners", "ID-"), ("lighthouse", "ID-"), ("classic", "ID-"),
    ("entra-ds", "DS-"), ("paas", "PAAS-"), ("datapane", "SCOPE-"), ("dataplane", "SCOPE-"),
    ("entra-ca", "CA-"), ("stale-privileged", "ID-"), ("scim", "APP-"), ("deleted-users", "ID-"),
    ("kv-legacy", "KV-"), ("abac", "ID-"), ("disk", "ST-"), ("acr", "ACR-"),
    ("flexible-server", "DB-"), ("arc", "ARC-"), ("data-platform", "DATA-"), ("law-", "LOG-"),
    ("escalation-role", "ID-"), ("graph-permissions", "APP-"), ("uami", "ID-"), ("identity-protection", "ID-"),
    ("authenticator", "AUTH-"), ("external-identity", "EXT-"), ("mg-assignments", "ID-"),
    ("vm-posture", "VM-"), ("net-path", "NW-"), ("data-services", "DATA-"), ("storage-keys", "ST-"),
    ("hybrid-sync", "HYB-"), ("mfa-baseline", "AUTH-"), ("mfa-", "AUTH-"), ("ca-inventory", "CA-"), ("ca-state", "CA-"),
    ("ca-guest", "CA-"), ("ca-persistent", "CA-"), ("ca-mcas", "CA-"), ("auth-methods", "AUTH-"), ("email-otp", "AUTH-"),
    ("sms-voice", "AUTH-"), ("fido2-", "AUTH-"), ("external-collab", "ID-"), ("b2b-", "ID-"), ("stale-invites", "ID-"),
    ("guest-invite", "ID-"), ("delegated-", "APP-"), ("domain-", "GOV-"), ("policy-coverage", "GOV-"), ("policy-", "GOV-"),
    ("activity-log", "LOG-"), ("no-log-profile", "LOG-"), ("kv-object", "KV-"), ("keyvault-softdelete", "KV-"),
    ("keyvault-purge", "KV-"), ("appgw-", "NW-"), ("app-publisher", "APP-"), ("app-publisher-unverified", "APP-"),
    ("saml-", "APP-"), ("admin-unit", "ID-"), ("app-policy", "APP-"), ("app-management", "APP-"),
    ("mgmt-hierarchy", "ID-"), ("management-group-root", "ID-"), ("tenant-root", "ID-"),
    ("diag-content", "LOG-"), ("diag-", "LOG-"), ("storage-cmk", "ST-"), ("sql-outbound", "SQL-"),
    ("route-default", "NW-"), ("net-routes", "NW-"), ("appservice-public", "APP-"), ("appservice-vnet", "APP-"),
    ("aks-no-oidc", "AKS-"), ("aks-workload", "AKS-"), ("aks-policy", "AKS-"), ("aks-api-public", "AKS-"), ("aks-wi", "AKS-"), ("rbac-", "ID-"), ("access-review", "GOV-"), ("risky-", "ID-"), ("token-lifetime", "AUTH-"),
    ("privileged-role", "ID-"), ("privileged-builtin", "ID-"), ("alert-content", "LOG-"), ("alert-coverage", "LOG-"),
    ("ca-scope", "CA-"), ("ca-app-excluded", "CA-"), ("ca-role-", "CA-"), ("ca-platform-", "CA-"), ("ca-device-state", "CA-"), ("ca-location-", "CA-"),
    ("implicit-", "APP-"), ("api-scope", "APP-"), ("redirect-uri", "APP-"), ("policy-scope", "GOV-"), ("policy-notscopes", "GOV-"),
    ("credential-near-expiry", "ID-"), ("datacollection", "LOG-"),
    ("sp-credential", "ID-"), ("guest-dormant", "ID-"), ("guest-never-signed", "ID-"), ("deleted-sp", "ID-"),
    ("apps", "APP-"), ("enterprise-apps", "APP-"), ("access-package", "GOV-"), ("deleted-service-principal", "ID-"),
    ("uami-fic-arm", "ID-"), ("waf-attachment", "NW-"), ("appgw-no-waf", "NW-"), ("appgw-waf", "NW-"), ("pim-azure", "ID-"), ("azure-pim-eligible", "ID-"),
    ("device-", "ID-"), ("no-managed-devices", "ID-"), ("open-security-alert", "DEF-"), ("sp-creation", "ID-"), ("security-alert", "DEF-"),
    ("guests-can-self", "ID-"), ("guest-data-removal", "ID-"), ("b2x-", "EXT-"), ("admin-consent-", "APP-"),
    ("sp-credential-expiring", "ID-"), ("password-based-sso", "APP-"), ("wsfed-", "APP-"), ("sso-mode", "APP-"), ("guest-member-of-role", "ID-"),
    ("managed-devices", "ID-"), ("external-id", "EXT-"),
    ("deleted-group", "ID-"), ("standing-global", "ID-"), ("no-standing-global", "ID-"), ("kv-object-", "KV-"), ("kv-key-", "KV-"), ("kv-secrets", "KV-"), ("sql-mi-", "SQL-"), ("storage-files", "ST-"),
    ("pim-group", "GOV-"), ("pim-alert", "GOV-"), ("review-", "GOV-"), ("approles", "APP-"), ("legacy-auth", "AUTH-"), ("no-global-administrator", "ID-"),
    ("ca-no-breakglass", "CA-"), ("ca-exclusion-sprawl", "CA-"), ("delegated-high-risk", "APP-"), ("workload-app-role", "APP-"), ("no-workload-app-roles", "APP-"),
    ("entra-log-export", "LOG-"), ("entra-no-log-export", "LOG-"), ("nsg-low-priority", "NW-"), ("nsg-defaults", "NW-"), ("storage-no-immutability", "ST-"),
    ("storage-immutability", "ST-"), ("storage-nsp", "NW-"), ("nsp-not-covering", "NW-"), ("sql-db-audit", "SQL-"), ("certificate-", "APP-"),
    ("appinsights-", "LOG-"), ("adf-linked-service", "DATA-"), ("dcr-", "LOG-"), ("security-setting", "DEF-"), ("datafactory", "DATA-"),
    ("policy-managed-identity", "GOV-"), ("role-assignment-orphaned", "ID-"), ("vault-scoped-role", "KV-"), ("storage-queue-table", "ST-"),
    ("aks-cluster-admin", "AKS-"), ("aks-local-admin", "AKS-"), ("containerapp-", "APP-"), ("db-ssl", "DB-"), ("db-public-network", "DB-"),
    ("db-legacy-tls", "DB-"), ("resourcegroup-unlocked", "GOV-"), ("single-server-db", "DB-"), ("orphaned-scopes", "ID-"),
    ("gdap-", "ID-"), ("no-gdap", "ID-"), ("xtenant-", "ID-"), ("tou-", "GOV-"), ("weak-method", "ID-"), ("tap-long", "ID-"),
    ("idle-timeout", "ID-"), ("no-idle-timeout", "ID-"), ("consent-policy", "APP-"), ("no-consent-grant", "APP-"),
    ("per-user-mfa", "ID-"), ("license-assignment", "GOV-"), ("csa-", "ID-"), ("access-review", "GOV-"), ("no-azure-access-review", "GOV-"),
    ("hsm-", "KV-"), ("apim-", "APP-"), ("firewall-", "NW-"), ("frontdoor-", "NW-"), ("no-frontdoor", "NW-"),
    ("appservice-http2", "APP-"), ("appservice-legacy-tls", "APP-"), ("appservice-ftps", "APP-"), ("appservice-cors", "APP-"), ("appservice-remote-debug", "APP-"),
    ("defender-extension", "DEF-"), ("security-automation", "DEF-"), ("no-security-automation", "DEF-"),
    ("aks-azure-rbac", "AKS-"), ("aks-local-accounts", "AKS-"), ("aks-defender", "AKS-"), ("aks-api-public", "AKS-"),
    ("loganalytics-short", "LOG-"), ("loganalytics-daily-cap", "LOG-"), ("loganalytics-basic", "LOG-"),
    ("publicip-", "NW-"), ("no-private-endpoint", "NW-"), ("private-endpoint-gap", "NW-"), ("managed-hsm", "KV-"),
    ("account-", "ID-"), ("administrative-unit", "ID-"), ("alert-disabled", "LOG-"), ("catalog-count", "GOV-"), ("check-error", "TOOL-"),
    ("db-", "DB-"), ("deleted-user-holds-role", "ID-"), ("deny-assignment", "GOV-"), ("diagnostic-setting", "LOG-"),
    ("directory-sync-account", "ID-"), ("disabled-account-holds-role", "ID-"), ("federated-", "ID-"), ("flowlog-", "LOG-"),
    ("foreign-or-unknown-principal", "ID-"), ("home-realm-discovery", "ID-"), ("inventory-unavailable", "TOOL-"), ("jit-not-enabled", "DEF-"),
    ("legacy-aad-graph-grant", "APP-"), ("licence-inventory", "GOV-"), ("lock-level", "GOV-"), ("messaging-", "DATA-"),
    ("msol-powershell-allowed", "ID-"), ("network-component", "NW-"), ("no-azurehound-dataset", "TOOL-"), ("no-casb-session-control", "CA-"),
    ("no-custom-attributes", "ID-"), ("no-ddos-plan", "NW-"), ("no-directory-audit-events", "LOG-"), ("no-p2-licence", "GOV-"),
    ("no-persistent-browser-control", "CA-"), ("no-phishing-resistant", "ID-"), ("no-registration-campaign", "ID-"), ("no-sync-account", "ID-"),
    ("no-token-protection", "CA-"), ("no-workload-identity-ca", "CA-"), ("orphan-scope-check-truncated", "TOOL-"), ("p2-licensed", "GOV-"),
    ("partner-trust-accepted", "ID-"), ("principal-holds-write-role", "ID-"), ("privileged-audit-event", "LOG-"), ("public-ip-", "NW-"),
    ("queue-table-not-indexed", "ST-"), ("recovery-services-vault", "BCK-"), ("redis-", "DATA-"), ("risk-detection", "ID-"),
    ("role-can-", "ID-"), ("role-permanent-no-eligible-path", "ID-"), ("self-service-signup-enabled", "ID-"), ("service-principal-holds-role", "ID-"),
    ("session-", "CA-"), ("signin-activity-unreadable", "ID-"), ("slot-", "APP-"), ("snapshot-public-export", "ST-"),
    ("social-idp-configured", "ID-"), ("standing-ga-unreadable", "ID-"), ("strong-method", "ID-"), ("sync-", "ID-"),
    ("template-spec", "GOV-"), ("temporary-access-pass-enabled", "ID-"), ("unexpected-principal-type", "ID-"), ("users-can-", "ID-"),
    ("vm-", "VM-"),
    ("federated-identity-unknown", "ID-"), ("policy-identity-holds-owner", "GOV-"), ("deployment-parameter-secret", "GOV-"),
    ("deployment-listkeys", "GOV-"), ("role-assignable-group-owner", "ID-"), ("access-package-no-expiry", "GOV-"),
    ("access-package-no-justification", "GOV-"), ("access-package-separation", "GOV-"), ("access-package-no-sod", "GOV-"),
    ("firewall-fqdn", "NW-"), ("storage-no-container-immutability", "ST-"), ("storage-immutability-unlocked", "ST-"),
    ("storage-immutability-short", "ST-"), ("seamless-sso", "ID-"), ("directory-sync-enabled", "ID-"), ("no-directory-sync", "ID-"),
    ("writeback-", "ID-"), ("pim-no-justification", "ID-"), ("pim-no-ticketing", "ID-"), ("pim-long-activation", "ID-"),
    ("pim-activation-rule", "ID-"), ("domain-federated", "ID-"), ("domain-managed", "ID-"), ("federation-cert", "ID-"),
    ("federation-certs-unreadable", "ID-"), ("guest-no-sponsor", "ID-"), ("guest-sponsorship-gap", "ID-"),
    ("redis-no-entra-auth", "DATA-"), ("redis-no-firewall-rule", "DATA-"), ("messaging-sas", "DATA-"),
    ("nsg-two-layer", "NW-"), ("nsg-nic-only", "NW-"), ("nsg-subnet-only", "NW-"), ("policy-parameter-weak", "GOV-"),
    ("encryption-scope", "ST-"), ("no-encryption-scope", "ST-"), ("aks-no-azure-policy", "AKS-"), ("aks-workload-identity-off", "AKS-"),
    ("apim-named-value", "APP-"), ("apim-developer-portal", "APP-"), ("automation-credential-asset", "ID-"),
    ("automation-certificate-asset", "ID-"), ("logicapp-", "APP-"), ("subscription-at-tenant-root", "ID-"),
    ("diag-storage-", "LOG-"), ("diag-no-storage-target", "LOG-"), ("nsg-allow-shadowed", "NW-"),
    ("storage-firewall-any", "ST-"), ("standing-privileged-role", "ID-"), ("privileged-role-unheld", "ID-"),
    ("access-review-guest-scoped", "GOV-"), ("access-review-no-guest-scope", "GOV-"), ("app-instance-lock", "APP-"),
    ("apim-api-", "APP-"), ("runbook-inline-credential", "ID-"), ("runbook-content-unreadable", "ID-"),
    ("tenant-partner", "ID-"), ("app-owned-by-foreign-tenant", "APP-"), ("no-foreign-app-publishers", "APP-"), ("tenant-identity-unverified", "ID-"),
    ("cross-tenant-guest-privileged-role", "ID-"), ("cross-tenant-trust-bypass", "CA-"), ("cross-tenant-sync-identity-source", "ID-"),
    ("cross-tenant-outbound-admin", "ID-"), ("no-cross-tenant-escalation-edge", "ID-"), ("cross-tenant-scope-limit", "ID-"),
    ("guest-personal-identity", "ID-"), ("guest-consumer-identity-share", "ID-"), ("guest-domain", "ID-"),
    ("cross-tenant-control-plane-access", "ID-"), ("cross-tenant-azure-rbac", "ID-"),
    ("identity-privileged-in-both-tenants", "ID-"), ("peer-guest-holds-role", "ID-"), ("peer-tenant-", "ID-"),
    ("upn-privileged-in-both", "ID-"), ("dual-tenant-privilege", "ID-"), ("guest-to-peer-role", "ID-"),
    ("guest-invite-modes", "ID-"), ("ca-unconfirmed-empty", "CA-"), ("licence-unreadable", "GOV-"),
    ("seamless-sso-key-rotation-unverifiable", "ID-"), ("seamless-sso-not-applicable", "ID-"), ("seamless-sso-agent-groups", "ID-"),
    ("pta-not-applicable", "ID-"), ("pta-agent-group", "ID-"), ("token-lifetime-policy", "AUTH-"),
    ("ca-roles-unconstrained", "CA-"),
    ("no-signin-frequency", "CA-"), ("signin-frequency", "CA-"), ("global-administrator-count", "ID-"),
    ("single-global-administrator", "ID-"), ("multitenant-application", "APP-"), ("no-multitenant-apps", "APP-"),
    ("grant-without-manifest-scope", "APP-"), ("grant-not-in-manifest", "APP-"), ("grant-declared", "APP-"), ("advisor-", "GOV-"),
    ("private-endpoint-no-dns-zone", "NW-"), ("aks-api-public", "AKS-"), ("aks-no-network-policy", "AKS-"),
    ("vnet-no-ddos-plan", "NW-"), ("no-ddos-plan", "NW-"),
    ("no-user-risk-policy", "ID-"), ("no-signin-risk-policy", "ID-"), ("user-risk-policy", "ID-"), ("signin-risk-policy", "ID-"),
    ("breakglass-not-excluded", "ID-"), ("breakglass-excluded", "ID-"), ("breakglass-synced", "ID-"), ("breakglass-licensed", "ID-"),
    ("breakglass-no-strong-method", "ID-"), ("breakglass-no-holder", "ID-"), ("breakglass-alert-not-visible", "ID-"),
    ("resource-without-owner-tag", "GOV-"), ("tag-coverage", "GOV-"),
    ("objectid-privileged-in-both-tenants", "ID-"),
    ("sspr-", "ID-"), ("password-protection", "ID-"), ("password-no-custom", "ID-"), ("lifecycle-workflow", "GOV-"), ("no-leaver", "GOV-"),
    ("no-lifecycle", "GOV-"), ("cross-tenant-sync", "ID-"), ("b2b-direct-connect", "ID-"), ("tenant-restrictions", "ID-"),
    ("app-group-claims", "APP-"), ("app-optional-claim", "APP-"), ("token-encryption", "APP-"), ("no-token-encryption", "APP-"),
    ("pta-agent", "ID-"), ("no-pta-agents", "ID-"), ("guest-invites", "ID-"), ("users-can-register-apps", "ID-"),
    ("appconfig-", "APP-"), ("search-", "DATA-"), ("appgw-waf-policy", "NW-"), ("no-appgw-waf-policy", "NW-"),
    ("kv-cert-", "KV-"), ("defender-plan-absent", "DEF-"), ("defender-plan-free", "DEF-"), ("security-contact", "DEF-"),
    ("no-security-contact", "DEF-"), ("udr-", "NW-"), ("sql-firewall-", "SQL-"),
    ("rsv-", "BCK-"), ("secure-score", "DEF-"), ("defender-secure", "DEF-"), ("no-regulatory-standard", "DEF-"), ("vm-encryption-at-host", "VM-"), ("vm-host", "VM-"),
    ("cosmos-", "DATA-"), ("backup-vault", "BCK-"), ("aks-kv", "AKS-"), ("aks-no-kubelet", "AKS-"),
    ("network-inventory", "NW-"), ("kv-pe", "KV-"), ("aks-depth", "AKS-"), ("sentinel-depth", "LOG-"), ("policy-depth", "GOV-"), ("backup-items", "BCK-"),
)


def _infer(check):
    low = check.lower()
    best = None
    for position, (token, prefix) in enumerate(PREFIX_RULES):
        if token and token in low:
            score = (len(token), -position)
            if best is None or score > best[0]:
                best = (score, prefix)
    return best[1] if best else "MISC-"


FINDING_KEYS = {}


UNATTRIBUTED = []

SENTINEL_SUBJECTS = ("tenant", "all", "?", "every subscription")


def _owner(subscription, subject, scope):
    """The subscription a finding belongs to: the caller's value, else the one in its subject or scope."""
    if subscription:
        return str(subscription)
    for value in (subject, scope):
        found = re.search(r"/subscriptions/([0-9a-fA-F-]{36})", str(value or ""))
        if found:
            return found.group(1).lower()
    return ""


def add(sev, check, subject, ev, why, subscription=None, scope="tenant", likelihood=None, impact=None, repro=""):
    sub = _owner(subscription, subject, scope)
    if not sub:
        sub = "tenant"
        if str(CURRENT["check"]).startswith("sub-") and str(subject) not in SENTINEL_SUBJECTS:
            UNATTRIBUTED.append((str(CURRENT["check"]), str(check), str(subject)[:60]))
    key = "|".join([str(CURRENT["check"]), str(check), str(subject), sub, str(scope)])
    if key in FINDING_KEYS:
        prior = FINDING_KEYS[key]
        prior["evidence"] = (prior["evidence"] + "; " + str(ev))[:300]
        if SEV[sev] < SEV[prior["severity"]]:
            prior["severity"] = sev
            prior["likelihood"] = likelihood or ("high" if sev in ("critical", "high") else "medium" if sev == "medium" else "low")
            prior["impact"] = impact or ("low" if sev == "info" else sev)
            prior["score"] = LIKELIHOOD.get(prior["likelihood"], 2) * IMPACT.get(prior["impact"], 2)
        return
    lk = likelihood or ("high" if sev in ("critical", "high") else "medium" if sev == "medium" else "low")
    im = impact or ("low" if sev == "info" else sev)
    meta = FRAMEWORK.get(check)
    cwe, reg = meta if meta else ("CWE-693", _infer(check))
    record = {
            "severity": sev,
            "check": check,
            "subject": subject,
            "subscription": sub,
            "scope": scope,
            "evidence": ev,
            "why": why,
            "likelihood": lk,
            "impact": im,
            "score": LIKELIHOOD.get(lk, 2) * IMPACT.get(im, 2),
            "cwe": cwe,
            "register": reg,
            "source": str(CURRENT["check"]),
            "repro": repro or LAST_QUERY.get(CURRENT["check"]) or OFFLINE_REPRO.get(CURRENT["check"]) or ("offline: derived from " + os.path.basename(str(CFG.get("azurehound", "azurehound.json")))),
    }
    FINDING_KEYS[key] = record
    FINDINGS.append(record)


CHAIN_SEEN = set()
CHAIN_CAP = 40


def chain(name, path, sev, why):
    """Record one attack chain, once per name and path.

    The owning check is stored so the report can tie the chain to the findings that
    justify it. A loop that walks many objects must not repeat one chain, and one
    name must not grow without bound.
    """
    if sev not in SEV:
        raise ValueError("unknown chain severity: " + str(sev))
    key = str(name) + "|" + str(path)
    if key in CHAIN_SEEN:
        return
    if sum(1 for c in CHAINS if c["chain"] == name) >= CHAIN_CAP:
        capped(CURRENT["check"], CHAIN_CAP, "chains for " + str(name))
        return
    CHAIN_SEEN.add(key)
    CHAINS.append({"chain": name, "path": path, "severity": sev, "why": why,
                   "source": CURRENT["check"]})


class DatasetUnavailable(Exception):
    """Raised when a check needs identity objects that were never loaded.

    Absence of the export is a state, not an empty dataset. A check that hits this
    cannot assert a negative, and the runner records it as absent instead.
    """


class Index:
    def __init__(self, nodes, state="ok", detail=""):
        self._by_kind = defaultdict(list)
        self._names = {}
        self._kinds = Counter()
        self.state = state
        self.detail = detail
        self.skipped = 0
        for n in nodes:
            if not isinstance(n, dict):
                self.skipped += 1
                continue
            k = str(n.get("kind") or "").lower()
            if not k:
                continue
            self._kinds[k] += 1
            self._by_kind[k].append(n)
            if n.get("id"):
                self._names[n["id"]] = self.name(n)
        self.lookups = 0
        self.exhausted = False
        self.failures = 0
        self.absent = set()

    def guard(self):
        if self.state != "ok":
            raise DatasetUnavailable(self.detail or "identity dataset not available")

    @property
    def by_kind(self):
        self.guard()
        return self._by_kind

    @property
    def names(self):
        self.guard()
        return self._names

    @property
    def kinds(self):
        self.guard()
        return self._kinds

    def summary(self):
        """(skipped nodes, kind histogram) without the availability guard."""
        return self.skipped, dict(self._kinds)

    @staticmethod
    def props(n):
        if not isinstance(n, dict):
            return {}
        found = n.get("properties") or n.get("props")
        return found if isinstance(found, dict) else {}

    def name(self, n):
        p = self.props(n)
        return p.get("displayName") or p.get("userPrincipalName") or n.get("id") or "?"

    def pick(self, *kinds):
        out = []
        for k in kinds:
            out.extend(self.by_kind.get(k.lower(), []))
        return out

    def users(self):
        return self.pick("azuser")

    def groups(self):
        return self.pick("azgroup")

    def sps(self):
        return self.pick("azserviceprincipal")

    def apps(self):
        return self.pick("azapp")

    def resolve_reason(self, oid):
        """(display name, reason) where reason is known, absent, exhausted or error."""
        label = self.resolve(oid)
        if label is not None:
            return label, "known"
        if str(oid or "") in self.absent:
            return None, "absent"
        if self.exhausted:
            return None, "exhausted"
        return None, "error"

    def reset_budget(self):
        self.lookups = 0
        self.exhausted = False
        self.failures = 0
        self.absent.clear()

    def resolve(self, oid, max_lookups=200):
        self.guard()
        if not oid:
            return None
        if oid in self._names:
            return self._names[oid]
        if oid in self.absent:
            return None
        if self.exhausted:
            return None
        if self.lookups >= max_lookups:
            self.exhausted = True
            if CURRENT["check"]:
                EXHAUSTED[CURRENT["check"]] = True
            return None
        self.lookups += 1
        keep = CURRENT["check"]
        with audit_scope(suppress=True):
            page = graph("directoryObjects/" + oid + "?$select=id,displayName")
            kind = az_kind()
        if page is None and kind == "absent":
            self.absent.add(oid)
            return None
        if page is None:
            self.failures += 1
            if self.failures >= 3:
                self.exhausted = True
            if keep:
                EXHAUSTED[keep] = True
                deny(keep)
            return None
        label = str(val(dig(page, "displayName"), ""))
        if not label:
            self._names[oid] = oid
            return oid
        self._names[oid] = label
        return label


def load_ah(path):
    """(nodes, state, detail). A missing or unusable export is a state, never an empty list."""
    if not path:
        return [], "missing", "no --azurehound path given"
    if not os.path.exists(path):
        return [], "missing", str(path) + " does not exist"
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        raw = fh.read()
    if not raw.strip():
        return [], "empty", str(path) + " is empty"
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError:
        nodes = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, list):
                nodes.extend(obj)
            elif isinstance(obj, dict):
                payload = obj.get("data")
                nodes.extend(payload if isinstance(payload, list) else [payload or obj])
        if not nodes:
            return [], "unreadable", str(path) + " is neither JSON nor JSON lines"
        return nodes, "ok", ""
    if isinstance(doc, dict):
        payload = doc.get("data")
        nodes = payload if isinstance(payload, list) else ([payload] if isinstance(payload, dict) else [])
    elif isinstance(doc, list):
        nodes = doc
    else:
        nodes = []
    if not nodes:
        return [], "empty", str(path) + " contains no directory objects"
    return nodes, "ok", ""


REGISTRY = []
REGISTRY_NAMES = set()
PHANTOM = []
DATASET_GAPS = []


TRANSPORT_CALLS = ("graph(", "graph_all(", "arg_rows(", "arg(", "az(", "arm(", "ca_all(", "per_sub(",
                   "scan_guests(", "scan_dynamic(", "_kv_rows(", "_kv_vaults(", "_strengths(", "resolve(",
                   "denied_now(", "mark_failure(", "DATAPLANE_PROBES", "kv_rows(", "_owner_takeover(", "dynamic_groups(")
OFFLINE_CHECKS = set()


SP_FALLBACK = {}


def sp_fallback(app_id):
    if not app_id:
        return None
    if app_id in SP_FALLBACK:
        return SP_FALLBACK[app_id]
    with audit_scope():
        doc = graph("servicePrincipals?$filter=appId eq '" + app_id + "'&$select=appId,isFallbackPublicClient")
    if doc is None:
        return None
    value = None
    for sp in lst(dig(doc, "value")):
        value = tri(dig(sp, "isFallbackPublicClient"))
        break
    SP_FALLBACK[app_id] = value
    return value


def check(name):
    if any(n == name for n, _ in REGISTRY):
        raise RuntimeError("duplicate check name: " + name)

    def deco(fn):
        REGISTRY.append((name, fn))
        REGISTRY_NAMES.add(name)
        try:
            source = inspect.getsource(fn)
        except (OSError, TypeError):
            source = ""
        if source and not any(token in source for token in TRANSPORT_CALLS):
            OFFLINE_CHECKS.add(name)
        return fn

    return deco


def ctx_sub(row):
    scope = row.get("scope") or row.get("sc") or ""
    if "/subscriptions/" in scope:
        return scope.split("/")[2]
    return row.get("subscriptionId") or "tenant"


@check("sub-owners")
def c_owners(ctx):
    subs = ctx["subs"]
    q = filtered_in_python((
        "AuthorizationResources | where type =~ 'microsoft.authorization/roleassignments'"
        " | where tostring(properties.roleDefinitionId) endswith '" + BUILTIN_ROLE_OWNER + "'"
        " | extend t=tostring(properties.principalType), sc=tostring(properties.scope)"
        " | where tostring(sc) startswith '/subscriptions/' or tostring(sc) startswith '/providers/Microsoft.Management/'"
        " | summarize users=countif(t=='User'), groups=countif(t=='Group'), sps=countif(t=='ServicePrincipal') by sc"
    ))
    rows = arg_rows(q, subs, scoped=False)
    if rows is None:
        note("sub-owners", 0, denied=len(subs))
        return
    rows = [r for r in rows if any(s in str(r.get("sc")) for s in subs) or str(r.get("sc")).startswith("/providers/Microsoft.Management/")]
    note("sub-owners", len(rows))
    for r in rows:
        sub = ctx_sub(r)
        sc = r.get("sc") or "?"
        if r.get("groups"):
            add("high", "subscription-owner-group", sub + " " + sc, "groups=" + str(r["groups"]), "group holds Owner; membership is the blast radius", sub, sc)
        if r.get("sps"):
            add("high", "subscription-owner-serviceprincipal", sub + " " + sc, "sps=" + str(r["sps"]), "machine identity holds Owner", sub, sc)
        if (r.get("users") or 0) > 3:
            add("low", "subscription-owner-count", sub + " " + sc, "users=" + str(r["users"]), "more than three human owners", sub, sc)
        if str(sc).startswith("/providers/Microsoft.Management/managementGroups/"):
            add("high", "management-group-owner", sub + " " + sc, "scope=" + sc, "Owner at management-group scope reaches every subscription below", sub, sc)


@check("sub-lighthouse")
def c_lighthouse(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.managedservices/registrationdefinitions' | project name, subscriptionId, properties", ctx["subs"])
    if rows is None:
        note("sub-lighthouse", 0, denied=1)
        return
    note("sub-lighthouse", len(rows))
    for r in rows:
        props = r.get("properties") or {}
        auth = lst(dig(props, "authorizations")) or lst(dig(props, "registrationDefinitionProperties.authorizations"))
        manager = str(val(dig(props, "managedByTenantId"), "")) or str(val(dig(props, "registrationDefinitionProperties.managedByTenantId"), ""))
        s = str(dig(r, "subscriptionId"))
        rel = tenant_rel(manager)
        if rel == "unknown":
            undecided("lighthouse-tenant-unknown", "managedByTenantId=" + (manager or "not returned"), "the home tenant was not read, so a delegation cannot be classified as internal or external")
            continue
        if rel == "home":
            add("info", "lighthouse-same-tenant", dig(r, "name"), "managedByTenantId=" + manager, "the managing tenant is this tenant", s)
            continue
        if not auth:
            add("low", "lighthouse-no-authorization", dig(r, "name"), "managedByTenantId=" + (manager or "unknown") + " authorizations=0", "registration exists but grants no access yet", s)
            continue
        label = tenant_name(manager) if manager and not NO_ENTRA else ""
        add("high", "azure-lighthouse-delegation", dig(r, "name"), "managedByTenantId=" + (manager or "unknown") + (" (" + label + ")" if label else "") + " principals=" + str(len(auth)), "external tenant holds delegated control", s)


@check("sub-classic-admins")
def c_classic(ctx):
    subs = ctx["subs"]
    res = per_sub(subs, "providers/Microsoft.Authorization/classicAdministrators", "2015-06-01", lambda d: d.get("value") or [])
    note("sub-classic-admins", sum(1 for v in res.values() if v is not None), denied=sum(1 for v in res.values() if v is None))
    for s, items in res.items():
        for c in items or []:
            p = c.get("properties") or {}
            role = str(p.get("role") or "").lower()
            if re.sub(r"[^a-z]", "", role) == "coadministrator":
                add("high", "classic-coadministrator", s + " " + str(p.get("emailAddress")), "role=" + str(p.get("role")), "co-admin acts outside RBAC", s)





KV_CACHE = {}


class _Missing:
    def __repr__(self):
        return "missing"

    def __str__(self):
        return ""

    def __bool__(self):
        return False


MISSING = _Missing()
PARSE = defaultdict(lambda: {"resolved": 0, "missing": 0})


def tally(resolved):
    bucket = PARSE[CURRENT["check"]]
    bucket["resolved" if resolved else "missing"] += 1


def dig(obj, path, default=MISSING):
    cur = obj
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def tri(value):
    if value is MISSING or value is None:
        tally(False)
        return None
    if isinstance(value, bool):
        tally(True)
        return value
    text = str(value).strip().lower()
    if not text:
        tally(False)
        return None
    tally(True)
    if text in ("false", "disabled", "no", "off", "0"):
        return False
    if text in ("true", "enabled", "yes", "on", "1"):
        return True
    return None


def allow_deny(value):
    if value is MISSING or value is None:
        tally(False)
        return None
    tally(True)
    text_value = str(value).strip().lower()
    if text_value in ("allow", "true", "enabled"):
        return True
    if text_value in ("deny", "false", "disabled"):
        return False
    return None


def num(value, default=MISSING):
    try:
        result = int(float(value))
    except (TypeError, ValueError):
        tally(False)
        return default
    tally(True)
    return result


def flt(value, default=MISSING):
    try:
        result = float(value)
    except (TypeError, ValueError):
        tally(False)
        return default
    tally(True)
    return result


def project(resource_type, fields, extra=""):
    cols = ", ".join("%s=%s" % (k, p) for k, (p, _) in fields.items())
    return "Resources | where type =~ '" + resource_type + "' | project name, subscriptionId" + (", " + extra if extra else "") + ", " + cols


def parse_row(row, fields):
    out = {}
    for k, (path, coerce) in fields.items():
        if k in row:
            value = row[k]
        elif path in row:
            value = row[path]
        else:
            value = dig(row, path)
        out[k] = coerce(value)
    return out


def apply_rules(row, rules, subject, subscription):
    for key, predicate, sev, check_id, why in rules:
        if predicate(row.get(key)):
            add(sev, check_id, subject, key + "=" + str(row.get(key)), why, subscription)


KV_FIELDS = {
    "publicNet": ("properties.publicNetworkAccess", tri),
    "defaultAction": ("properties.networkAcls.defaultAction", allow_deny),
    "bypass": ("properties.networkAcls.bypass", lambda v: v if v is not MISSING else tally(False) or None),
    "ipRules": ("properties.networkAcls.ipRules", lambda v: len(v) if isinstance(v, list) else tally(False) or None),
    "vnetRules": ("properties.networkAcls.virtualNetworkRules", lambda v: len(v) if isinstance(v, list) else None),
    "ipRulesRaw": ("properties.networkAcls.ipRules", lambda v: v if isinstance(v, list) else tally(False) or []),
    "purge": ("properties.enablePurgeProtection", tri),
    "soft": ("properties.enableSoftDelete", tri),
    "softDays": ("properties.softDeleteRetentionInDays", num),
    "rbac": ("properties.enableRbacAuthorization", tri),
    "policies": ("properties.accessPolicies", lambda v: v if isinstance(v, list) else []),
    "sku": ("properties.sku.name", lambda v: str(v).lower() if v is not MISSING and v is not None else None),
    "pe": ("properties.privateEndpointConnections", lambda v: len(v) if isinstance(v, list) else 0),
}

KV_RULES = (
    ("purge", lambda v: v is False, "high", "keyvault-purge-protection-off", "deleted vault can be purged"),
    ("purge", lambda v: v is None, "low", "keyvault-purge-protection-unknown", "enablePurgeProtection not returned; cannot confirm the state"),
    ("soft", lambda v: v is False, "high", "keyvault-soft-delete-off", "deleted secrets are unrecoverable"),
    ("soft", lambda v: v is None, "low", "keyvault-soft-delete-unknown", "enableSoftDelete not returned; cannot confirm the state"),
    ("rbac", lambda v: v is False, "medium", "keyvault-access-policy-model", "vault uses access policies instead of RBAC; per-principal audit is weaker"),
    ("rbac", lambda v: v is None, "low", "keyvault-rbac-unknown", "enableRbacAuthorization not returned"),
    ("sku", lambda v: v == "premium", "info", "keyvault-premium-sku", "HSM-backed; verify key types and export policy"),
)

def _kv_rows(subs):
    key = str(CFG.get("tenant", "")) + "|" + ",".join(subs)
    if key in KV_CACHE:
        if CURRENT["check"] and not CURRENT.get("suppress"):
            LAST_QUERY[CURRENT["check"]] = "az graph query -q " + repr(_kv_query(subs))
        return KV_CACHE[key]
    q = _kv_query(subs)
    rows = arg_rows(q, subs)
    if rows is not None:
        KV_CACHE[key] = rows
    return rows


def _kv_query(subs):
    return _scoped(project("microsoft.keyvault/vaults", KV_FIELDS, "rg=resourceGroup"), subs)


def _kv_vaults(subs):
    rows = _kv_rows(subs)
    if rows is None:
        return None
    return [(r, parse_row(r, KV_FIELDS)) for r in rows]


@check("sub-keyvault")
def c_keyvault(ctx):
    vaults = _kv_vaults(ctx["subs"])
    if vaults is None:
        note("sub-keyvault", 0, denied=1)
        return
    note("sub-keyvault", len(vaults))
    for raw, v in vaults:
        s = raw.get("subscriptionId")
        name = raw.get("name")
        apply_rules(v, KV_RULES, name, s)
        pe = v["pe"]
        if v["publicNet"] is False:
            add("info", "keyvault-public-access-disabled", name, "publicNetworkAccess=Disabled pe=" + str(pe), "reachable only through private endpoints", s)
        elif v["publicNet"] is None:
            add("low", "keyvault-public-access-unknown", name, "publicNetworkAccess not returned", "public reachability cannot be confirmed", s)
        if v["defaultAction"] is None:
            add("medium", "keyvault-firewall-unknown", name, "networkAcls.defaultAction not returned", "firewall default cannot be confirmed", s)
        elif v["defaultAction"] is True and (v["ipRules"] is None or v["vnetRules"] is None):
            add("low", "keyvault-network-rules-unknown", name, "networkAcls rule arrays not returned", "exposure cannot be confirmed", s)
        elif v["defaultAction"] is True and not v["ipRules"] and not v["vnetRules"]:
            add("medium", "keyvault-open-network", name, "defaultAction=Allow ipRules=0 vnetRules=0 pe=" + str(pe), "reachable from any network", s)
        elif v["defaultAction"] is False and v["bypass"] == "AzureServices":
            add("low", "keyvault-azure-services-bypass", name, "defaultAction=Deny bypass=AzureServices", "trusted-service bypass remains open", s)
        for rule in v["ipRulesRaw"]:
            value = str((rule or {}).get("value") or "")
            if not value:
                add("low", "keyvault-firewall-rule-unknown", name, "ipRule without a value", "one firewall rule cannot be evaluated", s)
            elif any_source(value) or value in ("0.0.0.0", "::"):
                add("high", "keyvault-firewall-any", name, "ipRule=" + value, "firewall admits any address", s)
        days = v["softDays"]
        if days is not MISSING and days is not None and 0 < days < 90:
            add("low", "keyvault-softdelete-short", name, "softDeleteRetentionInDays=" + str(days), "retention shorter than the recommended 90 days", s)
        if v["rbac"] is True and v["policies"]:
            add("low", "keyvault-stale-access-policies", name, "rbac=true but " + str(len(v["policies"])) + " access policies present", "legacy policies remain readable and mislead review", s)
        for p in v["policies"]:
            perms = (p or {}).get("permissions") or {}
            secrets, keys, certs = perms.get("secrets") or [], perms.get("keys") or [], perms.get("certificates") or []
            if len(secrets) >= 6 or len(keys) >= 4 or len(certs) >= 4:
                add("medium", "keyvault-broad-policy", name, "objectId=" + str((p or {}).get("objectId")) + " secrets=" + str(len(secrets)) + " keys=" + str(len(keys)) + " certs=" + str(len(certs)), "vault-wide rights for one principal", s)


@check("sub-keyvault-logs")
def c_keyvault_logs(ctx):
    rows = _kv_rows(ctx["subs"])
    if rows is None:
        note("sub-keyvault-logs", 0, denied=1)
        return
    n = 0
    sample("sub-keyvault-logs", min(len(rows), 30), len(rows), "vaults")
    for r in rows[:30]:
        url = (
            ARM_BASE + "/subscriptions/" + str(r.get("subscriptionId"))
            + "/resourceGroups/" + str(r.get("rg")) + "/providers/Microsoft.KeyVault/vaults/" + str(r.get("name"))
            + "/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview"
        )
        LAST_QUERY[CURRENT["check"]] = "az rest --url " + repr(url)
        doc = az(["rest", "--url", url])
        if doc is None:
            denied_now("sub-keyvault-logs")
            continue
        n += 1
        settings = doc.get("value") or []
        cats = []
        for item in settings:
            for log in ((item.get("properties") or {}).get("logs") or []):
                if log.get("enabled"):
                    cats.append(log.get("category"))
        if "AuditEvent" not in cats:
            add("medium", "keyvault-no-audit-logging", r.get("name"), "diagnosticSettings=" + str(len(settings)) + " categories=" + (",".join([c for c in cats if c]) or "none"), "vault operations are not recorded", r.get("subscriptionId"))
        else:
            add("info", "keyvault-audit-logging", r.get("name"), "categories=" + ",".join([c for c in cats if c]), "audit event logging enabled", r.get("subscriptionId"))
    note("sub-keyvault-logs", n)


@check("sub-storage")
def c_storage(ctx):
    q = (
        "Resources | where type =~ 'microsoft.storage/storageaccounts'"
        " | project name, subscriptionId, publicBlob=tostring(properties.allowBlobPublicAccess),"
        " sharedKey=tostring(properties.allowSharedKeyAccess), tls=tostring(properties.minimumTlsVersion),"
        " crossTenant=tostring(properties.allowCrossTenantReplication), publicNet=tostring(properties.publicNetworkAccess),"
        " netDefault=tostring(properties.networkAcls.defaultAction), netBypass=tostring(properties.networkAcls.bypass), ipRules=properties.networkAcls.ipRules"
    )
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-storage", 0, denied=1)
        return
    note("sub-storage", len(rows))
    for r in rows:
        s = r.get("subscriptionId")
        if r.get("publicBlob") == "true":
            add("high", "storage-public-blob-access", r.get("name"), "allowBlobPublicAccess=true", "anonymous blob read if a container is public", s)
        if r.get("sharedKey") == "true":
            add("medium", "storage-shared-key-enabled", r.get("name"), "allowSharedKeyAccess=true", "account key bypasses identity control", s)
        tls = str(val(dig(r, "tls"), ""))
        if tls and tls not in ("TLS1_2", "TLS1_3"):
            add("medium", "storage-legacy-tls", dig(r, "name"), "minimumTlsVersion=" + tls, "legacy TLS accepted", s)
        elif not tls:
            add("low", "storage-tls-unknown", dig(r, "name"), "minimumTlsVersion not returned", "the platform default applies; confirm the enforced version", s)
        if r.get("crossTenant") == "true":
            add("low", "storage-cross-tenant-replication", r.get("name"), "allowCrossTenantReplication=true", "data can replicate to another tenant", s)
        if r.get("netBypass") == "AzureServices":
            add("low", "storage-azure-services-bypass", r.get("name"), "networkAcls.bypass=AzureServices", "trusted-service bypass remains", s)
        public = str(val(dig(r, "publicNet"), "")).lower()
        action = str(val(dig(r, "netDefault"), "")).lower()
        if public == "" and action == "":
            add("low", "storage-network-unknown", dig(r, "name"), "publicNetworkAccess and defaultAction not returned", "public reachability cannot be confirmed", s)
        elif public in ("", "enabled") and action in ("", "allow"):
            shown = "publicNetworkAccess=" + (public or "not returned") + " defaultAction=" + (action or "not returned")
            add("medium", "storage-network-open", dig(r, "name"), shown, "nothing in the response restricts the data plane to a private network", s)
        elif public == "" or action == "":
            add("low", "storage-network-partial", dig(r, "name"), "publicNetworkAccess=" + (public or "not returned") + " defaultAction=" + (action or "not returned"), "one part of the network control is unknown", s)
        for rule in lst(dig(r, "ipRules")):
            value = str(val(dig(rule, "value"), ""))
            if not value:
                add("low", "storage-firewall-rule-unknown", dig(r, "name"), "ipRule without a value", "one firewall rule cannot be evaluated", s)
            elif any_source(value) or value in ("0.0.0.0", "::"):
                add("high", "storage-firewall-any", dig(r, "name"), "ipRule=" + value, "the account firewall admits any address", s)


@check("sub-storage-containers")
def c_containers(ctx):
    q = "Resources | where type =~ 'microsoft.storage/storageaccounts/blobservices/containers' | project name, subscriptionId, publicAccess=tostring(properties.publicAccess)"
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-storage-containers", 0, denied=1)
        return
    parents = unread_list(arg_rows("Resources | where type =~ 'microsoft.storage/storageaccounts' | project name, subscriptionId", ctx["subs"]),
                          "storage account inventory", "storage-parents-unreadable")
    if parents and not rows:
        note("sub-storage-containers", 0)
        add("info", "storage-containers-not-indexed", "all", "storage accounts=" + str(len(parents)) + " container rows=0", "child resource type not returned; container public access is not assessed")
        return
    note("sub-storage-containers", len(rows))
    for r in rows:
        pa = r.get("publicAccess") or ""
        if pa in ("Blob", "Container"):
            add("high", "storage-anonymous-container", r.get("name"), "publicAccess=" + pa, "anonymous read of container contents", r.get("subscriptionId"))


@check("sub-sql")
def c_sql(ctx):
    q = (
        "Resources | where type =~ 'microsoft.sql/servers'"
        " | project name, subscriptionId, rg=resourceGroup, publicNet=tostring(properties.publicNetworkAccess),"
        " tls=tostring(properties.minimalTlsVersion)"
    )
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-sql", 0, denied=1)
        return
    note("sub-sql", len(rows))
    admin_rows = unread(arg_rows("Resources | where type =~ 'microsoft.sql/servers/administrators' | project id=tolower(substring(id, 0, indexof(tolower(id), '/administrators'))), login=tostring(properties.login)", ctx["subs"]),
                        "SQL server administrators", "sql-administrators-unreadable")
    admins = None if admin_rows is None else {str(a.get("id")): a for a in admin_rows}
    for r in rows:
        s = r.get("subscriptionId")
        if r.get("publicNet") == "Enabled":
            add("medium", "sql-public-endpoint", r.get("name"), "publicNetworkAccess=Enabled", "server reachable from the internet", s)
        tls = str(r.get("tls") or "").strip()
        if tls in ("1.0", "1.1"):
            add("medium", "sql-legacy-tls", r.get("name"), "minimalTlsVersion=" + tls, "legacy TLS accepted", s)
        elif not tls:
            add("low", "sql-tls-unknown", r.get("name"), "minimalTlsVersion not returned", "server default applies; confirm the enforced version", s)
        server_id = ("/subscriptions/" + str(s) + "/resourcegroups/" + str(r.get("rg")) + "/providers/microsoft.sql/servers/" + str(r.get("name"))).lower()
        if admins is not None and server_id not in admins:
            add("medium", "sql-no-entra-admin", r.get("name"), "no microsoft.sql/servers/administrators child resource", "no working administrative path via Entra", s)
        base = ARM_BASE + "/subscriptions/" + str(s) + "/resourceGroups/" + str(r.get("rg")) + "/providers/Microsoft.Sql/servers/" + str(r.get("name"))
        LAST_QUERY[CURRENT["check"]] = "az rest --url " + repr(base + "/auditingSettings/default?api-version=2021-11-01")
        aud = az(["rest", "--url", base + "/auditingSettings/default?api-version=2021-11-01"])
        if aud is None:
            deny("sub-sql")
        elif (aud.get("properties") or {}).get("state") != "Enabled":
            add("medium", "sql-auditing-disabled", r.get("name"), "auditingSettings.state != Enabled", "no query audit trail", s)
        tde = az(["rest", "--url", base + "/transparentDataEncryption/current?api-version=2021-11-01"])
        if tde is None:
            deny("sub-sql")
        elif (tde.get("properties") or {}).get("state") != "Enabled":
            add("high", "sql-tde-disabled", r.get("name"), "transparentDataEncryption.state != Enabled", "data at rest unprotected", s)


@check("sub-sql-firewall")
def c_sql_fw(ctx):
    q = "Resources | where type =~ 'microsoft.sql/servers' | project name, subscriptionId, rg=resourceGroup"
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-sql-firewall", 0, denied=1)
        return
    note("sub-sql-firewall", len(rows))
    for r in rows:
        base = ARM_BASE + "/subscriptions/" + str(r.get("subscriptionId")) + "/resourceGroups/" + str(r.get("rg")) + "/providers/Microsoft.Sql/servers/" + str(r.get("name"))
        fw = az(["rest", "--url", base + "/firewallRules?api-version=2021-11-01"])
        if fw is None:
            deny("sub-sql-firewall")
            continue
        for rule in fw.get("value") or []:
            p = rule.get("properties") or {}
            start, end = str(p.get("startIpAddress")), str(p.get("endIpAddress"))
            if start in ("0.0.0.0", "0.0.0.1") and end == "0.0.0.0":
                add("medium", "sql-allow-azure-services", str(dig(r, "name")) + " " + str(dig(rule, "name")), start + "-" + end, "Azure-internal range allowed; sentinel, not internet-wide", r.get("subscriptionId"))
            elif end == "255.255.255.255":
                add("high", "sql-firewall-wide-open", str(dig(r, "name")) + " " + str(dig(rule, "name")), start + "-" + end, "public range allowed", r.get("subscriptionId"))
            else:
                add("low", "sql-firewall-rule", str(dig(r, "name")) + " " + str(dig(rule, "name")), start + "-" + end, "verify the client still exists", r.get("subscriptionId"))


NSG_INVENTORY = "Resources | where type =~ 'microsoft.network/networksecuritygroups' | project name, subscriptionId"
NIC_ATTACH = "Resources | where type =~ 'microsoft.network/networkinterfaces' | project nsg=tostring(properties.networkSecurityGroup.id)"


@check("sub-nsg")
def c_nsg(ctx):
    q = (
        "Resources | where type =~ 'microsoft.network/networksecuritygroups'"
        " | mv-expand r = properties.securityRules"
        " | extend a=tostring(r.properties.access), d=tostring(r.properties.direction),"
        " src=tostring(coalesce(r.properties.sourceAddressPrefix, strcat_array(r.properties.sourceAddressPrefixes, ','))), srcs=r.properties.sourceAddressPrefixes,"
        " dst=tostring(r.properties.destinationPortRange), dsts=r.properties.destinationPortRanges"
        " | where a=='Allow' and d=='Inbound'"
        " | project name, rg=resourceGroup, subscriptionId, rule=tostring(r.properties.name), dst=dst, dsts=dsts, src=src, srcs=srcs"
    )
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-nsg", 0, denied=1)
        return
    wide = []
    unknown_src = []
    for r in rows:
        raw = str(r.get("src") or "")
        srcs = [str(x) for x in (r.get("srcs") or [])]
        if any_source(raw) or any(any_source(x) for x in srcs):
            wide.append(r)
        elif not raw and not srcs:
            unknown_src.append(r)
    note("sub-nsg", len(rows))
    if unknown_src:
        undecided("nsg-rule-source-unknown", "rules=" + str(len(unknown_src)), "a rule returned no source address; whether it admits the internet is not decided")
    attach = unread(arg_rows("Resources | where type =~ 'microsoft.network/virtualnetworks' | mv-expand sn=properties.subnets | project nsg=tolower(tostring(sn.properties.networkSecurityGroup.id))", ctx["subs"]),
                    "subnet attachments", "nsg-attachments-unreadable")
    nsg_total = unread(arg_rows(NSG_INVENTORY, ctx["subs"]), "network security group inventory", "nsg-inventory-unreadable")
    if nsg_total and not rows:
        add("info", "nsg-rules-not-indexed", "all", "nsgs=" + str(len(nsg_total)) + " ruleRows=0", "no network security group returned a rule; internet exposure is not assessed")
    elif nsg_total and not wide and not unknown_src:
        add("info", "nsg-no-internet-rule", "all", "nsgs=" + str(len(nsg_total)) + " ruleRows=" + str(len(rows)) + " internetFacing=0", "rules exist and none admits any address")
    attached = {str(dig(a, "nsg")) for a in lst(attach) if dig(a, "nsg")}
    nics = unread(arg_rows(NIC_ATTACH, ctx["subs"]), "network interface attachments", "nsg-nic-attachments-unreadable")
    attachment_known = attach is not None and nics is not None
    nic_nsgs = {str(dig(n, "nsg") or "").lower() for n in lst(nics) if dig(n, "nsg")}
    mgmt_ports = {"22", "3389", "1433", "3306", "5432", "5985", "5986", "21", "23", "445", "1521", "27017", "2375", "2376", "11211", "9200", "5601"}

    def is_mgmt(portspec):
        if isinstance(portspec, (list, tuple)):
            return any(is_mgmt(x) for x in portspec)
        spec = str(portspec or "").strip()
        if not spec:
            return False
        if spec.startswith("["):
            try:
                return any(is_mgmt(x) for x in json.loads(spec))
            except (ValueError, TypeError):
                pass
        if spec in ("*", "Any", "any"):
            return True
        for part in spec.replace(" ", "").split(","):
            if "-" in part:
                lo, _, hi = part.partition("-")
                try:
                    lo_i, hi_i = int(lo), int(hi)
                except ValueError:
                    continue
                if any(lo_i <= int(p) <= hi_i for p in mgmt_ports):
                    return True
            elif part in mgmt_ports:
                return True
        return False

    for r in wide:
        dst = str(r.get("dst") or "") + " " + str(r.get("dsts") or "")
        mgmt = is_mgmt(r.get("dst")) or is_mgmt(r.get("dsts"))
        full_id = ("/subscriptions/" + str(r.get("subscriptionId")) + "/resourcegroups/" + str(r.get("rg")) + "/providers/microsoft.network/networksecuritygroups/" + str(r.get("name"))).lower()
        is_attached = full_id in attached or full_id in nic_nsgs
        if not attachment_known:
            sev = "high" if mgmt else "low"
            attach_note = "unknown"
        else:
            sev = "high" if mgmt and is_attached else ("medium" if mgmt else "low")
            attach_note = str(is_attached)
        add(sev, "nsg-internet-inbound", r.get("name"), "rg=" + str(r.get("rg")) + " rule=" + str(r.get("rule")) + " port=" + dst + " source=" + str(r.get("src")), "inbound from the internet; attached=" + attach_note, r.get("subscriptionId"))


SECURITY_DEFINITION_HINTS = ("keyvault", "sql", "storage", "network", "virtualmachine", "defender", "encryption", "publicip", "nsg")


def _policy_maps(subs):
    with audit_scope():
        return _policy_maps_inner(subs)


def _policy_maps_inner(subs):
    assigns = arg_rows(
        "PolicyResources | where type =~ 'microsoft.authorization/policyassignments'"
        " | where subscriptionId in (" + subq(subs) + ") or tostring(properties.scope) startswith '/providers/Microsoft.Management/'"
        " | project name, id, subscriptionId, scope=tostring(properties.scope), def=properties.policyDefinitionId",
        subs,
        scoped=False,
    )
    defs = arg_rows(
        "PolicyResources | where type =~ 'microsoft.authorization/policydefinitions'"
        " | where subscriptionId in (" + subq(subs) + ") or isempty(tostring(subscriptionId))"
        " | project name, id, subscriptionId, displayName=properties.displayName, effect=properties.policyRule.then.effect",
        subs,
        scoped=False,
    )
    if assigns is None and defs is None:
        mark_failure()
        return {}, {}
    assigns = unread_list(assigns, "policy assignments", "policy-assignments-unreadable")
    defs = unread_list(defs, "policy definitions", "policy-definitions-unreadable")
    amap = {str(a.get("id")).lower(): a for a in assigns}
    dmap = {str(d.get("id")).lower(): d for d in defs}
    return amap, dmap


@check("sub-policy")
def c_policy(ctx):
    subs = ctx["subs"]
    rows = arg_rows(
        "PolicyResources | where type =~ 'microsoft.authorization/policyexemptions'"
        " | project name, subscriptionId, cat=properties.exemptionCategory, exp=properties.expiresOn,"
        " assignment=properties.policyAssignmentId, scope=tostring(properties.resourceId)",
        subs,
    )
    if rows is None:
        note("sub-policy", 0, denied=1)
        return
    amap, dmap = _policy_maps(subs)
    note("sub-policy", len(rows))
    for r in rows:
        aid = str(r.get("assignment") or "").lower()
        a = amap.get(aid) or {}
        d = dmap.get(str(a.get("def") or "").lower()) or {}
        target = d.get("displayName") or d.get("name") or a.get("name") or "unknown-definition"
        effect = str(d.get("effect") or "")
        security = any(h in str(target).lower() for h in SECURITY_DEFINITION_HINTS)
        expired = False
        unknown_expiry = False
        exp = r.get("exp")
        if exp:
            verdict = _expired(exp)
            unknown_expiry = verdict is None
            expired = verdict is True
        if unknown_expiry:
            add("low", "policy-exemption-expiry-unreadable", str(r.get("name")), "expiresOn=" + str(exp), "the exemption has an end date that could not be parsed; confirm it still applies", str(r.get("subscriptionId")))
        if expired:
            sev = "info"
        elif security and r.get("cat") == "Waiver":
            sev = "high"
        elif r.get("cat") == "Waiver":
            sev = "medium"
        else:
            sev = "low"
        add(
            sev,
            "policy-exemption",
            r.get("name"),
            "disables=" + str(target) + " effect=" + (effect or "-") + " category=" + str(r.get("cat"))
            + " expires=" + str(exp or "never") + " expired=" + str(expired),
            "policy effect disabled for this scope",
            r.get("subscriptionId"),
            r.get("scope"),
        )
    rows2 = arg_rows(
        "PolicyResources | where type =~ 'microsoft.authorization/policyassignments'"
        " | where tostring(properties.enforcementMode) == 'DoNotEnforce'"
        " | where subscriptionId in (" + subq(subs) + ") or isempty(tostring(subscriptionId))"
        " | project name, subscriptionId, def=properties.policyDefinitionId",
        subs,
        scoped=False,
    )
    for r in unread_list(rows2, "DoNotEnforce assignments", "policy-donotenforce-unreadable"):
        d = dmap.get(str(r.get("def") or "").lower()) or {}
        add(
            "medium",
            "policy-not-enforced",
            r.get("name"),
            "definition=" + str(d.get("displayName") or r.get("def")),
            "assignment evaluates but does not block",
            r.get("subscriptionId"),
        )


@check("sub-deployments")
def c_deployments(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.resources/deployments' | project name, subscriptionId, rg=resourceGroup, parameters=properties.parameters, outputs=properties.outputs", ctx["subs"])
    if rows is None:
        note("sub-deployments", 0, denied=1)
        return
    note("sub-deployments", len(rows))
    for r in rows:
        vals = []
        for side in ("parameters", "outputs"):
            stack = [r.get(side)]
            while stack:
                cur = stack.pop()
                if isinstance(cur, dict):
                    stack.extend(cur.values())
                elif isinstance(cur, list):
                    stack.extend(cur)
                elif isinstance(cur, str) and len(cur) > 12 and not cur.startswith(("http", "/subscriptions")):
                    vals.append(cur)
        hits = [v for v in vals if (SECRET_MATERIAL.search(v) or (SECRET_PAT.search(v) and not SECRET_NOISE.search(v))) and not v.lower().startswith("[parameters(")]
        if hits:
            add("high", "deployment-history-secret", r.get("name"), "rg=" + str(r.get("rg")) + " values=" + str(len(hits)) + " firstMatch=<redacted length=" + str(len(hits[0])) + ">", "ARM history stores parameter and output values verbatim", r.get("subscriptionId"))


@check("sub-locks")
def c_locks(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.authorization/locks' | project name, subscriptionId, level=properties.level", ctx["subs"])
    if rows is None:
        note("sub-locks", 0, denied=1)
        return
    note("sub-locks", len(rows))
    have = Counter(r.get("subscriptionId") for r in rows)
    for s in ctx["subs"]:
        if not have.get(s):
            add("low", "no-resource-locks", s, "0 locks", "nothing prevents deletion", s)


AAD_REQUIRED_CATEGORIES = (
    "SignInLogs",
    "NonInteractiveUserSignInLogs",
    "ServicePrincipalSignInLogs",
    "ManagedIdentitySignInLogs",
    "AuditLogs",
    "RiskyUsers",
    "UserRiskEvents",
)


def _categories(item):
    out = []
    for log in ((item.get("properties") or {}).get("logs") or []):
        if log.get("enabled"):
            out.append(log.get("category") or log.get("categoryGroup") or "?")
    return out


def _destination(p):
    if p.get("workspaceId"):
        return "loganalytics"
    if p.get("storageAccountId"):
        return "storage"
    if p.get("eventHubAuthorizationRuleId"):
        return "eventhub"
    return "none"


@check("sub-diagnostics")
def c_diag(ctx):
    subs = ctx["subs"]
    act = per_sub(subs, "providers/microsoft.insights/diagnosticSettings", "2021-05-01-preview", lambda d: d.get("value") or [])
    note("sub-diagnostics", sum(1 for v in act.values() if v is not None), denied=sum(1 for v in act.values() if v is None))
    add("info", "entra-log-export-unassessed", "tenant", "aadiam diagnostic settings are tenant-scoped", "subscription-scoped reads cannot confirm Entra log export")
    for s in subs:
        if act.get(s) == []:
            add("medium", "no-activity-log-export", s, "0 subscription diagnostic settings", "control-plane events not exported", s)

        for item in (act.get(s) or []):
            p = item.get("properties") or {}
            dest = _destination(p)
            cats = _categories(item)
            if dest == "none":
                add("low", "diagnostic-setting-no-destination", s + " " + str(item.get("name")), "no destination configured", "setting exists but exports nowhere", s)
            if not cats:
                add("low", "diagnostic-setting-no-categories", s + " " + str(item.get("name")), "dest=" + dest + " categories=0", "setting enabled with no log category", s)
            else:
                add("info", "diagnostic-setting", s + " " + str(item.get("name")), "dest=" + dest + " categories=" + ",".join(cats)[:70], "verify the exported categories cover the audit scope", s)



@check("sub-defender")
def c_defender(ctx):
    res = per_sub(ctx["subs"], "providers/Microsoft.Security/pricings", "2023-01-01", lambda d: d.get("value") or [])
    note("sub-defender", sum(1 for v in res.values() if v is not None), denied=sum(1 for v in res.values() if v is None))
    for s, items in res.items():
        for p in items or []:
            tier = str((p.get("properties") or {}).get("pricingTier") or "").lower()
            if tier == "free":
                add("medium", "defender-free-tier", s + " " + str(p.get("name")), "pricingTier=free", "detection disabled for this workload", s)


@check("sub-appservice")
def c_appservice(ctx):
    q = "Resources | where type =~ 'microsoft.web/sites' | project name, subscriptionId, rg=resourceGroup, https=properties.httpsOnly"
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-appservice", 0, denied=1)
        return
    checked = 0
    for r in rows[:25]:
        s = r.get("subscriptionId")
        https = tri(r.get("https"))
        if https is False:
            add("medium", "appservice-http-allowed", r.get("name"), "httpsOnly=false", "plaintext transport accepted", s)
        elif https is None:
            add("low", "appservice-http-unknown", r.get("name"), "httpsOnly not returned", "plaintext transport cannot be excluded", s)
        url = ARM_BASE + "/subscriptions/" + str(s) + "/resourceGroups/" + str(r.get("rg")) + "/providers/Microsoft.Web/sites/" + str(r.get("name")) + "/config/web?api-version=2022-09-01"
        LAST_QUERY[CURRENT["check"]] = "az rest --url " + repr(url)
        cfg = az(["rest", "--url", url])
        if cfg is None:
            deny("sub-appservice")
            continue
        checked += 1
        p = cfg.get("properties") or {}
        if str(p.get("ftpsState") or "") == "AllAllowed":
            add("medium", "appservice-ftp-enabled", r.get("name"), "ftpsState=AllAllowed", "FTP transport enabled", s)
        debug = tri(p.get("remoteDebuggingEnabled"))
        if debug is True:
            add("high", "appservice-remote-debug", r.get("name"), "remoteDebuggingEnabled=true", "debug endpoint exposed", s)
        tls = str(p.get("minTlsVersion") or "").strip()
        if tls in ("1.0", "1.1"):
            add("medium", "appservice-legacy-tls", r.get("name"), "minTlsVersion=" + tls, "legacy TLS accepted", s)
        elif not tls:
            add("low", "appservice-tls-unknown", r.get("name"), "minTlsVersion not returned", "platform default applies; confirm the enforced version", s)
    note("sub-appservice", checked, denied=DENIED["sub-appservice"])
    sample("sub-appservice", min(len(rows), 25), len(rows), "web apps")



@check("sub-managed-identities")
def c_mi(ctx):
    q = (
        "AuthorizationResources | where type =~ 'microsoft.authorization/roleassignments'"
        " | where subscriptionId in (" + subq(ctx["subs"]) + ")"
        " | where tostring(properties.principalType) == 'ServicePrincipal'"
        " | where (tostring(properties.roleDefinitionId) endswith '" + BUILTIN_ROLE_OWNER + "'"
        " or tostring(properties.roleDefinitionId) endswith '" + BUILTIN_ROLE_UAA + "')"
        " | project principalId=tostring(properties.principalId), roleId=tostring(properties.roleDefinitionId), scope=tostring(properties.scope)"
    )
    rows = arg_rows(q, ctx["subs"], scoped=False)
    if rows is None:
        note("sub-managed-identities", 0, denied=1)
        return
    note("sub-managed-identities", len(rows))
    sp_rows = graph_all("servicePrincipals?$select=id,displayName,servicePrincipalType", limit=40)
    kinds = {}
    if sp_rows is None:
        denied_now("sub-managed-identities")
    else:
        kinds = {str(dig(s, "id")): str(dig(s, "servicePrincipalType") or "") for s in sp_rows}
    trunc("sub-managed-identities", sum(1 for r in rows if str(dig(r, "principalId")) in kinds), len(rows), "service principal types resolved")
    for r in rows:
        sub = ctx_sub(r)
        pid = str(dig(r, "principalId"))
        name = ctx["idx"].resolve(pid) or pid
        kind = kinds.get(pid, "")
        if not kind:
            doc = graph("servicePrincipals/" + pid + "?$select=servicePrincipalType")
            if doc is not None:
                kind = str(val(dig(doc, "servicePrincipalType"), ""))
                kinds[pid] = kind
        if not kind:
            add("high", "service-principal-privileged-role", name, "servicePrincipalType=unknown role=" + str(dig(r, "roleId")) + " scope=" + str(dig(r, "scope")), "an application identity holds a privileged role; its type could not be resolved", sub, str(dig(r, "scope")))
            continue
        if kind != "ManagedIdentity":
            add("high", "service-principal-privileged-role", name, "servicePrincipalType=" + kind + " role=" + str(dig(r, "roleId")) + " scope=" + str(dig(r, "scope")), "an application identity can grant access or own resources", sub, str(dig(r, "scope")))
            continue
        add("high", "managed-identity-privileged-role", name, "servicePrincipalType=" + (kind or "unknown") + " role=" + str(dig(r, "roleId")) + " scope=" + str(dig(r, "scope")), "machine identity can grant access or own resources", sub, str(dig(r, "scope")))


@check("sub-public-ips")
def c_pubip(ctx):
    q = "Resources | where type =~ 'microsoft.network/publicipaddresses' | project name, subscriptionId, ip=properties.ipAddress, assoc=tostring(properties.ipConfiguration.id)"
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-public-ips", 0, denied=1)
        return
    note("sub-public-ips", len(rows))
    for r in rows:
        assoc = r.get("assoc") or ""
        if any(h in assoc for h in VM_ATTACHED):
            continue
        if not assoc:
            add("low", "public-ip-unattached", r.get("name"), "ip=" + str(r.get("ip")) + " assoc=none", "reserved address with no consumer; verify intent", r.get("subscriptionId"))
        else:
            parts = str(assoc).split("/")
            consumer = parts[-3] if len(parts) >= 3 else str(assoc)
            add("info", "public-ip-service-bound", dig(r, "name"), "ip=" + str(dig(r, "ip")) + " consumer=" + consumer, "address fronts a platform service, not a VM interface", str(dig(r, "subscriptionId")))


@check("sub-backup")
def c_backup(ctx):
    q = "Resources | where type =~ 'microsoft.dataprotection/backupvaults' or type =~ 'microsoft.recoveryservices/vaults' | project name, type, subscriptionId, props=properties"
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-backup", 0, denied=1)
        return
    note("sub-backup", len(rows))
    for r in rows:
        p = r.get("props") or {}
        rtype = str(r.get("type") or "").lower()
        soft = ((p.get("securitySettings") or {}).get("softDeleteSettings") or {})
        state = on_off(soft.get("softDeleteState") or soft.get("state"))
        if state == "unknown":
            add("low", "backup-soft-delete-unknown", dig(r, "name"), "softDeleteState not returned", "recovery posture cannot be confirmed", str(dig(r, "subscriptionId")))
        elif state == "off":
            add("medium", "backup-soft-delete-off", dig(r, "name"), "softDeleteState=" + str(dig(soft, "softDeleteState") or dig(soft, "state")), "backup deletion cannot be reversed", str(dig(r, "subscriptionId")))
        if rtype.endswith("backupvaults"):
            raw_immut = dig(p, "securitySettings.immutabilitySettings.state")
            istate = immutability(raw_immut)
            # A Backup vault enforces multi-user authorization through a Resource Guard.
            mua = on_off(dig(p, "isVaultProtectedByResourceGuard"))
            if istate == "off":
                add("medium", "backup-immutability-off", r.get("name"), "immutabilitySettings=" + str(raw_immut) + " mua=" + mua, "backup data can be altered or deleted", r.get("subscriptionId"))
            elif istate == "unknown":
                add("low", "backup-immutability-unknown", r.get("name"), "immutabilitySettings.state=" + (str(val(raw_immut, "")) or "not returned"), "immutability cannot be confirmed", r.get("subscriptionId"))
            if mua == "off":
                add("low", "backup-no-multi-user-auth", r.get("name"), "isVaultProtectedByResourceGuard=false", "critical backup operations need no second approver", r.get("subscriptionId"))
            elif mua == "unknown":
                add("low", "backup-mua-unknown", r.get("name"), "isVaultProtectedByResourceGuard not returned", "multi-user authorization cannot be confirmed", r.get("subscriptionId"))
        else:
            red = str(p.get("redundancySettings") or "")
            add("info", "recovery-services-vault", r.get("name"), "softDelete=" + (state or "-") + " redundancy=" + (red or "-"), "verify immutability and MUA separately", r.get("subscriptionId"))


@check("sub-orphans")
def c_orphans(ctx):
    idx = ctx["idx"]
    rows = arg_rows("Resources | where type =~ 'microsoft.keyvault/vaults' | project name, subscriptionId, policies=properties.accessPolicies", ctx["subs"])
    if rows is None:
        note("sub-orphans", 0, denied=1)
        return
    seen = 0
    for r in rows:
        for p in lst(dig(r, "policies")):
            oid = p.get("objectId")
            if not oid:
                continue
            seen += 1
            resolved, reason = idx.resolve_reason(oid)
            if resolved is None and reason != "absent":
                continue
            if resolved is None:
                add("medium", "orphaned-keyvault-policy", str(r.get("name")) + " " + oid, "objectId absent from the directory", "grant left behind after identity deletion", r.get("subscriptionId"))
    note("sub-orphans", seen, denied=DENIED["sub-orphans"])
    add("info", "vault-policy-principals-examined", "all", "vaults=" + str(len(rows)) + " principals=" + str(seen), "access policy principals checked against the directory")


@check("sub-sql-orphans")
def c_sql_orphans(ctx):
    idx = ctx["idx"]
    q = "Resources | where type =~ 'microsoft.sql/servers' | project name, subscriptionId, rg=resourceGroup"
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-sql-orphans", 0, denied=1)
        return
    n = 0
    for r in rows:
        base = (
            ARM_BASE + "/subscriptions/" + str(r.get("subscriptionId"))
            + "/resourceGroups/" + str(r.get("rg")) + "/providers/Microsoft.Sql/servers/" + str(r.get("name"))
            + "/administrators/ActiveDirectory?api-version=2022-05-01-preview"
        )
        doc = az(["rest", "--url", base])
        if doc is None:
            denied_now("sub-sql-orphans")
            continue
        n += 1
        p = doc.get("properties") or {}
        sid = p.get("sid")
        if not sid:
            continue
        resolved, reason = idx.resolve_reason(sid)
        if resolved is None and reason != "absent":
            add("info", "sql-entra-admin-unresolved", str(r.get("name")) + " " + str(sid), "login=" + str(p.get("login")) + " reason=" + reason, "the administrator identity was not resolved; it is not reported as orphaned", r.get("subscriptionId"))
        elif resolved is None:
            add("medium", "sql-orphaned-administrator", str(r.get("name")) + " " + str(sid), "login=" + str(p.get("login")) + " type=" + str(p.get("administratorType")), "administrator identity is absent from the directory; with AAD-only auth this blocks administration", r.get("subscriptionId"))
        else:
            add("info", "sql-entra-admin", str(r.get("name")) + " " + str(resolved), "type=" + str(p.get("administratorType")), "administrator resolves", r.get("subscriptionId"))
    note("sub-sql-orphans", n, denied=DENIED["sub-sql-orphans"])


@check("sub-arm-orphans")
def c_arm_orphans(ctx):
    idx = ctx["idx"]
    q = (
        "AuthorizationResources | where type =~ 'microsoft.authorization/roleassignments'"
        " | where subscriptionId in (" + subq(ctx["subs"]) + ")"
        " | project principalId=tostring(properties.principalId), principalType=tostring(properties.principalType), scope=tostring(properties.scope)"
        " | summarize n=count() by principalId, principalType, scope"
    )
    rows = arg_rows(q, ctx["subs"], scoped=False)
    if rows is None:
        note("sub-arm-orphans", 0, denied=1)
        return
    note("sub-arm-orphans", len(rows))
    seen = set()
    for r in rows:
        pid = r.get("principalId")
        if not pid or pid in seen:
            continue
        seen.add(pid)
        resolved, reason = idx.resolve_reason(pid)
        if resolved is None and reason != "absent":
            continue
        if resolved is None:
            add("medium", "orphaned-arm-role-assignment", pid, "type=" + str(r.get("principalType")) + " scope=" + str(r.get("scope")), "principal absent from the directory; access was never revoked", ctx_sub(r), r.get("scope"))


@check("sub-approle-orphans")
def c_approle_orphans(ctx):
    idx = ctx["idx"]
    sps = idx.sps()[:15]
    n = 0
    sample("sub-approle-orphans", min(len(idx.sps()), 15), len(idx.sps()), "service principals")
    for s in sps:
        sid = s.get("id")
        if not sid:
            continue
        doc = graph("servicePrincipals/" + str(sid) + "/appRoleAssignments")
        if doc is None:
            deny("sub-approle-orphans")
            continue
        n += 1
        for a in doc.get("value") or []:
            pid = a.get("principalId")
            resolved, reason = idx.resolve_reason(pid) if pid else (None, "error")
            if resolved is None and reason != "absent":
                continue
            if resolved is None:
                add("medium", "orphaned-app-role-assignment", idx.name(s) + " " + str(pid), "resource=" + str(a.get("resourceDisplayName")), "app role still granted to a principal that no longer exists")
    note("sub-approle-orphans", n, denied=DENIED["sub-approle-orphans"])


DATAPLANE_PROBES = (
    ("microsoft.keyvault/vaults", "keyvault-secrets", lambda r: ["keyvault", "secret", "list", "--vault-name", str(r.get("name")), "--maxresults", "1"]),
    ("microsoft.storage/storageaccounts", "storage-account-keys", lambda r: ["storage", "account", "keys", "list", "-n", str(r.get("name")), "-g", str(r.get("rg"))]),
    ("microsoft.containerregistry/registries", "acr-repositories", lambda r: ["acr", "repository", "list", "-n", str(r.get("name"))]),
    ("microsoft.cache/redis", "redis-keys", lambda r: ["redis", "list-keys", "-n", str(r.get("name")), "-g", str(r.get("rg"))]),
    ("microsoft.documentdb/databaseaccounts", "cosmos-keys", lambda r: ["cosmosdb", "keys", "list", "-n", str(r.get("name")), "-g", str(r.get("rg"))]),
    ("microsoft.servicebus/namespaces", "servicebus-keys", lambda r: ["servicebus", "namespace", "authorization-rule", "keys", "list", "-g", str(r.get("rg")), "--namespace-name", str(r.get("name")), "--name", "RootManageSharedAccessKey"]),
    ("microsoft.web/sites", "functionapp-keys", lambda r: ["functionapp", "keys", "list", "-n", str(r.get("name")), "-g", str(r.get("rg"))]),
    ("microsoft.cognitiveservices/accounts", "cognitive-keys", lambda r: ["cognitiveservices", "account", "keys", "list", "-n", str(r.get("name")), "-g", str(r.get("rg"))]),
    ("microsoft.search/searchservices", "search-admin-keys", lambda r: ["search", "admin-key", "list", "--service-name", str(r.get("name")), "-g", str(r.get("rg"))]),
    ("microsoft.appconfiguration/configurationstores", "appconfig-keys", lambda r: ["appconfig", "credential", "list", "-n", str(r.get("name")), "-g", str(r.get("rg"))]),
)


@check("sub-dataplane")
def c_datapane(ctx):
    total = 0
    for rtype, label, builder in DATAPLANE_PROBES:
        rows = arg_rows("Resources | where type =~ '" + rtype + "' | project name, subscriptionId, rg=resourceGroup", ctx["subs"])
        if rows is None:
            deny("sub-dataplane")
            continue
        ok = 0
        denied = 0
        sample("sub-dataplane", min(len(rows), 5), len(rows), label + " resources")
        for r in rows[:5]:
            total += 1
            cmd = builder(r)
            sub = str(val(dig(r, "subscriptionId"), ""))
            if sub and "--subscription" not in cmd:
                cmd = cmd + ["--subscription", sub]
            res = az(cmd, timeout=60)
            if res is None:
                kind = az_kind()
                if kind in ("denied", "unauthenticated", "absent"):
                    denied += 1
                else:
                    deny("sub-dataplane")
                continue
            ok += 1
            kind = "data-plane" if label in ("keyvault-secrets", "acr-repositories", "redis-keys") else "control-plane key read"
            add("high", "datapane-secret-readable" if kind == "data-plane" else "controlplane-key-readable", str(r.get("name")) + " " + label, "kind=" + kind, "the audit identity can read this credential material", r.get("subscriptionId"))
        if rows:
            add("info", "datapane-probe", label, "resources=" + str(len(rows)) + " allowed=" + str(ok) + " denied=" + str(denied), "data plane not assessed unless allowed>0")
    note("sub-dataplane", total, denied=DENIED["sub-dataplane"])


def scan_dynamic(ctx):
    """Classify dynamic groups once, for any check that reads ctx["dyn"].

    A caller whose verdict depends on the classification takes a denial when the
    rules could not be read, so it cannot report a clean result.
    """
    if not ctx.get("dyn_done"):
        with audit_scope(check="entra-dynamic-groups"):
            c_dyn(ctx)
    if (ctx.get("dyn_failed") or ctx.get("dyn_degraded")) and CURRENT["check"] != "entra-dynamic-groups":
        deny(CURRENT["check"])


def dynamic_groups(ctx):
    """id -> (displayName, membershipRule, processingState) for every dynamic group.

    Live Graph first; the AzureHound export when Graph is unreadable. None when
    neither source could be read. Cached in ctx.
    """
    if "dyn_rules" in ctx:
        if ctx.get("dyn_degraded") and ctx["dyn_rules"] is not None:
            deny(CURRENT["check"])  # every reader of the export fallback is partial, not only the first
        return ctx["dyn_rules"]
    ctx["dyn_degraded"] = False
    out = None
    rows = graph_all("groups?$filter=groupTypes/any(c:c eq 'DynamicMembership')&$select=id,displayName,membershipRule,membershipRuleProcessingState", limit=20)
    if rows is not None:
        out = {str(dig(g, "id")): (str(val(dig(g, "displayName"), "")), str(val(dig(g, "membershipRule"), "")),
                                   str(val(dig(g, "membershipRuleProcessingState"), ""))) for g in rows}
    else:
        denied_now(CURRENT["check"])  # the live read failed; the export is a weaker, possibly stale source
        ctx["dyn_degraded"] = True
        try:
            idx = ctx["idx"]
            out = {}
            for g in idx.groups():
                p = idx.props(g)
                rule = str(val(dig(p, "membershipRule"), ""))
                if rule:
                    out[str(dig(g, "id"))] = (str(val(dig(p, "displayName"), "")), rule, str(val(dig(p, "membershipRuleProcessingState"), "")))
        except DatasetUnavailable:
            out = None
    ctx["dyn_rules"] = out
    return out


# Who can steer a dynamic rule, from easiest to hardest.
STEER_ORDER = ("guest", "device", "privileged", "fixed")
STEER_OPEN = ("guest", "device")
STEER_LABEL = {"guest": "anyone who can invite a guest", "device": "anyone who can register a device",
               "privileged": "attribute writer (admin, on-prem sync or app with User.ReadWrite.All)"}
MAILISH = ("user.mail", "user.othermails", "user.proxyaddresses", "user.userprincipalname")
DEVICE_SET = ("device.displayname", "device.devicemodel", "device.devicemanufacturer", "device.deviceostype",
              "device.deviceosversion", "device.accountenabled")
RULE_TERM = re.compile(r'((?:user|device)\.[a-z0-9_.]+)\s+(?:-(?:any|all)\s*\(\s*_\s+)?(-[a-z]+)\s+("[^"]*"|\[[^\]]*\]|\S+)')


def rule_steer(rule):
    """(steer, attributes) for a dynamic membership rule.

    steer is who can change membership: guest (an invited guest matches), device
    (whoever registers a device sets the value), privileged (an admin, on-prem sync or
    an app writes the attribute: extensionAttributeN, extension_<appId>_*, custom
    security attributes, onPremises*, memberOf) or fixed.
    -or picks the easiest branch, -and the hardest; -and binds tighter than -or, as in
    Entra. A userType Member guard closes guest terms in its own -and group.
    ponytail: token heuristic per leaf; -not is ignored and -match is read as loose.
    Guest invite and device registration policy are not read.
    """
    text = re.sub(r"\s+", " ", str(rule or "").lower())  # the rule editor stores newlines and tabs
    terms = RULE_TERM.findall(text)
    if not terms:
        return "fixed", []
    return _steer_expr(text, False), sorted({a for a, _, _ in terms})


RULE_GUARD = re.compile(r'^user\.usertype\s+-(?:eq\s+"?member|ne\s+"?guest|in\s+\[\s*"member"\s*\])')


def _split_top(text, op):
    """Split on op where it stands outside parentheses, brackets and quotes."""
    parts, depth, quoted, start, i = [], 0, False, 0, 0
    while i < len(text):
        ch = text[i]
        if ch == '"':
            quoted = not quoted
        elif not quoted and ch in "([":
            depth += 1
        elif not quoted and ch in ")]":
            depth -= 1
        elif not quoted and depth == 0 and text.startswith(op, i):
            parts.append(text[start:i])
            i += len(op)
            start = i
            continue
        i += 1
    parts.append(text[start:])
    return parts


def _unwrap(expr):
    """Strip parentheses that enclose the whole expression."""
    e = expr.strip()
    while e.startswith("(") and e.endswith(")"):
        inner, depth = e[1:-1], 0
        for ch in inner:
            depth += ch == "("
            depth -= ch == ")"
            if depth < 0:
                return e
        e = inner.strip()
    return e


def _steer_expr(expr, guarded):
    e = _unwrap(expr)
    ors = _split_top(e, " -or ")
    if len(ors) > 1:
        return min((_steer_expr(x, guarded) for x in ors), key=STEER_ORDER.index)
    ands = [_unwrap(x) for x in _split_top(e, " -and ")]
    if len(ands) > 1:
        rest = [x for x in ands if not RULE_GUARD.match(x)]
        guarded = guarded or len(rest) < len(ands)
        if not rest:
            return "privileged"
        return max((_steer_expr(x, guarded) for x in rest), key=STEER_ORDER.index)
    terms = RULE_TERM.findall(e)
    if not terms:
        return "fixed"
    return max((_steer_term(attr, op, value, guarded) for attr, op, value in terms), key=STEER_ORDER.index)


def _steer_term(attr, op, value, guarded):
    if attr == "user.usertype":
        # -eq guest or -ne member selects guests; a Member guard alone needs a new member account.
        return "guest" if (op in ("-eq", "-in")) == ("guest" in value) else "privileged"
    loose = op not in ("-eq", "-in")
    negated = op.startswith("-n")
    # accountEnabled selects every enabled account only for "-eq true" or "-ne false".
    every_enabled = attr.endswith(".accountenabled") and (("true" in value) == (op == "-eq"))
    if attr.startswith("user."):
        if not guarded and (attr == "user.displayname" or every_enabled or (attr in MAILISH and loose) or (attr == "user.objectid" and negated)):
            return "guest"
        if attr == "user.objectid" and not negated:
            return "fixed"
        return "privileged"
    if attr in DEVICE_SET and (attr != "device.accountenabled" or every_enabled):
        return "device"
    if attr in ("device.objectid", "device.deviceid"):
        return "fixed"
    return "privileged"


def group_node(ctx, gid):
    """Chain label for a dynamic group. The id suffix keeps two groups that share a
    display name apart in the dot graph."""
    name = (dig(ctx, "dyn_rules", None) or {}).get(gid, ("",))[0]
    return "group " + (name or gid) + " (" + str(gid)[:8] + ")"


def _group_capabilities(ctx, gids):
    """(gid -> [(rank, label)], gids not fully assessed) for what membership grants:
    Azure RBAC and app roles.

    rank 3 controls RBAC, 2 holds a dangerous Azure action, 1 reaches an application.
    """
    caps = defaultdict(list)
    blind = set(sorted(gids)[40:])
    for gid in sorted(gids)[:40]:
        doc = graph("groups/" + gid + "/appRoleAssignments?$select=resourceDisplayName")
        if doc is None:
            denied_now(CURRENT["check"])
            blind.add(gid)
            continue
        for a in lst(dig(doc, "value")):
            caps[gid].append((1, "app " + str(val(dig(a, "resourceDisplayName"), "?"))))
    sample(CURRENT["check"], min(len(gids), 40), len(gids), "dynamic groups checked for app access")
    if not gids:
        return caps, blind
    if not ctx.get("subs"):
        undecided("dynamic-group-rbac-unassessed", "subscriptions=0", "no subscription in scope; Azure RBAC granted to dynamic groups was not read")
        return caps, set(gids)
    rows = unread(arg_rows("AuthorizationResources | where type =~ 'microsoft.authorization/roleassignments' | where tostring(properties.principalType) =~ 'Group' | project principalId=tostring(properties.principalId), roleId=tolower(tostring(properties.roleDefinitionId)), scope=tostring(properties.scope), subscriptionId", ctx["subs"]),
                  "Azure role assignments to groups", "dynamic-group-rbac-unassessed")
    defs = unread(arg_rows(tenant_wide("AuthorizationResources | where type =~ 'microsoft.authorization/roledefinitions' | project id=tolower(id), name=tostring(properties.roleName), perms=properties.permissions"), ctx["subs"], scoped=False),
                  "Azure role definitions", "dynamic-group-rbac-unassessed")
    if rows is None or defs is None:
        return caps, set(gids)
    roles = {str(dig(d, "id")).split("/")[-1]: (str(dig(d, "name")), lst(dig(d, "perms"))) for d in defs}
    for r in rows:
        gid = str(dig(r, "principalId"))
        if gid not in gids:
            continue
        name, perms = roles.get(str(dig(r, "roleId")).split("/")[-1], ("", []))
        rank = 3 if grants_role_write(perms) else 2 if any(permits(p, t) for p in perms for t in DANGEROUS_ACTIONS) else 0
        if rank:
            caps[gid].append((rank, name + " on " + str(dig(r, "scope"))))
    return caps, blind


@check("entra-dynamic-groups")
def c_dyn(ctx):
    if ctx.get("dyn_done"):
        return
    ctx["dyn_done"] = True
    ctx.setdefault("dyn", {})
    ctx.setdefault("dynamic", set())
    groups = unread(dynamic_groups(ctx), "dynamic group rules", "dynamic-groups-unreadable")
    if groups is None:
        ctx["dyn_failed"] = True
        note("entra-dynamic-groups", 0)
        return
    note("entra-dynamic-groups", len(groups))
    steers = {gid: rule_steer(rule) for gid, (_name, rule, _state) in groups.items()}
    for gid, (steer, _attrs) in steers.items():
        ctx["dyn"][gid] = steer
        ctx["dynamic"].add(gid)
    caps, blind = _group_capabilities(ctx, [g for g, (s, _a) in steers.items() if s != "fixed"])
    for gid, (name, rule, state) in groups.items():
        label = name or gid
        steer, attrs = steers[gid]
        if state.lower() == "paused":
            add("low", "dynamic-group-processing-paused", label, "membershipRuleProcessingState=Paused", "membership is frozen; the rule no longer decides who is in the group")
        grants = sorted(caps.get(gid, []), reverse=True)
        top = grants[0][0] if grants else 0
        if steer in STEER_OPEN:
            sev = ("low", "medium", "high", "critical")[top]
        elif steer == "privileged":
            sev = (None, None, "low", "medium")[top]
        else:
            sev = None
        if not sev:
            continue
        add(sev, "dynamic-group-steerable", label,
            "steer=" + steer + " attrs=" + (",".join(attrs) or "-") + " grants=" + (",".join(g for _r, g in grants[:3]) or ("not assessed" if gid in blind else "none")) + " rule=" + rule[:80],
            "whoever can steer the rule decides who holds what the group grants")
        if sev in ("critical", "high"):
            chain("dynamic-group-to-capability", STEER_LABEL[steer] + " -> " + group_node(ctx, gid) + " -> " + grants[0][1], sev, "a rule an outsider can satisfy grants this access")


@check("entra-group-roles")
def c_grouproles(ctx):
    scan_dynamic(ctx)
    idx = ctx["idx"]
    defs = {}
    rd = graph_all("roleManagement/directory/roleDefinitions", limit=5)
    if rd is None:
        note("entra-group-roles", 0, denied=1)
        return
    for r in rd:
        actions = []
        for perm in r.get("rolePermissions") or []:
            actions.extend(perm.get("allowedResourceActions") or [])
        if not r.get("id"):
            continue
        defs[r["id"]] = {"name": r.get("displayName"), "writable": any(not a.endswith("/read") for a in actions)}
    assignments = graph_all("roleManagement/directory/roleAssignments", limit=5)
    if assignments is None:
        note("entra-group-roles", 0, denied=1)
        return
    note("entra-group-roles", len(assignments))
    for a in assignments:
        pid = a.get("principalId")
        d = defs.get(a.get("roleDefinitionId")) or {}
        if pid in ctx["dynamic"]:
            sev = "critical" if d.get("writable") else "high"
            name = idx.resolve(pid) or pid
            add(sev, "dynamic-group-holds-role", name, "role=" + str(d.get("name")) + " writable=" + str(d.get("writable")), "rule-based membership decides who holds this role")
            chain("dynamic-group-to-role", "attribute -> " + str(name) + " -> role " + str(d.get("name")), sev, "a mutable attribute decides role membership")
        elif d.get("writable") and pid in idx.names:
            add("low", "principal-holds-write-role", idx.names[pid], "role=" + str(d.get("name")), "review necessity", "tenant")


SCOPE_NAMES = {}


def declared_names(ids, resource_app=None):
    """Permission ids mapped to scope names for one resource app, or None when the lookup failed.

    Permission ids are only unique inside their resource application, so the key carries it.
    """
    resource = str(resource_app or GRAPH_APP_ID)
    if resource not in SCOPE_NAMES:
        with audit_scope():
            doc = graph("servicePrincipals?$filter=appId eq '" + resource + "'&$select=appId,oauth2PermissionScopes")
        if doc is None:
            return None
        names = {}
        for sp in lst(dig(doc, "value")):
            for scope in lst(dig(sp, "oauth2PermissionScopes")):
                names[str(dig(scope, "id"))] = str(val(dig(scope, "value"), "")).lower()
        SCOPE_NAMES[resource] = names
    names = SCOPE_NAMES[resource]
    return {names[i] for i in ids if i in names and names[i]}


def _glob(pattern, value):
    if pattern == "*":
        return True
    if pattern == value:
        return True
    if "*" not in pattern:
        return False
    return re.match("^" + re.escape(pattern).replace("\\*", ".*") + "$", value) is not None


def permits(perm, action):
    """True when this permission block grants some action inside the requested pattern.

    A literal target is tested directly. A wildcard target asks whether the block grants
    anything in that namespace, so the wildcard may sit on either side of the comparison.
    """
    acts = [str(a).lower() for a in lst(dig(perm, "actions"))]
    nots = [str(a).lower() for a in lst(dig(perm, "notActions"))]
    target = str(action).lower()
    glob = "*" in target
    probe = "/".join("x" if "*" in seg else seg for seg in target.split("/")) if glob else target

    def hit(pattern):
        if not glob:
            return _glob(pattern, target)
        return _glob(target, pattern) or _glob(pattern, target) or _glob(pattern, probe)

    def denied(pattern):
        return _glob(pattern, probe)

    if any(denied(p) for p in nots):
        return False
    return any(hit(p) for p in acts)


def grants_role_write(perms):
    return any(permits(p, "microsoft.authorization/roleassignments/write") for p in lst(perms))


def write_scope(scope):
    low = str(scope or "").lower()
    return any(t in low for t in ("readwrite", "fullcontrol", "manage", ".write", "accessasuser"))


def _strengths():
    """id -> (displayName, allowedCombinations), or None when the read failed."""
    rows = unread(graph_all("policies/authenticationStrengthPolicies", limit=3),
                  "authentication strength policies", "ca-strengths-unreadable")
    if rows is None:
        return None
    out = {}
    for sp in rows:
        out[sp.get("id")] = (sp.get("displayName"), [c for c in sp.get("allowedCombinations") or []])
    return out


@check("entra-ca")
def c_ca(ctx):
    scan_dynamic(ctx)
    pols = ca_all("policies", limit=5)
    if pols is None:
        note("entra-ca", 0, denied=1)
        return
    note("entra-ca", len(pols))
    strengths = _strengths()
    ctx["ca"] = pols
    restricts_flows = False
    has_frequency = False
    has_risk = False
    requires_device = False
    for p in pols:
        state = p.get("state")
        enforced = state == "enabled"
        name = p.get("displayName")
        cond = p.get("conditions") or {}
        users = cond.get("users") or {}
        gc = p.get("grantControls") or {}
        sc = p.get("sessionControls") or {}
        builtins = [str(b) for b in (gc.get("builtInControls") or [])]
        if state == "enabledForReportingButNotEnforced":
            add("high", "ca-policy-report-only", name, "state=report-only", "control documented but not enforced")
        for gid in users.get("excludeGroups") or []:
            steer = dig(ctx, "dyn", {}).get(gid)
            if enforced and steer in STEER_OPEN + ("privileged",):
                glabel = (dig(ctx, "dyn_rules", None) or {}).get(gid, (gid,))[0] or gid
                sev = "high" if steer in STEER_OPEN else "medium"
                add(sev, "ca-exclusion-dynamic-group", name, "excludeGroups includes " + glabel + " steer=" + steer, "rule-based membership removes the control")
                if sev == "high":
                    chain("attribute-to-ca-bypass", STEER_LABEL[steer] + " -> " + group_node(ctx, gid) + " -> excluded from " + str(name), sev, "join the group, skip the policy")
        if state == "enabled" and (users.get("excludeGroups") or users.get("excludeUsers")):
            add("low", "ca-policy-has-exclusions", name, "excludeGroups=" + str(len(users.get("excludeGroups") or [])) + " excludeUsers=" + str(len(users.get("excludeUsers") or [])), "exclusions are the bypass surface")
        flows = cond.get("authenticationFlows") or {}
        raw_methods = dig(flows, "transferMethods")
        methods = [str(x) for x in lst(raw_methods)] if isinstance(raw_methods, list) else ([str(raw_methods)] if raw_methods not in (MISSING, None, "") else [])
        if "deviceCodeFlow" in methods or (enforced and not methods and flows):
            blocks = state == "enabled" and "block" in [b.lower() for b in builtins]
            if blocks:
                restricts_flows = True
            add("info", "ca-device-code-flow-referenced", name, "state=" + str(state) + " transferMethods=" + ",".join(methods) + " blocks=" + str(blocks), "device code flow is named in a policy; only an enforced Block control restricts it")
        locs = cond.get("locations") or {}
        for lid in (locs.get("excludeLocations") or []) if enforced else []:
            if lid == "AllTrusted":
                add("high", "ca-all-trusted-locations-excluded", name, "excludeLocations=AllTrusted", "any trusted IP skips the policy")
            else:
                add("medium", "ca-named-location-excluded", name, "excludeLocations=" + str(lid), "named location exclusion")
        devices = cond.get("devices") or {}
        for dtype in ((devices.get("excludeDevices") or {}).get("trustType") or []) if enforced else []:
            add("high", "ca-trusttype-excluded", name, "excludeDevices.trustType=" + str(dtype), "that device trust class skips the policy")
        if enforced and devices.get("deviceFilter"):
            df = devices.get("deviceFilter") or {}
            add("medium", "ca-device-filter", name, "mode=" + str(df.get("mode")) + " rule=" + str(df.get("rule"))[:60], "device filter decides who is covered; verify the rule")
        device_controls = {"compliantdevice", "domainjoineddevice", "approvedapplication"}
        if enforced and any(str(b).lower() in device_controls for b in builtins):
            requires_device = True
            add("info", "ca-requires-device-state", name, "controls=" + ",".join(builtins), "device state is an authentication factor here")
        sif = sc.get("signInFrequency") or {}
        if enforced and (sif.get("isEnabled") is True or str(sif.get("isEnabled") or "").lower() == "true"):
            has_frequency = True
        if enforced and (cond.get("signInRiskLevels") or cond.get("userRiskLevels")):
            has_risk = True
        sid = (gc.get("authenticationStrength") or {}).get("id")
        if sid:
            if strengths is None:
                continue
            disp, combos = strengths.get(sid, (str(sid), []))
            single = [c for c in combos if "SingleFactor" in c]
            add("medium" if single else "info", "ca-auth-strength", name, "strength=" + str(disp) + " combos=" + ",".join(combos)[:60], "custom authentication strength; verify the combinations")
        if gc.get("operator") == "OR" and len(builtins) > 1:
            add("medium", "ca-grant-operator-or", name, "operator=OR controls=" + ",".join(builtins), "any single control satisfies the policy")
    if pols and not ca_complete():
        capped(CURRENT["check"], len(pols), "conditional access policy pages")
    if pols and ca_complete() and not restricts_flows:
        add("high", "ca-device-code-flow-unrestricted", "tenant", "no policy sets conditions.authenticationFlows", "device code flow issues tokens with password-only authentication")
    if pols and ca_complete() and not has_frequency:
        add("medium", "ca-no-signin-frequency", "tenant", "no sessionControls.signInFrequency", "stolen tokens stay valid for their full lifetime")
    if pols and ca_complete() and not has_risk:
        add("medium", "ca-no-risk-conditions", "tenant", "no signInRiskLevels or userRiskLevels", "no risk-based response; requires P2")
    if pols and ca_complete() and not requires_device:
        add("medium", "ca-no-device-requirement", "tenant", "no policy requires compliant or joined device", "device trust is not an access condition")
    for p in pols:
        for action in ((p.get("conditions") or {}).get("userActions") or []):
            if action in ("urn:user:registersecurityinfo", "urn:user:registerdevice"):
                excl = ((p.get("conditions") or {}).get("users") or {}).get("excludeRoles") or []
                add("high" if excl else "low", "ca-user-action-policy", p.get("displayName"), "action=" + action + " excludeRoles=" + str(len(excl)), "security-info registration can be used to add a persistent MFA method")


@check("entra-x509-method")
def c_x509_method(ctx):
    cfg = graph("policies/authenticationMethodsPolicy/authenticationMethodConfigurations/x509Certificate", beta=True)
    if cfg is None:
        note("entra-x509-method", 0, denied=1)
        return
    note("entra-x509-method", 1)
    if str(cfg.get("state")) != "enabled":
        add("info", "x509-disabled", "tenant", "state=" + str(cfg.get("state")), "certificate-based authentication not in use")
        return
    mode = ((cfg.get("authenticationModeConfiguration") or {}).get("x509CertificateAuthenticationDefaultMode")) or ""
    targets = [t.get("id") for t in (cfg.get("includeTargets") or [])]
    excluded = [t.get("id") for t in (cfg.get("excludeTargets") or [])]
    add("info", "x509-enabled", "tenant", "mode=" + mode + " targets=" + str(len(targets)) + " excluded=" + str(len(excluded)), "certificate authentication is active")
    if "SingleFactor" in mode:
        add("high", "x509-single-factor", "tenant", "defaultMode=" + mode, "one certificate satisfies authentication without a second factor")
    for binding in cfg.get("certificateUserBindings") or []:
        prop = str(binding.get("userProperty") or "")
        if prop in ("onPremisesUserPrincipalName", "onPremisesPkcs15", "alternativeSecurityId"):
            add("medium", "x509-binding-legacy-attribute", "tenant", "userProperty=" + prop, "binding uses a synced attribute that can diverge from the cloud UPN")
    if "all_users" in targets:
        add("medium", "x509-all-users", "tenant", "includeTargets=all_users", "every user may authenticate by certificate")


@check("entra-federation-detail")
def c_fed_detail(ctx):
    rows = graph_all("domains?$select=id,authenticationType", limit=3)
    if rows is None:
        note("entra-federation-detail", 0, denied=1)
        return
    fed = [d for d in rows if str(d.get("authenticationType")).lower() == "federated"]
    note("entra-federation-detail", len(fed))
    for d in fed:
        cfg = graph("domains/" + str(d.get("id")) + "/federationConfiguration", beta=True)
        if cfg is None:
            deny("entra-federation-detail")
            add("info", "federation-not-assessed", d.get("id"), "federationConfiguration unavailable", "issuer and signing certificate not verified")
            continue
        for c in cfg.get("value") or []:
            issuer = c.get("issuerUri")
            certs = [x for x in (c.get("signingCertificate"), c.get("nextSigningCertificate")) if x]
            add("medium", "federated-trust-anchor", d.get("id"), "issuer=" + str(issuer) + " passive=" + str(c.get("passiveSignInUri")), "external STS is the tenant skeleton key; its compromise is tenant compromise")
            if certs:
                add("info", "federation-signing-cert", d.get("id"), "certificates=" + str(len(certs)) + " nextUpdate=" + str(c.get("signingCertificateUpdateStatus")), "token-signing material present")


@check("entra-linked-identities")
def c_linked(ctx):
    users = graph_all("users?$select=userPrincipalName,identities&$top=999", limit=10)
    if users is None:
        note("entra-linked-identities", 0, denied=1)
        return
    note("entra-linked-identities", len(users))
    for u in users:
        for ident in u.get("identities") or []:
            issuer = str(dig(ident, "issuer") or "")
            low = issuer.lower()
            social = ("google", "facebook", "apple", "github", "twitter", "amazon", "linkedin", "microsoftaccount", "live.com", "mail.ru", "vk.com", "weibo", "qq.com")
            if any(t in low for t in social):
                add("high", "federated-identity-link", dig(u, "userPrincipalName"), "issuer=" + issuer + " type=" + str(dig(ident, "signInType")), "a consumer identity provider authenticates this account; its recovery path is outside this tenant")
            elif low and low not in ("externalazuread", "mailboxnotfound") and str(dig(ident, "signInType")) == "federated":
                if tenant_rel(low) == "unknown":
                    undecided("federated-identity-tenant-unknown", "issuer=" + issuer, "the home tenant was not read, so an external issuer cannot be confirmed")
                elif not same_tenant(low):
                    add("medium", "federated-identity-unknown-issuer", dig(u, "userPrincipalName"), "issuer=" + issuer, "an issuer outside this tenant authenticates this account")


@check("entra-stale-privileged")
def c_stale_priv(ctx):
    def_rows = graph_all("roleManagement/directory/roleDefinitions", limit=5)
    asg_rows = graph_all("roleManagement/directory/roleAssignments", limit=5)
    if def_rows is None or asg_rows is None:
        note("entra-stale-privileged", 0, denied=1)
        return
    def_objs = {d.get("id"): d for d in def_rows if d.get("id")}
    holders = {a.get("principalId") for a in asg_rows if is_escalation(def_objs.get(a.get("roleDefinitionId")))}
    if not holders:
        note("entra-stale-privileged", 0)
        return
    users = graph_all("users?$select=id,userPrincipalName,accountEnabled,signInActivity&$top=999", limit=10)
    if users is None:
        note("entra-stale-privileged", 0, denied=1)
        return
    cutoff = time.time() - 90 * 86400
    n = 0
    for u in users:
        if u.get("id") not in holders:
            continue
        n += 1
        if u.get("accountEnabled") is False:
            add("high", "disabled-account-holds-role", u.get("userPrincipalName"), "accountEnabled=false", "assignment survives the disabled account")
            continue
        act = dig(u, "signInActivity")
        last = str(val(dig(act, "lastSignInDateTime"), ""))
        machine = str(val(dig(act, "lastNonInteractiveSignInDateTime"), ""))
        newest = max(_stamp(last) or 0.0, _stamp(machine) or 0.0)
        if not newest:
            add("low", "stale-privileged-unknown", dig(u, "userPrincipalName"), "no signInActivity returned", "activity cannot be read; the account may be dormant")
        elif newest < cutoff:
            add("medium", "stale-privileged-account", dig(u, "userPrincipalName"), "lastSignIn=" + _iso(newest), "privileged account unused for more than 90 days")
    seen_ids = {str(u.get("id")) for u in users}
    non_user = sorted(holders - seen_ids)
    if non_user:
        sps = unread(graph_all("servicePrincipals?$select=id,displayName,servicePrincipalType&$top=999", limit=10),
                     "service principals for privileged holders", "stale-privileged-sps-unreadable")
        groups = unread(graph_all("groups?$select=id,displayName&$top=999", limit=10),
                        "groups for privileged holders", "stale-privileged-groups-unreadable")
        blind = sps is None or groups is None
        kinds = {}
        for s in lst(sps):
            kinds[str(dig(s, "id"))] = str(dig(s, "servicePrincipalType")) or "ServicePrincipal"
        for g in lst(groups):
            kinds[str(dig(g, "id"))] = "Group"
        for pid in non_user:
            kind = kinds.get(pid, "")
            if kind == "Group":
                add("medium", "group-holds-privileged-role", ctx["idx"].resolve(pid) or pid, "principalType=Group", "group-held privilege is not attributed to an individual; membership review decides exposure")
            elif kind == "ManagedIdentity":
                add("low", "managed-identity-holds-privileged-role", ctx["idx"].resolve(pid) or pid, "principalType=ManagedIdentity", "machine identity holds a privileged directory role")
            elif kind:
                add("low", "workload-holds-privileged-role", ctx["idx"].resolve(pid) or pid, "principalType=" + kind, "a workload principal holds a privileged directory role")
            elif not blind:
                add("low", "privileged-principal-type-unknown", str(pid), "principal absent from users, groups and service principals", "the holder could not be classified; confirm the assignment is intentional")
    note("entra-stale-privileged", n)


@check("entra-mfa-registration")
def c_mfa_reg(ctx):
    rows = graph_all("reports/authenticationMethods/userRegistrationDetails?$top=999", limit=10)
    if rows is None:
        note("entra-mfa-registration", 0, denied=1)
        return
    note("entra-mfa-registration", len(rows))
    weak = 0
    for r in rows:
        methods = r.get("methodsRegistered") or []
        strong = [m for m in methods if m in ("fido2", "windowsHelloForBusiness", "x509Certificate", "x509CertificateSingleFactor", "certificateBasedAuthentication")]
        if not strong:
            weak += 1
            add("medium", "no-phishing-resistant-mfa", r.get("userPrincipalName"), "methods=" + ",".join([str(m) for m in methods][:5]), "registration lacks a phishing-resistant method")
    if rows and weak == len(rows):
        add("high", "no-phishing-resistant-mfa-tenant", "tenant", str(weak) + "/" + str(len(rows)) + " users", "no user has a phishing-resistant method")


@check("entra-licences")
def c_skus(ctx):
    rows = graph_all("subscribedSkus", limit=3)
    if rows is None:
        note("entra-licences", 0, denied=1)
        return
    note("entra-licences", len(rows))
    names = []
    for sku in rows:
        part = str(sku.get("skuPartNumber") or "")
        names.append(part + "=" + str(sku.get("consumedUnits")) + "/" + str((sku.get("prepaidUnits") or {}).get("enabled")))
        if part in ("AAD_PREMIUM_P2", "EMSPREMIUM", "IDENTITY_THREAT_PROTECTION", "SPE_E5"):
            add("info", "p2-licensed", part, "consumed=" + str(sku.get("consumedUnits")), "P2 features available: PIM, risk, access reviews")
    add("info", "licence-inventory", "tenant", " ".join(names)[:120] or "no SKU rows returned", "licence mix determines which controls are possible")
    if not rows:
        add("low", "licence-unreadable", "tenant", "0 SKU rows returned", "the licence mix cannot be assessed; P2-only controls may exist")
    elif not any("P2" in n or "E5" in n or "THREAT_PROTECTION" in n or "EMSPREMIUM" in n or "EMS_PREMIUM" in n for n in names):
        add("medium", "no-p2-licence", "tenant", "SKUs=" + " ".join(names)[:100], "no PIM, access reviews, or risk-based CA possible")


@check("entra-audit-signals")
def c_audit_signals(ctx):
    since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 30 * 86400))
    signins = graph_all("auditLogs/signIns?$filter=createdDateTime ge " + since + "&$top=999", limit=5, beta=True)
    if signins is None:
        note("entra-audit-signals", 0, denied=1)
        return
    def succeeded(entry):
        code = dig(entry, "status.errorCode")
        if code is MISSING or code is None:
            return False
        return num(code, 1) == 0

    legacy_all = [s for s in signins if str(dig(s, "clientAppUsed")) in ("IMAP", "POP", "SMTP", "Authenticated SMTP", "Other clients", "Exchange ActiveSync")]
    legacy = [s for s in legacy_all if succeeded(s)]
    blocked = len(legacy_all) - len(legacy)
    for s in legacy[:20]:
        add("high", "legacy-auth-signin", dig(s, "userPrincipalName"), "clientApp=" + str(dig(s, "clientAppUsed")) + " at=" + str(dig(s, "createdDateTime")), "legacy authentication succeeded; it bypasses MFA-capable clients")
    if blocked:
        add("info", "legacy-auth-attempts-blocked", "tenant", "attempts=" + str(len(legacy_all)) + " blocked=" + str(blocked), "legacy clients tried and were refused; the block is working")
    devicecode = [s for s in signins if str(val(dig(s, "authenticationProtocol"), "")).lower() in ("devicecode", "devicecodeflow") and succeeded(s)]
    for s in devicecode[:10]:
        add("high", "device-code-signin", s.get("userPrincipalName"), "protocol=deviceCode at=" + str(s.get("createdDateTime")), "device code grant used; the password alone authenticates")
    if devicecode:
        add("high", "device-code-flow-in-use", "tenant", "signIns=" + str(len(devicecode)), "the flow that bypasses MFA is actively used")
    audits = graph_all("auditLogs/directoryAudits?$filter=activityDateTime ge " + since + "&$top=999", limit=5)
    if audits is None:
        deny("entra-audit-signals")
        return
    note("entra-audit-signals", len(signins) + len(audits))
    watched = ("Add service principal credentials", "Add federated identity credential", "Consent to application", "Add member to role", "Reset password", "Update user")
    for a in audits:
        act = str(a.get("activityDisplayName") or "")
        if act in watched:
            actor = ((a.get("initiatedBy") or {}).get("user") or {}).get("userPrincipalName") or ((a.get("initiatedBy") or {}).get("app") or {}).get("displayName")
            add("info", "privileged-audit-event", act, "actor=" + str(actor) + " at=" + str(a.get("activityDateTime")), "high-signal event present in the audit trail")
    if not audits:
        add("medium", "no-directory-audit-events", "tenant", "0 events in 30 days", "either no changes occurred or auditing is not retained")


@check("entra-cross-tenant-partners")
def c_partners(ctx):
    rows = graph_all("policies/crossTenantAccessPolicy/partners", limit=5)
    if rows is None:
        note("entra-cross-tenant-partners", 0, denied=1)
        return
    note("entra-cross-tenant-partners", len(rows))
    for p in rows:
        trust = dig(p, "inboundTrust")
        mfa = tri(dig(trust, "isMfaAccepted")) is True
        compliant = tri(dig(trust, "isCompliantDeviceAccepted")) is True
        hybrid = tri(dig(trust, "isHybridAzureADJoinedDeviceAccepted")) is True
        if mfa or compliant or hybrid:
            add("high", "partner-trust-accepted", dig(p, "tenantId"), "mfa=" + str(mfa) + " compliantDevice=" + str(compliant) + " hybridJoinedDevice=" + str(hybrid), "a named external tenant satisfies your authentication or device policy")
        add("info", "cross-tenant-partner", p.get("tenantId"), "b2bInbound=" + str(bool(p.get("b2bCollaborationInbound"))), "per-partner configuration present")


ROLE_TEMPLATE_IDS = {
    "62e90394-69f5-4237-9190-012177145e10": "GA",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "PRA",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "PAA",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "AppAdmin",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "CloudAppAdmin",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "AuthAdmin",
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": "HybridAdmin",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "UserAdmin",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "CAAdmin",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "SecAdmin",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "ExoAdmin",
}


def is_escalation(role):
    template = str((role or {}).get("templateId") or "").lower()
    if template in ROLE_TEMPLATE_IDS:
        return True
    return str((role or {}).get("displayName") or "") in ESCALATION_ROLES


ESCALATION_ROLES = (
    "Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator",
    "Application Administrator", "Cloud Application Administrator", "Authentication Administrator",
    "Hybrid Identity Administrator", "User Administrator", "Helpdesk Administrator",
    "Conditional Access Administrator", "Security Administrator", "Exchange Administrator",
    "SharePoint Administrator", "Groups Administrator", "Directory Synchronization Accounts",
)


@check("entra-escalation-roles")
def c_escalation(ctx):
    defs = graph_all("roleManagement/directory/roleDefinitions", limit=5)
    if defs is None:
        note("entra-escalation-roles", 0, denied=1)
        return
    privileged = {d.get("id"): d for d in defs if d.get("id") and is_escalation(d)}
    assignments = graph_all("roleManagement/directory/roleAssignments", limit=5)
    if assignments is None:
        note("entra-escalation-roles", 0, denied=1)
        return
    note("entra-escalation-roles", len(assignments))
    holders = defaultdict(list)
    for a in assignments:
        rid = a.get("roleDefinitionId")
        if rid in privileged:
            holders[rid].append(a.get("principalId"))
    for rid, pids in holders.items():
        role_def = privileged.get(rid) or {}
        template = str(role_def.get("templateId") or "").lower()
        critical = template in ("62e90394-69f5-4237-9190-012177145e10", "e8611ab8-c189-46e8-94e1-60213ab1f814", "7be44c8a-adaf-4e2a-84d6-ab2649e08a13", "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2")
        add("critical" if critical else "high", "escalation-role-holders", str(role_def.get("displayName") or rid), "holders=" + str(len(pids)) + " first=" + str(ctx["idx"].resolve(pids[0]) or pids[0]), "this role leads to app takeover, credential reset, or full control")


@check("entra-graph-permissions")
def c_graph_perms(ctx):
    sp = graph("servicePrincipals?$filter=appId eq '" + GRAPH_APP_ID + "'&$select=id,appRoles")
    if sp is None or not lst(dig(sp, "value")):
        note("entra-graph-permissions", 0, denied=1)
        return
    role_names = {r.get("id"): r.get("value") for r in (sp["value"][0].get("appRoles") or [])}
    sps = graph_all("servicePrincipals?$select=id,displayName", limit=10)
    if sps is None:
        deny("entra-graph-permissions")
        return
    checked = 0
    for s in sps[:25]:
        doc = graph("servicePrincipals/" + str(s.get("id")) + "/appRoleAssignments")
        if doc is None:
            deny("entra-graph-permissions")
            continue
        checked += 1
        perms = []
        for a in doc.get("value") or []:
            nm = role_names.get(a.get("appRoleId"))
            if nm:
                perms.append(nm)
        dangerous = [x for x in perms if x in GRAPH_DANGEROUS]
        if dangerous:
            add("high", "sp-holds-graph-application-permission", s.get("displayName"), "permissions=" + ",".join(sorted(set(dangerous))), "application permission runs without a user and needs no consent at runtime")
    note("entra-graph-permissions", checked)
    sample("entra-graph-permissions", min(len(sps), 25), len(sps), "service principals")


@check("entra-uami-fic")
def c_uami_fic(ctx):
    rows = graph_all("servicePrincipals?$filter=servicePrincipalType eq 'ManagedIdentity'&$select=id,displayName", limit=10)
    if rows is None:
        note("entra-uami-fic", 0, denied=1)
        return
    note("entra-uami-fic", min(len(rows), 25))
    sample("entra-uami-fic", min(len(rows), 25), len(rows), "managed identities")
    for sp in rows[:25]:
        doc = graph("servicePrincipals/" + str(sp.get("id")) + "/federatedIdentityCredentials", beta=True)
        if doc is None:
            deny("entra-uami-fic")
            continue
        for fic in doc.get("value") or []:
            sub = str(fic.get("subject") or "")
            issuer = str(fic.get("issuer") or "")
            wildcard = "*" in sub
            first_party = issuer.startswith("https://token.actions.githubusercontent.com")
            branch_only = first_party and ":ref:refs/heads/" in sub and "environment:" not in sub
            foreign_issuer = bool(issuer) and not any(issuer.startswith(k) for k in KNOWN_FIC_ISSUERS)
            sev = "high" if (wildcard or foreign_issuer) else ("medium" if branch_only else "low")
            if wildcard:
                why = "subject wildcard: any subject matching the pattern can mint a token"
            elif foreign_issuer:
                why = "issuer is not the first-party GitHub token service; compare it byte for byte"
            elif branch_only:
                why = "branch-scoped subject: any workflow in the repository can use it"
            else:
                why = "environment-scoped or otherwise narrow subject"
            add(sev, "uami-federated-credential", sp.get("displayName"), "issuer=" + issuer + " subject=" + sub, why)


@check("entra-identity-protection")
def c_idp(ctx):
    risky = graph_all("identityProtection/riskyUsers?$filter=riskState eq 'atRisk' or riskState eq 'confirmedCompromised'", limit=5, beta=True)
    dets = graph_all("identityProtection/riskDetections?$top=100", limit=3, beta=True)
    if risky is None and dets is None:
        note("entra-identity-protection", 0, denied=1)
        add("info", "identity-protection-unavailable", "tenant", "endpoint unavailable", "requires P2; leaked-credential detection not assessed")
        return
    if risky is None or dets is None:
        deny("entra-identity-protection")
    note("entra-identity-protection", len(lst(risky)) + len(lst(dets)))
    for u in lst(risky):
        compromised = str(dig(u, "riskState") or "").lower() == "confirmedcompromised"
        add("critical" if compromised else "high", "risky-user-confirmed-compromised" if compromised else "risky-user-at-risk", dig(u, "userPrincipalName"), "riskLevel=" + str(dig(u, "riskLevel")) + " state=" + str(dig(u, "riskState")), "compromise is confirmed and the account is still active" if compromised else "detected compromise not remediated")
    kinds = Counter(str(d.get("riskEventType")) for d in lst(dets))
    for k, v in kinds.most_common(8):
        add("info", "risk-detection", k, "count=" + str(v), "risk signal observed in the tenant")


@check("entra-pim-depth")
def c_pim_depth(ctx):
    elig = graph_all("roleManagement/directory/roleEligibilityScheduleInstances", limit=5, beta=True)
    active = graph_all("roleManagement/directory/roleAssignmentScheduleInstances", limit=5, beta=True)
    if active is None:
        note("entra-pim-depth", 0, denied=1)
        return
    note("entra-pim-depth", len(active))
    if elig is None:
        add("info", "pim-depth-partial", "tenant", "eligibility endpoint denied", "permanent vs eligible split not computed")
        return
    perm = Counter()
    for a in active:
        if str(a.get("assignmentType")) == "Assigned":
            perm[a.get("roleDefinitionId")] += 1
    eligible_ids = {e.get("roleDefinitionId") for e in elig}
    for rid, cnt in perm.items():
        if rid not in eligible_ids:
            add("medium", "role-permanent-no-eligible-path", rid, "permanent=" + str(cnt), "no PIM path exists for this role; every holder is standing")


@check("entra-authenticator-features")
def c_auth_features(ctx):
    pol = graph("policies/authenticationMethodsPolicy")
    if pol is None:
        note("entra-authenticator-features", 0, denied=1)
        return
    note("entra-authenticator-features", 1)
    for cfg in pol.get("authenticationMethodConfigurations") or []:
        if "microsoftAuthenticator" not in str(cfg.get("@odata.type")):
            continue
        fs = cfg.get("featureSettings") or {}
        for key, label in (("numberMatchingRequiredState", "number matching"), ("displayAppInformationRequiredState", "app name shown"), ("displayLocationInformationRequiredState", "location shown")):
            st = str((fs.get(key) or {}).get("state") or "").lower()
            if st in ("disabled",):
                add("medium", "authenticator-feature-off", label, key + "=" + st, "push approval without context enables MFA fatigue")
            elif st in ("", "default"):
                add("info", "authenticator-feature-default", label, key + "=" + (st or "unset"), "Microsoft enforces this feature by default; confirm no policy overrides it")


@check("entra-external-identity")
def c_extid(ctx):
    flows = graph("policies/authenticationFlowsPolicy")
    if flows is None:
        note("entra-external-identity", 0, denied=1)
        return
    note("entra-external-identity", 1)
    self_service = ((flows.get("selfServiceSignUp") or {}).get("isEnabled"))
    if self_service:
        add("high", "self-service-signup-enabled", "tenant", "selfServiceSignUp.isEnabled=true", "anyone can create a guest identity without an invitation")
    idps = unread(graph_all("identity/identityProviders", limit=3), "identity providers", "external-idp-unreadable")
    external = [] if idps is None else [i for i in idps if str(i.get("identityProviderType") or "").lower() in ("google", "facebook", "microsoftaccount", "amazon", "linkedin", "twitter")]
    for i in external:
        add("medium", "social-idp-configured", i.get("displayName"), "type=" + str(i.get("identityProviderType")), "a social identity provider authenticates users")
    if idps:
        note("entra-external-identity", len(idps))
        if not external:
            add("info", "external-idp-inventory", "tenant", "providers=" + ",".join([str(i.get("identityProviderType")) for i in idps][:6]), "no social provider beyond built-in email OTP and SAML")


@check("entra-ca-workload")
def c_ca_workload(ctx):
    pols = ca_all("policies", limit=5)
    if pols is None:
        note("entra-ca-workload", 0, denied=1)
        return
    note("entra-ca-workload", len(pols))
    wp = [p for p in pols if ((p.get("conditions") or {}).get("clientApplications") or (p.get("conditions") or {}).get("servicePrincipalFilter"))]
    if not wp:
        add("medium", "no-workload-identity-ca", "tenant", "0 policies target service principals", "workload identities bypass every user policy")
    for p in wp:
        add("info", "workload-identity-policy", p.get("displayName"), "state=" + str(p.get("state")), "policy covers service principal sign-ins")


@check("entra-ca-session")
def c_ca_session(ctx):
    pols = ca_all("policies", limit=5)
    if pols is None:
        note("entra-ca-session", 0, denied=1)
        return
    note("entra-ca-session", len(pols))
    token_protection = 0
    browser = 0
    casb = 0
    for p in pols:
        sc = p.get("sessionControls") or {}
        sss = sc.get("secureSignInSession") or {}
        tprot = sc.get("tokenProtection") or {}
        sss_on = tri(sss.get("isEnabled") if isinstance(sss, dict) else sss) is True
        tprot_on = tri(tprot.get("isEnabled") if isinstance(tprot, dict) else tprot) is True
        if sss_on or tprot_on:
            token_protection += 1
            add("info", "session-token-protection", p.get("displayName"), "secureSignInSession=true", "token protection active")
        if tri(dig(sc, "persistentBrowser.isEnabled")) is True or str(val(dig(sc, "persistentBrowser.mode"), "")).lower() == "never":
            browser += 1
        if tri(dig(sc, "cloudAppSecurity.isEnabled")) is True:
            casb += 1
        if sc.get("continuousAccessEvaluation"):
            add("info", "session-cae", p.get("displayName"), "continuousAccessEvaluation=" + str(sc.get("continuousAccessEvaluation")), "near-real-time revocation")
    if not token_protection:
        add("medium", "no-token-protection", "tenant", "0 policies with secureSignInSession", "a stolen token can be replayed from any device; requires P2")
    if not browser:
        add("low", "no-persistent-browser-control", "tenant", "0 policies with persistentBrowser", "browser session persistence uncontrolled")
    if not casb:
        add("info", "no-casb-session-control", "tenant", "0 policies with cloudAppSecurity", "no session proxy control")


@check("entra-breakglass")
def c_breakglass(ctx):
    idx = ctx["idx"]
    pols = ca_all("policies", limit=5)
    if pols is None:
        note("entra-breakglass", 0, denied=1)
        add("info", "breakglass-ca-unreadable", "tenant", "conditional access unreadable", "exclusion set unknown")
        return
    excluded = set()
    excluded_dead = set()
    for p in pols:
        target = excluded if p.get("state") == "enabled" else excluded_dead
        target.update(((p.get("conditions") or {}).get("users") or {}).get("excludeUsers") or [])
    note("entra-breakglass", len(excluded))
    if excluded_dead - excluded:
        add("info", "breakglass-excluded-only-in-dead-policy", "tenant", "accounts=" + str(len(excluded_dead - excluded)), "those exclusions apply to no enforced policy")
    add("info", "breakglass-exclusion-scope", "tenant", "excludedFromEnabledPolicies=" + str(len(excluded)) + " enabledPolicies=" + str(len([p for p in pols if str(dig(p, "state")) == "enabled"])), "an exclusion set is measured per policy; being excluded from one policy is not being excluded from all")
    candidates = []
    named = []
    for u in idx.users():
        p = idx.props(u)
        name = str(p.get("displayName") or "").lower()
        if u.get("id") in excluded:
            named.append(u)
        if any(t in name for t in ("break", "emergency", "notfall", "sos", "fallback")):
            candidates.append(u)
    if not candidates and named:
        candidates = named
        add("info", "breakglass-exclusion-only", "tenant", "accounts=" + str(len(named)), "candidates identified by policy exclusion, not by naming")
    if not candidates:
        if idx.users():
            add("medium", "no-breakglass-account", "tenant", "0 accounts matching emergency naming in the dataset", "recovery depends on an undocumented account")
        else:
            add("info", "breakglass-not-assessed", "tenant", "no user objects in the dataset", "emergency account detection needs user data")
    for u in candidates:
        p = idx.props(u)
        synced = tri(dig(p, "onPremisesSyncEnabled"))
        cloud = synced is False
        ex = u.get("id") in excluded
        shown_cloud = "unknown" if synced is None else str(cloud)
        add("info", "breakglass-account", dig(p, "displayName"), "cloudOnly=" + shown_cloud + " caExcluded=" + str(ex) + " enabled=" + str(dig(p, "accountEnabled")), "verify credential custody and alerting")
        if ex and cloud:
            add("low", "breakglass-ca-excluded", p.get("displayName"), "excludedFromAtLeastOneEnabledPolicy", "an unmonitored path around that policy if the credential leaks")


@check("entra-ca-roles")
def c_ca_roles(ctx):
    pols = ca_all("policies", limit=5)
    if pols is None:
        note("entra-ca-roles", 0, denied=1)
        return
    note("entra-ca-roles", len(pols))
    targeted = 0
    for p in pols:
        roles = ((p.get("conditions") or {}).get("users") or {}).get("includeRoles") or []
        if roles:
            targeted += 1
            add("info", "ca-targets-roles", p.get("displayName"), "includeRoles=" + str(len(roles)) + " state=" + str(p.get("state")), "role-targeted policy; verify every privileged role is listed")
    if not targeted:
        enabled = [p for p in pols if str(dig(p, "state")) == "enabled"]
        if not enabled:
            add("medium", "ca-no-role-targeting", "tenant", "policies=" + str(len(pols)) + " enabled=0", "no policy constrains privileged roles; the tenant has no enforced policy at all")
        else:
            add("medium", "ca-no-role-targeting", "tenant", "policies=" + str(len(pols)) + " enabled=" + str(len(enabled)) + " roleTargeted=0", "privileged accounts are covered only by user-wide rules")


@check("entra-cba-config")
def c_cba(ctx):
    org = graph("organization")
    if org is None:
        note("entra-cba-config", 0, denied=1)
        return
    orgs = lst(dig(org, "value"))
    note("entra-cba-config", len(orgs))
    if not orgs:
        return
    oid = dig(orgs[0], "id")
    cert = graph("organization/" + str(oid) + "/certificateBasedAuthConfiguration")
    if cert is None:
        add("info", "cba-not-assessed", "tenant", "certificateBasedAuthConfiguration unavailable", "certificate trust anchors not assessed")
        return
    items = cert.get("value") or []
    if not items:
        add("info", "cba-none", "tenant", "0 certificate authorities", "certificate-based authentication not configured")
    for item in items:
        cas = (item.get("certificateAuthorities") or [])
        for ca in cas:
            end = str(ca.get("endDate") or "")
            expired = _expired(end)
            sev = "medium" if expired else "info"
            label = "cba-authority-expired" if expired else ("cba-authority-expiry-unknown" if expired is None else "cba-authority")
            add(sev, label, ca.get("displayName"), "trusted CA endDate=" + end + " isRootAuthority=" + str(ca.get("isRootAuthority")), "expired trust anchor still listed" if expired else ("the trust anchor end date could not be parsed" if expired is None else "any certificate from this CA authenticates a user"))


@check("entra-auth-methods-detail")
def c_authmethods_detail(ctx):
    pol = graph("policies/authenticationMethodsPolicy")
    if pol is None:
        note("entra-auth-methods-detail", 0, denied=1)
        return
    note("entra-auth-methods-detail", 1)
    reg = pol.get("registrationEnforcement") or {}
    campaign = reg.get("authenticationMethodsRegistrationCampaign") or {}
    if campaign.get("state") != "enabled":
        add("low", "no-registration-campaign", "tenant", "campaign state=" + str(campaign.get("state")), "no nudge toward phishing-resistant methods")
    for cfg in pol.get("authenticationMethodConfigurations") or []:
        mid = str(cfg.get("@odata.type") or "").split(".")[-1]
        if mid == "temporaryAccessPassAuthenticationMethodConfiguration" and str(cfg.get("state") or "").lower() == "enabled":
            code = cfg.get("codeConfiguration") or cfg
            groups = [t.get("id") for t in (cfg.get("includeTargets") or []) if str(t.get("targetType")) == "group"]
            once = tri(code.get("isUsableOnce"))
            raw_minutes = str(code.get("defaultLifetimeInMinutes") or "")
            minutes = int(raw_minutes) if raw_minutes.isdigit() else None
            sev = "high" if once is not True or (minutes is not None and minutes > 60) else "medium"
            add(sev, "tap-enabled-scope", mid, "state=enabled lifetime=" + str(code.get("defaultLifetimeInMinutes")) + " oneTime=" + str(code.get("isUsableOnce")) + " groups=" + str(len(groups)), "temporary access pass can bypass MFA registration; review issuers and lifetime")
        if mid in ("fido2AuthenticationMethodConfiguration", "microsoftAuthenticatorAuthenticationMethodConfiguration"):
            modes = cfg.get("isSelfServiceRegistrationAllowed")
            add("info", "strong-method", mid, "state=" + str(cfg.get("state")) + " selfService=" + str(modes), "strong method availability")


@check("entra-named-locations")
def c_locations(ctx):
    rows = ca_all("locations", limit=3)
    if rows is None:
        note("entra-named-locations", 0, denied=1)
        return
    note("entra-named-locations", len(rows))
    for loc in rows:
        ranges = loc.get("ipRanges") or []
        countries = loc.get("countriesAndRegions") or []
        def _private(cidr):
            head = str(cidr).split("/")[0]
            return head.startswith("10.") or head.startswith("192.168.") or (head.startswith("172.") and head.split(".")[1].isdigit() and 16 <= int(head.split(".")[1]) <= 31)
        wide = [r for r in ranges if (str(r).endswith("/0") or str(r) in ("0.0.0.0/0", "*")) or (str(r).endswith("/8") and not _private(r))]
        add("info", "named-location", loc.get("displayName"), "ranges=" + str(len(ranges)) + " countries=" + str(len(countries)), "inventory item")
        if wide:
            add("high", "named-location-wide-range", loc.get("displayName"), "wide=" + ",".join(wide[:3]), "location covers far more addresses than intended")
        if countries:
            add("medium", "named-location-country", loc.get("displayName"), "countries=" + ",".join(countries[:6]), "country-based trust is weak against VPN and cloud egress")


@check("entra-security-defaults")
def c_secdefaults(ctx):
    pol = graph("policies/identitySecurityDefaultsEnforcementPolicy")
    if pol is None:
        note("entra-security-defaults", 0, denied=1)
        return
    note("entra-security-defaults", 1)
    enabled = pol.get("isEnabled")
    ca = ctx.get("ca")
    if ca is None:
        ca = ca_all("policies", limit=3)
    if ca is None:
        note("entra-security-defaults", 1, denied=1)
        add("info", "ca-unreadable", "tenant", "isEnabled=" + str(enabled) + " CA unreadable", "cannot tell whether a policy enforces MFA")
        return
    enforced = [p for p in ca if p.get("state") == "enabled"]
    ca_count = len(ca)
    add("info", "security-defaults", "tenant", "isEnabled=" + str(enabled) + " caPolicies=" + str(ca_count) + " enforced=" + str(len(enforced)), "mutually exclusive with CA")
    if not enabled and not enforced:
        add("info", "no-mfa-baseline", "tenant", "security defaults off, enforced policies=0", "see entra-mfa-baseline for the tenant-wide MFA verdict")
    elif not enabled:
        add("info", "ca-enforced-policy-count", "tenant", "enforced=" + str(len(enforced)), "MFA sufficiency is decided by entra-mfa-baseline")


@check("entra-apps")
def c_apps(ctx):
    apps = graph_all("applications?$select=appId,id,displayName,api,identifierUris,web,spa,publicClient,passwordCredentials,keyCredentials,requiredResourceAccess", limit=10)
    if apps is None:
        note("entra-apps", 0, denied=1)
        return
    note("entra-apps", len(apps))
    seen_uri = defaultdict(list)
    now = time.time()
    sample("entra-apps", min(len(apps), 15), len(apps), "applications")
    for a in apps[:15]:
        name = str(val(dig(a, "displayName"), val(dig(a, "appId"), "unnamed")))
        fic_doc = graph("applications/" + str(val(dig(a, "id"), "")) + "/federatedIdentityCredentials", beta=True)
        if fic_doc is None:
            denied_now("entra-apps")
        for fic in lst(dig(fic_doc, "value")):
            sub = str(fic.get("subject") or "")
            risky = "*" in sub or sub.endswith(":*") or "pull_request" in sub
            add("high" if risky else "low", "federated-identity-credential", name, "issuer=" + str(fic.get("issuer")) + " subject=" + sub, "workload identity trusted on an external issuer")
        for uri in a.get("identifierUris") or []:
            seen_uri[uri.lower()].append(name)
        api = a.get("api") or {}
        if api.get("knownClientApplications") or api.get("preAuthorizedApplications"):
            add("medium", "app-preauthorization-chain", name, "known=" + str(len(api.get("knownClientApplications") or [])) + " preauth=" + str(len(api.get("preAuthorizedApplications") or [])), "consent to one app can grant another app's permissions")
        for uri in (a.get("web") or {}).get("redirectUris") or []:
            if "*" in uri or uri.startswith("http://"):
                add("medium", "app-redirect-uri-weak", name, uri, "token capture if the endpoint is attacker-controlled")
        rra = a.get("requiredResourceAccess") or []
        for res in rra:
            if str(res.get("resourceAppId")) == GRAPH_APP_ID:
                roles = [x for x in (res.get("resourceAccess") or []) if x.get("type") == "Role"]
                if len(roles) >= 3:
                    add("medium", "app-graph-application-permissions", name, "graph app roles requested=" + str(len(roles)), "application permissions need admin consent and run without a user")
        for cred in a.get("passwordCredentials") or []:
            end = cred.get("endDateTime") or ""
            if end and _expired(end) is None:
                add("low", "app-secret-expiry-unreadable", name, "secret=" + str(cred.get("displayName")) + " end=" + end, "the end date could not be parsed; expiry is unknown")
            elif end and _expired(end):
                add("medium", "app-secret-expired", name, "secret=" + str(cred.get("displayName")) + " end=" + end, "expired credential still present; rotation not completed")
            elif end:
                try:
                    yrs = (calendar.timegm(time.strptime(end[:10], "%Y-%m-%d")) - now) / 31536000.0
                except ValueError:
                    yrs = 0
                if yrs > 2:
                    add("low", "app-secret-long-lived", name, "secret=" + str(cred.get("displayName")) + " years=" + str(round(yrs, 1)), "credential outlives a normal rotation cycle")
        for cred in a.get("keyCredentials") or []:
            end = cred.get("endDateTime") or ""
            if end and _expired(end) is None:
                add("low", "app-cert-expiry-unreadable", name, "cert=" + str(cred.get("displayName")) + " end=" + end, "the end date could not be parsed; expiry is unknown")
            elif end and _expired(end):
                add("low", "app-cert-expired", name, "cert=" + str(cred.get("displayName")) + " end=" + end, "expired certificate still registered")
    for uri, names in seen_uri.items():
        if len(set(names)) > 1:
            add("medium", "app-audience-collision", uri, "apps=" + ",".join(sorted(set(names))), "two apps claim the same identifier; audience validation ambiguity")


@check("entra-saml-certs")
def c_saml(ctx):
    sps = graph_all("servicePrincipals?$select=id,displayName,preferredSingleSignOnMode", limit=10)
    if sps is None:
        note("entra-saml-certs", 0, denied=1)
        return
    saml = [s for s in sps if str(s.get("preferredSingleSignOnMode") or "") in ("saml", "wsFed")]
    note("entra-saml-certs", len(saml))
    for sp in saml[:20]:
        LAST_QUERY[CURRENT["check"]] = "az rest --url " + repr(GRAPH_BASE + "/v1.0/servicePrincipals/" + str(dig(sp, "id")) + "/samlSigningCertificates")
        certs = graph("servicePrincipals/" + str(sp.get("id")) + "/samlSigningCertificates")
        if certs is None:
            denied_now("entra-saml-certs")
            continue
        for c in certs.get("value") or []:
            status = str(c.get("status") or "")
            if status.lower() == "active":
                notif = c.get("notificationEmail")
                end = str(c.get("endDateTime") or "")
                if not notif:
                    add("medium", "saml-cert-no-notification", sp.get("displayName"), "thumbprint=" + str(c.get("thumbprint"))[:12] + " end=" + end, "expiry warning has no recipient; SAML breaks silently")
                if end and _expired(end) is None:
                    add("low", "saml-cert-expiry-unreadable", sp.get("displayName"), "end=" + end, "the certificate end date could not be parsed; expiry is unknown")
                elif end and _expired(end):
                    add("high", "saml-cert-expired", sp.get("displayName"), "end=" + end, "active signing certificate expired; token validation fails")
    sample("entra-saml-certs", min(len(saml), 20), len(saml), "SAML apps")


@check("entra-app-signing")
def c_app_signing(ctx):
    apps = graph_all("applications?$select=appId,displayName,signInAudience,keyCredentials,spa", limit=10)
    if apps is None:
        note("entra-app-signing", 0, denied=1)
        return
    note("entra-app-signing", len(apps))
    for a in apps:
        name = a.get("displayName") or a.get("appId")
        multi = str(a.get("signInAudience") or "") in ("AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount")
        for k in a.get("keyCredentials") or []:
            if str(k.get("usage") or "").lower() == "sign":
                sev = "high" if multi else "medium"
                add(sev, "app-signing-key", name, "key=" + str(k.get("displayName")) + " multiTenant=" + str(multi), "the app can mint tokens for its own API; multi-tenant widens the audience")
        for uri in (a.get("spa") or {}).get("redirectUris") or []:
            if uri.startswith("http://") or "*" in uri:
                add("medium", "app-spa-redirect-weak", name, uri, "SPA redirect target is insecure or wildcarded")


@check("entra-app-proxy")
def c_app_proxy(ctx):
    sps = graph_all("servicePrincipals?$select=id,displayName", limit=10)
    if sps is None:
        note("entra-app-proxy", 0, denied=1)
        return
    note("entra-app-proxy", len(sps))
    found = 0
    for sp in sps[:15]:
        doc = graph("servicePrincipals/" + str(sp.get("id")) + "/onPremisesPublishing", beta=True)
        if doc is None:
            denied_now("entra-app-proxy")
            continue
        if not doc:
            continue
        found += 1
        preauth = str(val(dig(doc, "externalAuthenticationType"), "unknown"))
        passthrough = preauth.lower() in ("passthru", "passthrough", "none")
        add("critical" if passthrough else "medium", "app-proxy-passthrough" if passthrough else "app-proxy-published", sp.get("displayName"), "externalUrl=" + str(dig(doc, "externalUrl")) + " preauth=" + preauth, "no authentication in front of the published internal service" if passthrough else "publishes an internal service to the internet behind Entra authentication")
    if not found:
        add("info", "no-app-proxy", "tenant", "0 published applications", "no on-premises publishing path")
    sample("entra-app-proxy", min(len(sps), 15), len(sps), "service principals")


@check("entra-scim-jobs")
def c_scim(ctx):
    sps = graph_all("servicePrincipals?$select=id,displayName", limit=10)
    if sps is None:
        note("entra-scim-jobs", 0, denied=1)
        return
    note("entra-scim-jobs", len(sps))
    for sp in sps[:15]:
        doc = graph("servicePrincipals/" + str(sp.get("id")) + "/synchronization/jobs", beta=True)
        if doc is None:
            denied_now("entra-scim-jobs")
            continue
        for job in doc.get("value") or []:
            add("medium", "scim-provisioning-job", sp.get("displayName"), "template=" + str(job.get("templateId")) + " status=" + str((job.get("status") or {}).get("code")), "provisioning holds a credential to an external system")
    sample("entra-scim-jobs", min(len(sps), 15), len(sps), "service principals")


@check("entra-sp-dormant")
def c_sp_dormant(ctx):
    rows = graph_all("reports/servicePrincipalSignInActivities", limit=10, beta=True)
    if rows is None:
        note("entra-sp-dormant", 0, denied=1)
        return
    note("entra-sp-dormant", len(rows))
    cutoff = time.time() - 90 * 86400
    for r in rows:
        last = dig(r, "lastSignInActivity")
        ts = str(val(dig(last, "lastSignInDateTime"), ""))
        app_ts = str(val(dig(r, "appOnlyLastSignInActivity.lastSignInDateTime"), ""))
        newest = max(_stamp(ts) or 0.0, _stamp(app_ts) or 0.0)
        if not newest:
            add("low", "sp-never-signed-in", dig(r, "appId"), "no delegated or app-only signInActivity", "the principal holds permissions but never authenticates")
        elif newest < cutoff:
            add("low", "sp-unused", dig(r, "appId"), "lastSignIn=" + _iso(newest), "app unused for 90 days; candidate for removal")


@check("entra-app-owned-by-sp")
def c_app_sp_owner(ctx):
    apps = graph_all("applications?$select=appId,displayName", limit=10)
    if apps is None:
        note("entra-app-owned-by-sp", 0, denied=1)
        return
    note("entra-app-owned-by-sp", len(apps))
    for a in apps[:15]:
        owners = graph("applications(appId='" + str(dig(a, "appId")) + "')/owners?$select=id,displayName,userPrincipalName")
        if owners is None:
            denied_now("entra-app-owned-by-sp")
            continue
        kinded = [(str(dig(o, "@odata.type") or "").lower(), o) for o in lst(dig(owners, "value"))]
        sps = [o for k, o in kinded if k.endswith("serviceprincipal")]
        groups = [o for k, o in kinded if k.endswith("group")]
        if sps:
            add("medium", "app-owned-by-service-principal", dig(a, "displayName"), "owners=" + ",".join([str(dig(o, "displayName")) for o in sps][:3]), "a machine identity controls an app registration and its credentials")
        if groups:
            add("low", "app-owned-by-group", a.get("displayName"), "groups=" + ",".join([str(o.get("displayName")) for o in groups][:3]), "any group member can take over the app registration")
    sample("entra-app-owned-by-sp", min(len(apps), 15), len(apps), "applications")


@check("entra-nested-role-groups")
def c_nested(ctx):
    idx = ctx["idx"]
    assignments = graph_all("roleManagement/directory/roleAssignments", limit=5)
    if assignments is None:
        note("entra-nested-role-groups", 0, denied=1)
        return
    holders = {a.get("principalId") for a in assignments}
    if not holders:
        note("entra-nested-role-groups", 0)
        return
    n = 0
    for g in idx.groups():
        gid = g.get("id")
        if gid not in holders:
            continue
        members = graph("groups/" + str(gid) + "/transitiveMembers?$select=id,displayName")
        if members is None:
            deny("entra-nested-role-groups")
            continue
        n += 1
        nested = [m.get("displayName") for m in members.get("value") or [] if str(m.get("@odata.type") or "").endswith("group")]
        if nested:
            add("high", "nested-group-in-role", idx.name(g), "nested=" + ",".join(nested[:4]), "a nested group inherits the role; its membership decides access")
    note("entra-nested-role-groups", n)


@check("entra-public-groups")
def c_public_groups(ctx):
    rows = graph_all("groups?$filter=groupTypes/any(c:c eq 'Unified')&$select=displayName,visibility,groupTypes", limit=10)
    if rows is None:
        note("entra-public-groups", 0, denied=1)
        return
    note("entra-public-groups", len(rows))
    for g in rows:
        if str(g.get("visibility") or "").lower() == "public":
            add("medium", "public-m365-group", g.get("displayName"), "visibility=Public", "any user can join and read the group's content")


@check("entra-role-assignable-groups")
def c_ra_groups(ctx):
    rows = graph_all("groups?$filter=isAssignableToRole eq true&$select=id,displayName,isAssignableToRole,membershipRule", limit=10)
    if rows is None:
        note("entra-role-assignable-groups", 0, denied=1)
        return
    note("entra-role-assignable-groups", len(rows))
    for g in rows:
        if g.get("membershipRule"):
            add("high", "role-assignable-dynamic-group", g.get("displayName"), "rule=" + str(g.get("membershipRule"))[:70], "a rule decides membership of a group that can hold roles")
        else:
            add("info", "role-assignable-group", dig(g, "displayName"), "assigned membership", "group exists for role assignment")
        owners = graph("groups/" + str(dig(g, "id")) + "/owners?$select=id,displayName,userPrincipalName")
        if owners is None:
            denied_now("entra-role-assignable-groups")
            continue
        people = [o for o in lst(dig(owners, "value")) if dig(o, "userPrincipalName")]
        if not people:
            add("medium", "role-assignable-group-ownerless", dig(g, "displayName"), "owners=0", "nobody is accountable for a group that can hold directory roles")
        else:
            add("high", "role-assignable-group-owner", dig(g, "displayName"), "owners=" + ",".join(str(dig(o, "userPrincipalName")) for o in people)[:80], "an owner can add members and inherit every role the group holds")


@check("entra-access-package-approval")
def c_package_approval(ctx):
    packs = graph_all("identityGovernance/entitlementManagement/accessPackages?$expand=assignmentPolicies", limit=5)
    if packs is None:
        note("entra-access-package-approval", 0, denied=1)
        return
    note("entra-access-package-approval", len(packs))
    for p in packs:
        for ap in lst(dig(p, "assignmentPolicies")):
            approval = dig(ap, "requestApprovalSettings")
            if tri(dig(approval, "isApprovalRequired")) is not True:
                add("high", "access-package-no-approval", dig(p, "displayName"), "policy=" + str(dig(ap, "displayName")), "access granted without an approver")
            expiration = dig(ap, "expiration")
            if not dig(expiration, "endDateTime") and str(val(dig(expiration, "type"), "")).lower() not in ("afterdatetime", "afterduration"):
                add("medium", "access-package-no-expiry", dig(p, "displayName"), "policy=" + str(dig(ap, "displayName")) + " expiration=" + str(val(dig(expiration, "type"), "unset")), "granted access never expires")
            if tri(dig(ap, "isRequestorJustificationRequired")) is not True:
                add("low", "access-package-no-justification", dig(p, "displayName"), "policy=" + str(dig(ap, "displayName")), "requests carry no stated reason")
        incompatible = lst(dig(p, "incompatibleAccessPackages"))
        if incompatible:
            add("info", "access-package-separation-of-duties", dig(p, "displayName"), "incompatiblePackages=" + str(len(incompatible)), "separation of duties is configured for this package")
        elif lst(dig(p, "assignmentPolicies")):
            add("low", "access-package-no-sod", dig(p, "displayName"), "incompatibleAccessPackages=0", "no separation-of-duties constraint prevents conflicting entitlements")


@check("entra-app-hygiene")
def c_app_hygiene(ctx):
    apps = graph_all("applications?$select=appId,displayName,signInAudience,publicClient,web,requiredResourceAccess", limit=10)
    if apps is None:
        note("entra-app-hygiene", 0, denied=1)
        return
    note("entra-app-hygiene", len(apps))
    for a in apps:
        name = a.get("displayName") or a.get("appId")
        aud = str(a.get("signInAudience") or "")
        if aud in ("AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount"):
            add("medium", "app-multitenant", name, "signInAudience=" + aud, "accepts identities from other tenants; consent phishing target")
        fallback = sp_fallback(str(val(dig(a, "appId"), "")))
        if fallback is True:
            add("high", "app-public-client-fallback", name, "servicePrincipal.isFallbackPublicClient=true", "device code and native flows allowed without a secret")
        for uri in (a.get("publicClient") or {}).get("redirectUris") or []:
            if uri.startswith("http://") or uri.startswith("ms-appx") or "localhost" in uri:
                add("low", "app-public-client-redirect", name, uri, "native redirect target; verify the client is not a confidential app")


def _owner_takeover(cap=40):
    """Users who own an app holding a dangerous granted application permission.

    Starts from what is granted, not what an app requests, and reads both owner
    lists: the app registration and the service principal. An owner of either can
    add a credential and act with the app's permissions. Returns the number of
    grants examined.
    """
    held = defaultdict(set)
    examined = 0
    for app_id, (label, wanted) in TAKEOVER_ROLES.items():
        what = (label.rstrip(":") or "Microsoft Graph") + " service principal"
        resource = unread(graph("servicePrincipals?$filter=appId eq '" + app_id + "'&$select=id,appRoles"),
                          what, "app-owner-takeover-unassessed")
        if resource is None:
            continue
        first = lst(dig(resource, "value"))[:1]
        if not first:
            continue  # the resource is not provisioned in this tenant; nothing can be granted on it
        risky = {str(dig(r, "id")): label + str(dig(r, "value")) for r in lst(dig(first[0], "appRoles"))
                 if str(dig(r, "value")) in wanted}
        if not risky:
            undecided("app-owner-takeover-unassessed", what + " appRoles unmapped", "permission ids could not be mapped to names, so no grant is classified")
            continue
        grants = unread(graph_all("servicePrincipals/" + str(dig(first[0], "id")) + "/appRoleAssignedTo", limit=20),
                        what + " application permission grants", "app-owner-takeover-unassessed")
        if grants is None:
            continue
        examined += len(grants)
        for g in grants:
            perm = risky.get(str(dig(g, "appRoleId")))
            if perm and str(dig(g, "principalType")) == "ServicePrincipal":
                held[str(dig(g, "principalId"))].add(perm)
    sample(CURRENT["check"], min(len(held), cap), len(held), "service principals with dangerous grants")
    for pid in sorted(held)[:cap]:
        perms = sorted(held[pid])
        sp = graph("servicePrincipals/" + pid + "?$select=appId,displayName,servicePrincipalType")
        if sp is None:
            if az_kind() != "absent":
                denied_now(CURRENT["check"])
                add("info", "app-owner-takeover-unassessed", pid, "granted=" + ",".join(perms) + " servicePrincipal unreadable", "owners of this privileged app were not assessed")
            continue
        name = str(val(dig(sp, "displayName"), pid))
        sources = [("servicePrincipal", "servicePrincipals/" + pid + "/owners?$select=id,userPrincipalName")]
        if str(dig(sp, "servicePrincipalType")) == "Application":
            sources.append(("application", "applications(appId='" + str(dig(sp, "appId")) + "')/owners?$select=id,userPrincipalName"))
        for via, path in sources:
            rows = graph(path)
            if rows is None:
                # absent: a multi-tenant app whose registration lives in the publisher tenant.
                if az_kind() != "absent":
                    denied_now(CURRENT["check"])
                    add("info", "app-owner-takeover-unassessed", name, via + " owners unreadable granted=" + ",".join(perms), "owners of this privileged app were not assessed")
                continue
            humans = [u for u in (str(val(dig(o, "userPrincipalName"), "")) for o in lst(dig(rows, "value"))) if u]
            if not humans:
                continue
            tier0 = [p for p in perms if p in GRAPH_TIER0]
            sev = "critical" if tier0 else "high"
            add(sev, "high-priv-app-owned-by-human", name,
                "via=" + via + " owners=" + ",".join(humans[:3]) + " granted=" + ",".join(perms),
                "an owner can add a credential and act with these granted application permissions")
            chain("owner-to-application-permissions", "user " + humans[0] + " -> owns " + name + " (" + pid[:8] + ") -> " + (tier0 or perms)[0], sev,
                  "credential injection reaches directory role control" if tier0 else "credential injection into a privileged application")
    return examined


@check("entra-sp-credentials")
def c_sp_creds(ctx):
    sps = graph_all("servicePrincipals?$select=id,displayName,passwordCredentials,keyCredentials,appOwnerOrganizationId", limit=10)
    if sps is None:
        note("entra-sp-credentials", 0, denied=1)
        return
    note("entra-sp-credentials", len(sps))
    now = time.time()
    for sp in sps:
        for cred in lst(dig(sp, "keyCredentials")):
            end = str(dig(cred, "endDateTime") or "")
            stamp = _stamp(end) if end else None
            if stamp is not None and stamp < now:
                add("low", "sp-cert-expired", dig(sp, "displayName"), "end=" + end, "expired certificate still registered; entra-credential-near-expiry reports the expired password credentials")


@check("entra-deleted-apps")
def c_deleted_apps(ctx):
    apps = graph_all("directory/deletedItems/microsoft.graph.application?$select=appId,displayName,deletedDateTime", limit=5)
    if apps is None:
        note("entra-deleted-apps", 0, denied=1)
        return
    note("entra-deleted-apps", len(apps))
    for a in apps[:20]:
        add("info", "deleted-app", a.get("displayName"), "appId=" + str(a.get("appId")) + " deleted=" + str(a.get("deletedDateTime")), "grants may survive on the service principal; verify")
    sample("entra-deleted-apps", min(len(apps), 20), len(apps), "deleted applications")


@check("entra-app-assignments")
def c_approle_assigned(ctx):
    sps = graph_all("servicePrincipals?$select=id,displayName,appRoleAssignmentRequired", limit=10)
    if sps is None:
        note("entra-app-assignments", 0, denied=1)
        return
    note("entra-app-assignments", len(sps))
    found = scan_guests(ctx)
    if found is None:
        note("entra-app-assignments", len(sps), denied=1)
        return
    guests = set(found)
    sample("entra-app-assignments", min(len(sps), 15), len(sps), "service principals")
    for sp in sps[:15]:
        doc = graph("servicePrincipals/" + str(dig(sp, "id")) + "/appRoleAssignedTo")
        if doc is None:
            denied_now("entra-app-assignments")
            continue
        for a in doc.get("value") or []:
            pid = a.get("principalId")
            if pid in guests:
                add("high", "guest-holds-app-role", sp.get("displayName"), "principal=" + str(pid) + " appRole=" + str(a.get("appRoleId")), "external identity granted an application role")


@check("entra-consent")
def c_consent(ctx):
    grants = graph_all("oauth2PermissionGrants", limit=5)
    if grants is None:
        note("entra-consent", 0, denied=1)
        return
    note("entra-consent", len(grants))
    sps = {}
    sp_list = unread(graph_all("servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId", limit=10),
                     "service principals for consent attribution", "consent-principals-unreadable")
    if sp_list is None:
        return
    for s in sp_list:
        sps[s.get("appId")] = s
        if s.get("id"):
            sps[s.get("id")] = s
    for g in grants:
        scope = g.get("scope") or ""
        write = write_scope(scope)
        if not write:
            continue
        sp = sps.get(g.get("clientId")) or {}
        owner_tenant = sp.get("appOwnerOrganizationId")
        foreign = str(owner_tenant).lower() not in MS_TENANTS and tenant_rel(owner_tenant) == "foreign"
        sev = "high" if foreign else "medium"
        publisher = tenant_name(owner_tenant) if foreign else ""
        add(sev, "write-consent-grant", dig(sp, "displayName") or str(dig(g, "clientId")), "consent=" + str(dig(g, "consentType")) + " scope=" + scope + " ownerTenant=" + (str(owner_tenant) + (" (" + publisher + ")" if publisher else "") if owner_tenant else "unknown") + (" foreign=true" if foreign else ""), "write access granted; a publisher in another tenant controls the application code")
        if g.get("consentType") == "AllPrincipals" and foreign:
            chain("third-party-tenant-wide-grant", str(sp.get("displayName")) + " -> " + scope + " -> every user", "high", "foreign publisher with tenant-wide write consent")


@check("entra-privileged-sps")
def c_sps(ctx):
    note("entra-privileged-sps", _owner_takeover())


@check("entra-devices")
def c_devices(ctx):
    devs = graph_all("devices?$select=deviceId,displayName,trustType,isCompliant,alternativeSecurityIds", limit=10)
    if devs is None:
        note("entra-devices", 0, denied=1)
        return
    note("entra-devices", len(devs))
    if not devs:
        add("info", "devices-not-assessed", "tenant", "0 devices returned", "device trust and key reuse are not assessed")
        return
    keys = Counter()
    for d in devs:
        for k in d.get("alternativeSecurityIds") or []:
            if k.get("key"):
                keys[k["key"]] += 1
    for key, c in keys.items():
        if c > 1:
            add("medium", "shared-device-key", key[:16], "appears on " + str(c) + " devices", "key reuse weakens device identity")
    trust = Counter(str(d.get("trustType") or "none") for d in devs)
    add("info", "device-trust-distribution", "tenant", " ".join(k + "=" + str(v) for k, v in trust.items()), "device trust types decide which CA conditions can be satisfied")
    for d in devs:
        if str(d.get("trustType") or "") == "Workplace":
            add("low", "device-workplace-trust", d.get("displayName"), "trustType=Workplace", "registered, not joined; weaker identity binding")
        if d.get("isCompliant") is False:
            add("low", "device-not-compliant", d.get("displayName"), "isCompliant=false", "non-compliant device still registered")


@check("entra-authorization-policy")
def c_authzpolicy(ctx):
    pol = graph("policies/authorizationPolicy")
    if pol is None:
        note("entra-authorization-policy", 0, denied=1)
        return
    note("entra-authorization-policy", 1)
    d = pol.get("defaultUserRolePermissions") or {}
    if d.get("allowedToCreateApps"):
        add("high", "users-can-register-apps", "tenant", "defaultUserRolePermissions.allowedToCreateApps=true", "any user can create an app and request consent")
    if d.get("allowedToCreateSecurityGroups"):
        add("medium", "users-can-create-groups", "tenant", "allowedToCreateSecurityGroups=true", "users create groups they own, which can later be targeted")
    if d.get("allowedToReadOtherUsers"):
        add("low", "users-can-read-directory", "tenant", "allowedToReadOtherUsers=true", "directory enumeration by any user")
    invites = str(val(dig(pol, "allowInvitesFrom"), ""))
    if invites.lower() in ("everyone", "adminsandguestinviters", "adminsguestinvitersandallmembers"):
        add("medium", "guest-invites-broad", "tenant", "allowInvitesFrom=" + invites, "non-administrators can bring external identities into the tenant")
    gur = str(pol.get("guestUserRoleId") or "")
    if gur == "a0b1b346-4d3e-4e8b-98f8-753987be4970":
        add("high", "guest-member-level-access", "tenant", "guestUserRoleId=User (a0b1b346)", "guests receive the member-equivalent role and can enumerate most of the directory")
    elif gur == "10dae51f-b6af-4016-8d66-8c2a99b929b3":
        add("info", "guest-limited-access", "tenant", "guestUserRoleId=Guest User (10dae51f)", "the default limited guest role")
    elif gur == "2af84b1e-32c8-42b7-82bc-daa82404023b":
        add("info", "guest-restricted-access", "tenant", "guestUserRoleId=Restricted Guest User (2af84b1e)", "the most restrictive guest role")
    else:
        add("medium", "guest-role-unknown", "tenant", "guestUserRoleId=" + (gur or "unset"), "the guest permission level is not one of the three documented roles")
    if pol.get("blockMsolPowerShell") is False:
        add("low", "msol-powershell-allowed", "tenant", "blockMsolPowerShell=false", "legacy MSOnline path remains available")
    assigned = pol.get("permissionGrantPolicyIdsAssignedToDefaultUserRole") or []
    if any("managePermissionGrantsForSelf" in str(a) for a in assigned):
        add("high", "user-consent-to-apps-enabled", "tenant", "permissionGrantPolicyIdsAssignedToDefaultUserRole=" + ",".join([str(a) for a in assigned][:4]), "users can grant app permissions without an administrator")
    if d.get("allowedToCreateTenants"):
        add("medium", "users-can-create-tenants", "tenant", "defaultUserRolePermissions.allowedToCreateTenants=true", "users can create tenants outside the governance boundary")
    if d.get("allowedToReadBitlockerKeysForOwnedDevice"):
        add("low", "users-can-read-bitlocker-keys", "tenant", "defaultUserRolePermissions.allowedToReadBitlockerKeysForOwnedDevice=true", "recovery keys readable by device owners")
    aps = graph("policies/adminConsentRequestPolicy")
    if aps:
        add("info", "admin-consent-workflow", "tenant", "isEnabled=" + str(aps.get("isEnabled")), "request workflow state")
    damp = graph("policies/defaultAppManagementPolicy")
    if damp:
        restrictions = dig(damp, "restrictions")
        if not isinstance(restrictions, dict):
            add("info", "app-policy-unparsed", "tenant", "restrictions=" + str(type(restrictions).__name__), "the app management policy shape was not recognised")
        for kind in sorted(restrictions) if isinstance(restrictions, dict) else []:
            bucket = dig(restrictions, kind)
            if isinstance(bucket, list):
                rules = bucket
            elif isinstance(bucket, dict):
                rules = [bucket]
            else:
                rules = []
            if not rules:
                add("info", "app-policy-rule-absent", str(kind), "no restriction of this kind", "this credential kind is unrestricted")
            for rule in rules:
                caps = str(val(dig(rule, "restrictForAppsCreatedAfterDateTime"), ""))
                max_life = str(val(dig(rule, "maxLifetime"), ""))
                if not max_life:
                    add("medium", "app-policy-no-lifetime", str(kind) + "/" + str(val(dig(rule, "restrictionType"), "unknown")), "restrictionType=" + str(val(dig(rule, "restrictionType"), "unknown")) + " maxLifetime unset", "the restriction exists but imposes no lifetime cap")
                else:
                    add("info", "app-policy-rule", str(kind) + "/" + str(val(dig(rule, "restrictionType"), "unknown")), "maxLifetime=" + max_life + " restrictAfter=" + (caps or "unset"), "credential lifetime cap in force")
    tlp = graph_all("policies/tokenLifetimePolicies", limit=3)
    if tlp is None:
        denied_now("entra-authorization-policy")
    for p in lst(tlp):
        for d in lst(dig(p, "definition")):
            add("info", "token-lifetime-policy", dig(p, "displayName"), "definition=" + str(d)[:80], "token lifetime override in force", "tenant")
    hrd = graph_all("policies/homeRealmDiscoveryPolicies", limit=3)
    if hrd is None:
        note("entra-authorization-policy", 0, denied=1)
        add("info", "home-realm-unassessed", "tenant", "homeRealmDiscoveryPolicies unreadable", "domain hint overrides were not assessed")
    for h in lst(hrd):
        add("info", "home-realm-discovery", dig(h, "displayName"), "state=" + str(dig(h, "definition")), "domain hint overrides for federated users")
    policies = unread(graph_all("policies/permissionGrantPolicies", limit=3), "permission grant policies", "consent-policies-unreadable")
    if policies is None:
        return
    note("entra-authorization-policy", len(policies))
    for gp in policies:
        add("info", "consent-policy", gp.get("displayName"), "id=" + str(gp.get("id")), "user consent scope in force")


@check("entra-pim")
def c_pim(ctx):
    elig = graph_all("roleManagement/directory/roleEligibilityScheduleInstances", limit=3, beta=True)
    if elig is None:
        note("entra-pim", 0, denied=1)
        add("info", "pim-not-assessed", "tenant", "eligibility endpoint unavailable", "cannot distinguish permanent from eligible roles")
        return
    note("entra-pim", len(elig))
    if not elig:
        add("medium", "no-pim-eligibility", "tenant", "0 eligible role assignments", "every privileged assignment is permanent; no activation gate")


@check("entra-group-owners")
def c_group_owners(ctx):
    idx = ctx["idx"]
    assignments = graph_all("roleManagement/directory/roleAssignments", limit=5)
    if assignments is None:
        note("entra-group-owners", 0, denied=1)
        return
    role_groups = {a.get("principalId") for a in assignments}
    n = 0
    for g in idx.groups():
        gid = g.get("id")
        if gid not in role_groups:
            continue
        owners = graph("groups/" + str(gid) + "/owners?$select=id,displayName,userPrincipalName")
        if owners is None:
            deny("entra-group-owners")
            continue
        n += 1
        humans = [o.get("userPrincipalName") for o in owners.get("value") or [] if o.get("userPrincipalName")]
        if humans:
            add("high", "role-group-has-human-owner", idx.name(g), "owners=" + ",".join(humans[:5]), "an owner can add members, which grants the role")
            chain("owner-to-role", "user " + humans[0] + " -> owns " + idx.name(g) + " -> group holds a role", "high", "group ownership is role-granting")
    note("entra-group-owners", n, denied=DENIED["entra-group-owners"])


@check("entra-scoped-roles")
def c_scoped(ctx):
    assignments = graph_all("roleManagement/directory/roleAssignments", limit=5)
    if assignments is None:
        note("entra-scoped-roles", 0, denied=1)
        return
    scoped = 0
    for a in assignments:
        scope = str(dig(a, "directoryScopeId") or "/")
        if scope != "/":
            scoped += 1
            add("medium", "scoped-role-assignment", str(dig(a, "principalId")), "role=" + str(dig(a, "roleDefinitionId")) + " scope=" + scope, "scoped administration; verify the scope boundary holds")
    aus = graph_all("directory/administrativeUnits", limit=3)
    note("entra-scoped-roles", len(assignments))
    add("info", "scoped-role-coverage", "all", "assignments=" + str(len(assignments)) + " scoped=" + str(scoped), "tenant-wide versus scoped role assignments")
    if aus is None:
        note("entra-scoped-roles", len(assignments), denied=1)
        add("info", "administrative-units-unassessed", "tenant", "administrativeUnits unreadable", "scoped administration containers were not listed")
    for au in lst(aus):
        add("info", "administrative-unit", dig(au, "displayName"), "id=" + str(dig(au, "id")), "scoped administration container")


@check("entra-legacy-graph")
def c_legacy(ctx):
    grants = graph_all("oauth2PermissionGrants", limit=5)
    if grants is None:
        note("entra-legacy-graph", 0, denied=1)
        return
    sps = {}
    sp_rows = graph_all("servicePrincipals?$select=id,appId,displayName", limit=10)
    if sp_rows is None:
        note("entra-legacy-graph", len(grants), denied=1)
        return
    for sp in sp_rows:
        sps[sp.get("id")] = sp.get("displayName")
        if sp.get("appId"):
            sps[sp.get("appId")] = sp.get("displayName")
    legacy = [g for g in grants if str(g.get("resourceId")) in sps and sps.get(g.get("resourceId")) and "Windows Azure Active Directory" in str(sps.get(g.get("resourceId")))]
    note("entra-legacy-graph", len(grants))
    for g in legacy:
        add("medium", "legacy-aad-graph-grant", sps.get(g.get("clientId")) or g.get("clientId"), "resource=" + str(sps.get(g.get("resourceId"))) + " scope=" + str(g.get("scope")), "AAD Graph is deprecated and logs less than Graph")


@check("entra-agent-identities")
def c_agents(ctx):
    types = Counter()
    sps = graph_all("servicePrincipals?$select=servicePrincipalType,displayName", limit=10)
    if sps is None:
        note("entra-agent-identities", 0, denied=1)
        return
    for sp in sps:
        types[str(sp.get("servicePrincipalType") or "?")] += 1
    note("entra-agent-identities", sum(types.values()))
    for k, v in types.items():
        if "agent" in k.lower():
            add("high", "agent-identity-present", k, "count=" + str(v), "agent identities are new, rarely reviewed, and hold delegated tokens")
        else:
            if str(k).lower() not in ("serviceprincipal", "user", "group", "application", "managedidentity", "legacy"):
                add("low", "unexpected-principal-type", k, "count=" + str(v), "unknown principal type in an assignment")


@check("entra-cross-tenant")
def c_crosstenant(ctx):
    pol = graph("policies/crossTenantAccessPolicy/default")
    if pol is None:
        note("entra-cross-tenant", 0, denied=1)
        return
    note("entra-cross-tenant", 1)
    trust = pol.get("inboundTrust") or {}
    if trust.get("isMfaAccepted"):
        add("medium", "cross-tenant-mfa-trust", "tenant", "inboundTrust.isMfaAccepted=true", "another tenant's MFA satisfies your policy")
    if trust.get("isCompliantDeviceAccepted") or trust.get("isHybridAzureADJoinedDeviceAccepted"):
        add("high", "cross-tenant-device-trust", "tenant", "compliant=" + str(trust.get("isCompliantDeviceAccepted")) + " hybrid=" + str(trust.get("isHybridAzureADJoinedDeviceAccepted")), "external device state satisfies your CA")


@check("entra-device-registration")
def c_devreg(ctx):
    pol = graph("policies/deviceRegistrationPolicy", beta=True)
    if pol is None:
        note("entra-device-registration", 0, denied=1)
        return
    note("entra-device-registration", 1)
    users = str(((pol.get("userDeviceQuota") is not None) and "quota=" + str(pol.get("userDeviceQuota"))) or "")
    for key in ("azureADJoin", "azureADRegistration"):
        block = pol.get(key) or {}
        allowed = block.get("isAllowed")
        if allowed:
            add("medium", "device-registration-open", key, "isAllowed=true " + users, "users can create device objects that CA may trust")


@check("entra-auth-methods")
def c_authmethods(ctx):
    pol = graph("policies/authenticationMethodsPolicy")
    if pol is None:
        note("entra-auth-methods", 0, denied=1)
        return
    note("entra-auth-methods", 1)
    for cfg in pol.get("authenticationMethodConfigurations") or []:
        mid = str(cfg.get("@odata.type") or "").split(".")[-1]
        state = cfg.get("state")
        if state == "enabled" and mid in ("voiceAuthenticationMethodConfiguration", "smsAuthenticationMethodConfiguration"):
            add("medium", "weak-auth-method-enabled", mid, "state=enabled", "SMS and voice are interceptable and SIM-swappable")
        if mid == "temporaryAccessPassAuthenticationMethodConfiguration" and state == "enabled":
            add("low", "temporary-access-pass-enabled", mid, "state=enabled", "single-use credential issuance; review who can create one")
        add("info", "auth-method", mid, "state=" + str(state), "method inventory")


def scan_guests(ctx):
    if ctx.get("guests_failed"):
        if CURRENT["check"]:
            GUEST_PARTIAL.add(CURRENT["check"])
        return None
    if ctx.get("guests_done"):
        if ctx.get("guests_partial") and CURRENT["check"]:
            GUEST_PARTIAL.add(CURRENT["check"])
        return ctx["guests"]
    before = len(TRUNCATED)
    ulist = graph_all("users?$filter=userType eq 'Guest'&$select=id,userPrincipalName,displayName&$top=999", limit=20)
    if ulist is None:
        ctx["guests_failed"] = True
        ctx["guests_failed_check"] = CURRENT["check"]
        if ctx["guests"] and CURRENT["check"]:
            GUEST_PARTIAL.add(CURRENT["check"])
        add("low", "guest-list-unreadable", CURRENT["check"] or "tenant", "users?$filter=userType eq 'Guest' unreadable offlineSeed=" + str(len(ctx["guests"])), "live guest membership was not read; " + ("the export seed is used and the result is partial" if ctx["guests"] else "every guest-dependent check below is partial"))
        if ctx["guests"]:
            ctx["guests_done"] = True
            ctx["guests_partial"] = True
            return ctx["guests"]
        return None
    if len(TRUNCATED) > before:
        ctx["guests_partial"] = True
    for u in ulist:
        if u.get("id"):
            ctx["guests"].add(u.get("id"))
            ctx["idx"].names[u.get("id")] = u.get("displayName") or u.get("userPrincipalName") or u.get("id")
    ctx["guests_done"] = True
    return ctx["guests"]


@check("entra-guests-with-roles")
def c_guest_roles(ctx):
    found = scan_guests(ctx)
    if found is None:
        note("entra-guests-with-roles", 0, denied=1)
        return
    guests = set(found)
    if not guests:
        note("entra-guests-with-roles", 0)
        return
    assignments = graph_all("roleManagement/directory/roleAssignments", limit=5)
    if assignments is None:
        deny("entra-guests-with-roles")
        return
    defs_raw = unread(graph_all("roleManagement/directory/roleDefinitions", limit=5),
                      "directory role definitions", "guest-roles-unreadable")
    if defs_raw is None:
        return
    defs = {d.get("id"): d.get("displayName") for d in defs_raw if d.get("id")}
    note("entra-guests-with-roles", len(assignments), denied=deny("entra-guests-with-roles", 0))
    for a in assignments:
        if a.get("principalId") in guests:
            label = str(defs.get(a.get("roleDefinitionId")) or a.get("roleDefinitionId"))
            sev = "critical" if label in ESCALATION_ROLES else "high"
            add(sev, "guest-holds-directory-role", str(a.get("principalId")), "role=" + label, "external identity holds a directory role")


@check("entra-custom-roles")
def c_customroles(ctx):
    roles = graph_all("roleManagement/directory/roleDefinitions?$filter=isBuiltIn eq false", limit=5)
    if roles is None:
        note("entra-custom-roles", 0, denied=1)
        return
    note("entra-custom-roles", len(roles))
    for r in roles:
        actions = []
        for perm in r.get("rolePermissions") or []:
            actions.extend(perm.get("allowedResourceActions") or [])
        wild = [a for a in actions if a.endswith("allTasks") or a == "*" or "allProperties" in a]
        escalation = [a for a in actions if any(t in str(a).lower() for t in (
            "microsoft.directory/users/password/update",
            "microsoft.directory/users/authenticationMethods/",
            "microsoft.directory/applications/credentials/update",
            "microsoft.directory/servicePrincipals/credentials/update",
            "microsoft.directory/applications/appRoles/update",
            "microsoft.directory/servicePrincipals/appRoleAssignments/",
            "microsoft.directory/oauth2PermissionGrants/",
            "microsoft.directory/roleManagement/",
            "microsoft.directory/groups/members/update"))]
        if wild:
            add("high", "custom-role-broad-actions", dig(r, "displayName"), "actions=" + str(len(actions)) + " broad=" + ",".join(wild[:4]), "custom role grants near-administrative breadth")
        if escalation:
            add("high", "custom-role-escalation-action", dig(r, "displayName"), "actions=" + ",".join(sorted(set(escalation))[:4]), "the role can reset credentials, grant consent, or change role membership")


@check("sub-network-topology")
def c_net(ctx):
    q = "Resources | where type =~ 'microsoft.network/virtualnetworks' | mv-expand p = properties.virtualNetworkPeerings | project name, subscriptionId, peer=tostring(p.properties.remoteVirtualNetwork.id), transit=tostring(p.properties.allowGatewayTransit), remote=tostring(p.properties.useRemoteGateways), fwd=tostring(p.properties.allowForwardedTraffic)"
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-network-topology", 0, denied=1)
        return
    note("sub-network-topology", len(rows))
    for r in rows:
        if r.get("fwd") == "true":
            add("low", "vnet-forwarded-traffic", r.get("name"), "peer=" + str(r.get("peer")) + " allowForwardedTraffic=true", "traffic from a remote network can be forwarded here", r.get("subscriptionId"))
        if r.get("transit") == "true":
            add("medium", "vnet-gateway-transit", r.get("name"), "peer=" + str(r.get("peer")) + " allowGatewayTransit=true", "spokes reach the hybrid gateway through this hub", r.get("subscriptionId"))
        if r.get("remote") == "true":
            add("low", "vnet-uses-remote-gateway", r.get("name"), "peer=" + str(r.get("peer")) + " useRemoteGateways=true", "this network routes through the hub gateway", r.get("subscriptionId"))
    fw = arg_rows("Resources | where type =~ 'microsoft.network/firewallpolicies' | project name, subscriptionId, mode=tostring(properties.threatIntelMode), sku=tostring(properties.sku.tier)", ctx["subs"])
    if fw is None:
        deny("sub-network-topology")
    for r in lst(fw):
        mode = str(r.get("mode") or "").lower()
        if mode in ("alert", "off"):
            add("medium" if mode == "alert" else "low", "firewall-threat-intel-mode", r.get("name"), "threatIntelMode=" + mode + " sku=" + str(r.get("sku")), "malicious traffic is logged or allowed rather than blocked", r.get("subscriptionId"))


@check("sub-private-endpoints")
def c_private(ctx):
    q = """Resources
| where subscriptionId in (""" + subq(ctx["subs"]) + """)
| where type in~ ('microsoft.keyvault/vaults','microsoft.storage/storageaccounts','microsoft.sql/servers','microsoft.documentdb/databaseaccounts','microsoft.servicebus/namespaces','microsoft.eventhub/namespaces','microsoft.cognitiveservices/accounts')
| project name, type, subscriptionId, pe=array_length(properties.privateEndpointConnections), publicNet=tostring(properties.publicNetworkAccess)"""
    rows = arg_rows(q, ctx["subs"], scoped=False)
    if rows is None:
        note("sub-private-endpoints", 0, denied=1)
        return
    note("sub-private-endpoints", len(rows))
    for r in rows:
        pe = r.get("pe") or 0
        public = str(r.get("publicNet") or "")
        if not pe and public == "Enabled":
            add("medium", "paas-no-private-endpoint", str(r.get("name")) + " " + str(r.get("type")).split("/")[-1], "privateEndpoints=0 publicNetworkAccess=Enabled", "service reachable over the public endpoint only", r.get("subscriptionId"))
        elif pe:
            add("info", "paas-private-endpoint", r.get("name"), "privateEndpoints=" + str(pe) + " publicNetworkAccess=" + public, "private path present", r.get("subscriptionId"))


DANGEROUS_ACTIONS = (
    "microsoft.authorization/roleassignments/write",
    "microsoft.authorization/roleassignments/delete",
    "microsoft.authorization/roleeligibilityschedules/write",
    "microsoft.managedidentity/userassignedidentities/assign/action",
    "microsoft.managedidentity/userassignedidentities/*/assign/action",
)


@check("sub-rbac-write")
def c_rbac_write(ctx):
    q = "AuthorizationResources | where type =~ 'microsoft.authorization/roleassignments' | where subscriptionId in (" + subq(ctx["subs"]) + ") | project principalId=tostring(properties.principalId), principalType=tostring(properties.principalType), roleId=tostring(properties.roleDefinitionId), scope=tostring(properties.scope)"
    rows = arg_rows(q, ctx["subs"], scoped=False)
    if rows is None:
        note("sub-rbac-write", 0, denied=1)
        return
    defs = {}
    role_rows = unread(arg_rows(tenant_wide("AuthorizationResources | where type =~ 'microsoft.authorization/roledefinitions' | project id, name=properties.roleName, perms=properties.permissions"), ctx["subs"], scoped=False),
                      "role definitions", "rbac-definitions-unreadable")
    if role_rows is None:
        return
    for r in role_rows:
        perms = lst(dig(r, "perms"))
        defs[str(dig(r, "id")).lower()] = {"name": dig(r, "name"), "perms": perms}
    note("sub-rbac-write", len(rows), denied=deny("sub-rbac-write", 0))
    agg = defaultdict(set)
    scopes = {}
    for r in rows:
        if dig(r, "scope") and not scopes.get(str(dig(r, "principalId"))):
            scopes[str(dig(r, "principalId"))] = str(dig(r, "scope"))
        rid = str(r.get("roleId") or "").lower()
        d = defs.get(rid) or {}
        perms = d.get("perms") or []
        assign = grants_role_write(perms) or any(permits(p, "microsoft.authorization/roledefinitions/write") for p in perms)
        assign = assign or any(permits(p, t) for p in perms for t in DANGEROUS_ACTIONS)
        if rid.endswith(BUILTIN_ROLE_OWNER) or rid.endswith(BUILTIN_ROLE_UAA) or assign:
            agg[r.get("principalId")].add(d.get("name") or rid.split("/")[-1])
    for pid, roles in agg.items():
        guest_set = scan_guests(ctx) or set()
        kind = "guest" if pid in guest_set else "principal"
        sub = ctx_sub({"scope": scopes.get(pid, "")})
        add("high" if kind == "guest" else "medium", "principal-can-grant-access", pid, "roles=" + ",".join(sorted(roles))[:80] + " type=" + kind, "can create role assignments or assign identities, which equals Owner", sub)


@check("sub-guest-rbac")
def c_guest_rbac(ctx):
    found = scan_guests(ctx)
    if found is None:
        note("sub-guest-rbac", 0, denied=1)
        return
    guests = set(found)
    note("sub-guest-rbac", len(guests))
    if not guests:
        return
    rows = arg_rows("AuthorizationResources | where type =~ 'microsoft.authorization/roleassignments' | where subscriptionId in (" + subq(ctx["subs"]) + ") | project roleId=tostring(properties.roleDefinitionId), principalId=tostring(properties.principalId), scope=tostring(properties.scope)", ctx["subs"], scoped=False)
    if rows is None:
        note("sub-guest-rbac", len(guests), denied=1)
        return
    defs = {}
    role_rows = unread(arg_rows(tenant_wide("AuthorizationResources | where type =~ 'microsoft.authorization/roledefinitions' | project id=tolower(id), name=tostring(properties.roleName), perms=properties.permissions"), ctx["subs"], scoped=False),
                      "role definitions", "guest-rbac-definitions-unreadable")
    if role_rows is None:
        return
    for d in role_rows:
        defs[str(dig(d, "id"))] = (str(dig(d, "name")), lst(dig(d, "perms")))
    for r in rows:
        if r.get("principalId") in guests:
            rid = str(r.get("roleId") or "").lower()
            name, perms = defs.get(rid, (rid.split("/")[-1], []))
            broad = grants_role_write(perms) or any(permits(p, t) for p in perms for t in DANGEROUS_ACTIONS)
            sev = "critical" if broad else "high"
            add(sev, "guest-holds-azure-rbac", r.get("principalId"), "role=" + name + " scope=" + str(r.get("scope")), "external identity with control-plane access", ctx_sub(r), r.get("scope"))


@check("sub-custom-roles")
def c_custom_arm(ctx):
    rows = arg_rows("AuthorizationResources | where type =~ 'microsoft.authorization/roledefinitions' | where tostring(properties.roleType) == 'CustomRole' | where subscriptionId in (" + subq(ctx["subs"]) + ") | project name, subscriptionId, id, perms=properties.permissions", ctx["subs"], scoped=False)
    if rows is None:
        note("sub-custom-roles", 0, denied=1)
        return
    note("sub-custom-roles", len(rows))
    for r in rows:
        perms = lst(dig(r, "perms"))
        grants = [t for t in ("microsoft.authorization/roleassignments/write", "microsoft.authorization/roledefinitions/write", "microsoft.authorization/elevateAccess/action") if any(permits(p, t) for p in perms)]
        danger = [t for t in DANGEROUS_ACTIONS if any(permits(p, t) for p in perms)]
        if grants:
            add("high", "custom-role-privilege-grant", dig(r, "name"), "actions=" + ",".join(grants[:3]), "the custom role can grant access or assign identities", str(dig(r, "subscriptionId")))
        elif danger:
            add("high", "custom-role-privilege-grant", dig(r, "name"), "actions=" + ",".join(danger[:3]), "custom role holds a dangerous action", str(dig(r, "subscriptionId")))
        elif not perms:
            add("low", "custom-role-no-permissions", dig(r, "name"), "permissions empty", "the role definition grants nothing", str(dig(r, "subscriptionId")))


@check("sub-deny-assignments")
def c_deny(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.authorization/denyassignments' | project name, subscriptionId, principals=properties.principals, excludePrincipals=properties.excludePrincipals", ctx["subs"])
    if rows is None:
        note("sub-deny-assignments", 0, denied=1)
        return
    note("sub-deny-assignments", len(rows))
    for r in rows:
        add("info", "deny-assignment", r.get("name"), "subscription=" + str(r.get("subscriptionId")), "explicit deny in effect; verify it is intentional", r.get("subscriptionId"))


@check("sub-paas-auth")
def c_paas(ctx):
    q = """Resources
| where subscriptionId in (""" + subq(ctx["subs"]) + """)
| where type in~ ('microsoft.documentdb/databaseaccounts','microsoft.servicebus/namespaces','microsoft.eventhub/namespaces','microsoft.cache/redis','microsoft.containerregistry/registries','microsoft.cognitiveservices/accounts')
| project name, type, subscriptionId, localAuth=tostring(properties.disableLocalAuth), tls=tostring(properties.minimumTlsVersion), nonSsl=tostring(properties.enableNonSslPort), adminUser=tostring(properties.adminUserEnabled), publicNet=tostring(properties.publicNetworkAccess)"""
    rows = arg_rows(q, ctx["subs"], scoped=False)
    if rows is None:
        note("sub-paas-auth", 0, denied=1)
        return
    note("sub-paas-auth", len(rows))
    for r in rows:
        s = r.get("subscriptionId")
        t = str(r.get("type")).split("/")[-1]
        local = tri(dig(r, "localAuth"))
        supports_local = t.lower() in ("databaseaccounts", "namespaces", "accounts")
        if local is False:
            add("medium", "paas-local-auth-enabled", str(r.get("name")) + " " + t, "disableLocalAuth=false", "shared-key authentication bypasses identity control", s)
        elif local is None and supports_local and not dig(r, "localAuth"):
            add("low", "paas-local-auth-unreadable", str(r.get("name")) + " " + t, "disableLocalAuth not returned", "shared-key exposure cannot be assessed", s)
        if r.get("nonSsl") == "true":
            add("medium", "redis-nonssl-port", r.get("name"), "enableNonSslPort=true", "unencrypted Redis port open", s)
        if r.get("adminUser") == "true":
            add("medium", "acr-admin-user", r.get("name"), "adminUserEnabled=true", "registry uses a shared administrative credential", s)
        if str(r.get("publicNet") or "").lower() == "disabled":
            add("info", "paas-public-access-disabled", str(r.get("name")) + " " + t, "publicNetworkAccess=Disabled", "public endpoint closed", s)
        if r.get("tls") and str(r.get("tls")) not in ("1.2", "TLS1_2", "1.3", "TLS1_3"):
            add("medium", "paas-legacy-tls", str(r.get("name")) + " " + t, "minimumTlsVersion=" + str(r.get("tls")), "legacy TLS accepted", s)


@check("sub-appservice-restrictions")
def c_webacl(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.web/sites' | project name, subscriptionId, rg=resourceGroup, clientCert=tostring(properties.clientCertEnabled)", ctx["subs"])
    if rows is None:
        note("sub-appservice-restrictions", 0, denied=1)
        return
    note("sub-appservice-restrictions", len(rows))
    cfg = unread(arg_rows("Resources | where type =~ 'microsoft.web/sites/config' | where name =~ 'web' | project parent=tolower(substring(id, 0, indexof(tolower(id), '/config/'))), ips=properties.ipSecurityRestrictions, scm=properties.scmIpSecurityRestrictions, scmMain=tostring(properties.scmIpSecurityRestrictionsUseMain), defaultAction=tostring(properties.ipSecurityRestrictionsDefaultAction)", ctx["subs"]),
                 "web app site configurations", "appservice-configs-unreadable")
    if cfg is None:
        return
    rules = {}
    for c in cfg:
        key = str(dig(c, "parent")).lower()
        rules[key] = c
    for r in rows:
        s = r.get("subscriptionId")
        cert = tri(r.get("clientCert"))
        if cert is False:
            add("low", "appservice-no-client-cert", r.get("name"), "clientCertEnabled=false", "mutual TLS not required", s)
        key = ("/subscriptions/" + str(s) + "/resourcegroups/" + str(r.get("rg")) + "/providers/microsoft.web/sites/" + str(r.get("name"))).lower()
        c = rules.get(key)
        if c is None:
            add("low", "appservice-restrictions-unreadable", r.get("name"), "siteConfig not returned", "SCM and IP restrictions cannot be confirmed", s)
            continue
        if not lst(dig(c, "scm")) and tri(dig(c, "scmMain")) is not True:
            add("medium", "appservice-scm-unrestricted", r.get("name"), "scmIpSecurityRestrictions=0 scmUseMain=false", "Kudu endpoint reachable without restriction", s)
        ips = lst(dig(c, "ips"))
        if not ips:
            add("medium", "appservice-no-ip-restriction", r.get("name"), "ipSecurityRestrictions=0 defaultAction=" + str(val(dig(c, "defaultAction"), "")), "app accepts traffic from any address", s)


@check("sub-loganalytics")
def c_law(ctx):
    q = "Resources | where type =~ 'microsoft.operationalinsights/workspaces' | project name, subscriptionId, ingest=tostring(properties.publicNetworkAccessForIngestion), query=tostring(properties.publicNetworkAccessForQuery), retention=properties.retentionInDays, sku=tostring(properties.sku.name)"
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-loganalytics", 0, denied=1)
        return
    note("sub-loganalytics", len(rows))
    for r in rows:
        s = r.get("subscriptionId")
        if r.get("ingest") == "Enabled" or r.get("query") == "Enabled":
            add("low", "loganalytics-public-endpoint", r.get("name"), "ingest=" + str(r.get("ingest")) + " query=" + str(r.get("query")), "workspace reachable without private link", s)
        days = num(r.get("retention"))
        if not isinstance(days, int):
            add("low", "loganalytics-retention-unknown", r.get("name"), "retentionInDays not returned", "investigation window cannot be confirmed", s)
        elif days < 90:
            add("medium", "loganalytics-short-retention", r.get("name"), "retentionInDays=" + str(days), "investigation window shorter than a quarter", s)


@check("sub-flowlogs")
def c_flowlogs(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.network/networkwatchers/flowlogs' | project name, subscriptionId, enabled=tostring(properties.enabled), retention=properties.retentionPolicy.days", ctx["subs"])
    if rows is None:
        note("sub-flowlogs", 0, denied=1)
        return
    note("sub-flowlogs", len(rows))
    if not rows:
        add("medium", "no-nsg-flow-logs", "all", "0 flow logs", "network connections are not recorded", "tenant")
    for r in rows:
        flow_state = tri(dig(r, "enabled"))
        if flow_state is False:
            add("medium", "flowlog-disabled", dig(r, "name"), "enabled=false", "flow log exists but is disabled", str(dig(r, "subscriptionId")))
        elif flow_state is None:
            add("low", "flowlog-state-unknown", dig(r, "name"), "enabled not returned", "flow log state cannot be confirmed", str(dig(r, "subscriptionId")))
        days = num(dig(r, "retention"))
        if isinstance(days, int) and 0 < days < 90:
            add("low", "flowlog-short-retention", dig(r, "name"), "retentionDays=" + str(days), "flow data expires sooner than a quarter", str(dig(r, "subscriptionId")))


@check("entra-sp-roles")
def c_sp_roles(ctx):
    idx = ctx["idx"]
    sp_ids = {sp.get("id") for sp in idx.sps()}
    assignments = graph_all("roleManagement/directory/roleAssignments", limit=5)
    if assignments is None:
        note("entra-sp-roles", 0, denied=1)
        return
    note("entra-sp-roles", len(assignments))
    for a in assignments:
        if a.get("principalId") in sp_ids:
            add("high", "service-principal-holds-role", idx.resolve(a.get("principalId")) or a.get("principalId"), "role=" + str(a.get("roleDefinitionId")), "machine identity with directory rights")


@check("entra-immutableid")
def c_immutable(ctx):
    idx = ctx["idx"]
    seen = defaultdict(list)
    n = 0
    for u in idx.users():
        p = idx.props(u)
        iid = p.get("onPremisesImmutableId")
        if iid:
            n += 1
            seen[str(iid)].append(p.get("userPrincipalName") or u.get("id"))
    note("entra-immutableid", n)
    for iid, users in seen.items():
        if len(users) > 1:
            add("critical", "duplicate-immutable-id", iid, "users=" + ",".join(users[:4]), "two objects share a source anchor; object takeover on next sync")
    if n == 0:
        add("info", "no-synced-objects", "tenant", "0 users with onPremisesImmutableId", "no hybrid sync anchor present in this dataset")


@check("entra-federation")
def c_fed(ctx):
    rows = graph_all("domains?$select=id,authenticationType,isVerified,isDefault", limit=3)
    if rows is None:
        note("entra-federation", 0, denied=1)
        return
    note("entra-federation", len(rows))
    for d in rows:
        auth = str(d.get("authenticationType") or "")
        if auth.lower() == "federated":
            add("medium", "federated-domain", d.get("id"), "authenticationType=Federated verified=" + str(d.get("isVerified")), "authentication depends on an external STS outside this audit")
        else:
            add("info", "managed-domain", d.get("id"), "authenticationType=" + auth, "cloud-managed authentication")


@check("entra-synced-admins")
def c_synced_admins(ctx):
    idx = ctx["idx"]
    synced = set()
    for u in idx.users():
        if idx.props(u).get("onPremisesSyncEnabled") is True:
            synced.add(u.get("id"))
    note("entra-synced-admins", len(synced))
    assignments = graph_all("roleManagement/directory/roleAssignments", limit=5)
    if assignments is None:
        note("entra-synced-admins", len(synced), denied=1)
        return
    if not synced:
        return
    for a in assignments:
        if a.get("principalId") in synced:
            add("high", "synced-account-holds-role", idx.resolve(a.get("principalId")) or a.get("principalId"), "role=" + str(a.get("roleDefinitionId")), "on-premises write access reaches a cloud administrative role")


@check("entra-password-policy")
def c_pwpolicy(ctx):
    idx = ctx["idx"]
    users = idx.users()
    note("entra-password-policy", len(users))
    if not users:
        return
    expired = [u for u in users if "DisablePasswordExpiration" in str(idx.props(u).get("passwordPolicies") or "")]
    add("info", "password-expiry-disabled", "tenant", "users=" + str(len(expired)) + " of " + str(len(users)),
        "no periodic expiry; Microsoft recommends this state when MFA and banned-password protection are enforced")
    if len(expired) < len(users):
        add("info", "password-expiry-enforced", "tenant", "users=" + str(len(users) - len(expired)) + " of " + str(len(users)),
            "periodic expiry is still enforced for these users; Microsoft no longer recommends forced rotation",
            repro="jq -r '.data[] | select(.kind==\"AZUser\") | select((.properties.passwordPolicies|tostring|test(\"DisablePasswordExpiration\"))|not) | .properties.userPrincipalName' azurehound.json")


@check("entra-enterprise-apps")
def c_enterprise_apps(ctx):
    sps = graph_all("servicePrincipals?$select=appId,displayName,appRoleAssignmentRequired,appOwnerOrganizationId,isFallbackPublicClient,accountEnabled,passwordCredentials,keyCredentials", limit=10)
    if sps is None:
        note("entra-enterprise-apps", 0, denied=1)
        return
    note("entra-enterprise-apps", len(sps))
    for sp in sps:
        owner = str(val(dig(sp, "appOwnerOrganizationId"), ""))
        rel = tenant_rel(owner)
        first_party = str(owner).lower() in MS_TENANTS or rel == "home"
        if tri(dig(sp, "appRoleAssignmentRequired")) is False and rel == "unknown":
            undecided("enterprise-app-owner-unknown", "ownerTenant not returned", "application ownership was not readable, so first-party status is not decided")
        elif tri(dig(sp, "appRoleAssignmentRequired")) is False and not first_party:
            add("low", "enterprise-app-no-assignment", dig(sp, "displayName"), "appRoleAssignmentRequired=false ownerTenant=" + owner, "any user in the tenant can sign in to this application")
        if sp.get("accountEnabled") is False and (lst(dig(sp, "passwordCredentials")) or lst(dig(sp, "keyCredentials"))):
            add("low", "disabled-sp-with-credentials", dig(sp, "displayName"), "accountEnabled=false credentials=" + str(len(lst(dig(sp, "passwordCredentials"))) + len(lst(dig(sp, "keyCredentials")))), "the principal cannot sign in while disabled, but the credential material remains and works again if it is re-enabled")


@check("entra-dormant")
def c_dormant(ctx):
    users = graph_all("users?$select=userPrincipalName,accountEnabled,signInActivity", limit=10)
    if users is None:
        note("entra-dormant", 0, denied=1)
        return
    note("entra-dormant", len(users))
    enabled = [u for u in users if u.get("accountEnabled")]
    readable = [u for u in enabled if (val(dig(dig(u, "signInActivity"), "lastSignInDateTime"), "")
                                          or val(dig(dig(u, "signInActivity"), "lastNonInteractiveSignInDateTime"), ""))]
    if enabled and not readable:
        add("low", "signin-activity-unreadable", "tenant", str(len(enabled)) + " enabled users, 0 with signInActivity", "dormancy cannot be assessed without AuditLog.Read.All")
        return
    cutoff = time.time() - 90 * 86400
    dormant = []
    stale = []
    for u in enabled:
        act = dig(u, "signInActivity")
        last = str(val(dig(act, "lastSignInDateTime"), ""))
        machine = str(val(dig(act, "lastNonInteractiveSignInDateTime"), ""))
        newest = max(_stamp(last) or 0.0, _stamp(machine) or 0.0)
        if not newest:
            dormant.append(u)
        elif newest < cutoff:
            stale.append((u, newest))
    for u in dormant[:20]:
        add("low", "account-never-signed-in", dig(u, "userPrincipalName"), "no interactive or non-interactive signInActivity", "enabled account with no recorded sign-in")
    for u, newest in stale[:20]:
        add("medium", "account-stale-90d", dig(u, "userPrincipalName"), "lastSignIn=" + _iso(newest), "enabled account unused for more than 90 days")
    sample("entra-dormant", min(len(dormant), 20) + min(len(stale), 20), len(dormant) + len(stale), "dormant accounts")


@check("sub-automation")
def c_automation(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.automation/automationaccounts' | project name, subscriptionId, rg=resourceGroup, identity=identity", ctx["subs"])
    if rows is None:
        note("sub-automation", 0, denied=1)
        return
    note("sub-automation", len(rows))
    for r in rows:
        base = ARM_BASE + "/subscriptions/" + str(r.get("subscriptionId")) + "/resourceGroups/" + str(r.get("rg")) + "/providers/Microsoft.Automation/automationAccounts/" + str(r.get("name"))
        rb = az(["rest", "--url", base + "/runbooks?api-version=2019-06-01"])
        if rb is None:
            deny("sub-automation")
            continue
        n = len(rb.get("value") or [])
        ident = r.get("identity") or {}
        add("info", "automation-account", r.get("name"), "runbooks=" + str(n) + " identity=" + str(ident.get("type")), "runbooks execute with the account identity; review their code", r.get("subscriptionId"))
        if n and not ident:
            add("medium", "automation-no-identity", r.get("name"), "runbooks=" + str(n) + " identity=none", "runbooks likely store credentials inline", r.get("subscriptionId"))


@check("sub-webapp-settings")
def c_webapp_settings(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.web/sites' | project name, subscriptionId, rg=resourceGroup", ctx["subs"])
    if rows is None:
        note("sub-webapp-settings", 0, denied=1)
        return
    note("sub-webapp-settings", min(len(rows), 20))
    sample("sub-webapp-settings", min(len(rows), 20), len(rows), "web apps")
    for r in rows[:20]:
        url = ARM_BASE + "/subscriptions/" + str(r.get("subscriptionId")) + "/resourceGroups/" + str(r.get("rg")) + "/providers/Microsoft.Web/sites/" + str(r.get("name")) + "/config/appsettings/list?api-version=2022-09-01"
        LAST_QUERY[CURRENT["check"]] = "az rest --method post --url " + repr(url) + " --body '{}'"
        doc = az(["rest", "--method", "post", "--url", url, "--body", "{}"])
        if doc is None:
            deny("sub-webapp-settings")
            continue
        props = doc.get("properties") or {}
        hits = [k for k, v in props.items()
                if isinstance(v, str) and not v.startswith("@Microsoft.KeyVault(")
                and ((len(v) > 20 and SECRET_MATERIAL.search(v))
                or (not SECRET_NOISE.search(str(k)) and SECRET_PAT.search(str(k))
                    and len(v) > 8 and not v.lower().startswith("http")))]
        if hits:
            add("high", "appsetting-plaintext-secret", r.get("name"), "keys=" + ",".join(sorted(hits)[:6]), "secrets stored in app settings, readable by anyone with website config read", r.get("subscriptionId"))


@check("sub-activity-alerts")
def c_activity_alerts(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.insights/activitylogalerts' | project name, subscriptionId, enabled=tostring(properties.enabled)", ctx["subs"])
    if rows is None:
        note("sub-activity-alerts", 0, denied=1)
        return
    note("sub-activity-alerts", len(rows))
    if not rows:
        add("medium", "no-activity-log-alerts", "all", "0 alert rules", "privileged changes raise no alert", "tenant")
    for r in rows:
        if tri(dig(r, "enabled")) is False:
            add("low", "alert-disabled", r.get("name"), "enabled=" + str(r.get("enabled")), "rule exists but is disabled", r.get("subscriptionId"))


@check("sub-defender-contacts")
def c_defender_contacts(ctx):
    res = per_sub(ctx["subs"], "providers/Microsoft.Security/securityContacts", "2020-01-01-preview", lambda d: d.get("value") or [])
    note("sub-defender-contacts", sum(1 for v in res.values() if v is not None), denied=sum(1 for v in res.values() if v is None))
    for s, items in res.items():
        if items == []:
            add("medium", "no-security-contact", s, "0 security contacts", "high-severity alerts have no recipient", s)


@check("sub-storage-lifecycle")
def c_storage_lifecycle(ctx):
    q = "Resources | where type =~ 'microsoft.storage/storageaccounts/blobservices' | project name, subscriptionId, softBlob=tostring(properties.deleteRetentionPolicy.enabled), versioning=tostring(properties.isVersioningEnabled), retention=properties.deleteRetentionPolicy.days"
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-storage-lifecycle", 0, denied=1)
        return
    note("sub-storage-lifecycle", len(rows))
    for r in rows:
        if tri(r.get("softBlob")) is False:
            add("medium", "storage-blob-soft-delete-off", r.get("name"), "deleteRetentionPolicy.enabled=" + str(r.get("softBlob")), "deleted blobs unrecoverable", r.get("subscriptionId"))
        if tri(r.get("versioning")) is False:
            add("low", "storage-versioning-off", r.get("name"), "isVersioningEnabled=" + str(r.get("versioning")), "no object history for overwrite recovery", r.get("subscriptionId"))


@check("entra-pim-policy")
def c_pim_policy(ctx):
    pols = graph_all("policies/roleManagementPolicies?$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'", limit=5, beta=True)
    if pols is None:
        note("entra-pim-policy", 0, denied=1)
        return
    note("entra-pim-policy", min(len(pols), 10))
    sample("entra-pim-policy", min(len(pols), 10), len(pols), "role management policies")
    if not pols:
        add("info", "pim-policy-none", "tenant", "0 role management policies", "no activation rules configured")
    for p in pols[:10]:
        rules = p.get("rules") or []
        approval = any(tri(dig(rule, "isApprovalRequired")) is True for rule in rules if "approval" in str(dig(rule, "@odata.type")).lower())
        mfa = any("MultiFactorAuthentication" in [str(x) for x in lst(dig(rule, "enabledRules"))] for rule in rules)
        justification = any("Justification" in [str(x) for x in lst(dig(rule, "enabledRules"))] for rule in rules)
        add("info", "pim-policy", dig(p, "displayName"), "rules=" + str(len(rules)) + " approval=" + str(approval) + " mfaOnActivation=" + str(mfa) + " justification=" + str(justification), "activation requirements for privileged roles")
        if not mfa:
            add("medium", "pim-activation-no-mfa", dig(p, "displayName"), "enabledRules without MultiFactorAuthentication", "a privileged role activates without a second factor")


@check("entra-governance")
def c_governance(ctx):
    reviews = graph_all("identityGovernance/accessReviews/definitions", limit=3)
    packages = graph_all("identityGovernance/entitlementManagement/accessPackages", limit=3)
    catalogs = graph_all("identityGovernance/entitlementManagement/catalogs", limit=3)
    note("entra-governance", (len(reviews) if reviews else 0) + (len(packages) if packages else 0))
    if reviews is None or packages is None:
        add("info", "governance-not-assessed", "tenant", "endpoint unavailable", "access reviews and entitlement management not assessed (needs P2 or Governance)")
        return
    for r in reviews[:10]:
        add("info", "access-review", r.get("displayName"), "status=" + str(r.get("status")), "recertification definition")
    for pk in packages[:10]:
        add("info", "access-package", pk.get("displayName"), "id=" + str(pk.get("id")), "self-service grant surface; verify approval policy")
    add("info", "catalog-count", "tenant", "catalogs=" + str(len(lst(catalogs))), "entitlement management inventory")


@check("entra-group-settings")
def c_groupsettings(ctx):
    rows = graph_all("groupSettings", limit=3)
    if rows is None:
        note("entra-group-settings", 0, denied=1)
        return
    note("entra-group-settings", len(rows))
    if not rows:
        add("medium", "no-group-settings", "tenant", "0 directory settings", "defaults apply: users may create groups and invite guests")
    for g in rows:
        vals = {v.get("name"): v.get("value") for v in g.get("values") or []}
        for k, v in vals.items():
            if str(v).strip().lower() in ("true", "everyone", "on"):
                add("medium", "group-setting-permissive", k, "value=" + str(v), "directory-level permission for group operations")
            else:
                add("info", "group-setting", k, "value=" + str(v), "directory setting")


@check("entra-organization")
def c_org(ctx):
    org = graph("organization")
    if not org:
        note("entra-organization", 0, denied=1)
        return
    o = (org.get("value") or [{}])[0]
    note("entra-organization", 1)
    add("info", "organization", o.get("displayName"), "tenantType=" + str(o.get("tenantType")) + " onPremSync=" + str(o.get("onPremisesSyncEnabled")) + " lastSync=" + str(o.get("onPremisesLastSyncDateTime")), "tenant metadata")



@check("entra-deleted-users-roles")
def c_deleted_users(ctx):
    deleted = graph_all("directory/deletedItems/microsoft.graph.user?$select=id,userPrincipalName,deletedDateTime", limit=5)
    if deleted is None:
        note("entra-deleted-users-roles", 0, denied=1)
        return
    note("entra-deleted-users-roles", len(deleted))
    ids = {d.get("id") for d in deleted}
    if not ids:
        add("info", "no-deleted-users", "tenant", "0 soft-deleted users", "nothing to reconcile")
        return
    assignments = graph_all("roleManagement/directory/roleAssignments", limit=5)
    if assignments is None:
        note("entra-deleted-users-roles", len(deleted), denied=1)
        return
    for a in assignments:
        if a.get("principalId") in ids:
            add("high", "deleted-user-holds-role", str(a.get("principalId")), "role=" + str(a.get("roleDefinitionId")), "soft-deleted object still referenced by an assignment")


@check("sub-aks")
def c_aks(ctx):
    q = "Resources | where type =~ 'microsoft.containerservice/managedclusters' | project name, subscriptionId, localAccounts=tostring(properties.disableLocalAccounts), apiRanges=properties.apiServerAccessProfile.authorizedIpRanges, publicFqdn=tostring(properties.apiServerAccessProfile.enablePrivateCluster), rbac=tostring(properties.enableRBAC), fqdn=properties.fqdn"
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-aks", 0, denied=1)
        return
    note("sub-aks", len(rows))
    for r in rows:
        s = r.get("subscriptionId")
        if str(r.get("localAccounts") or "").lower() == "false":
            add("high", "aks-local-accounts-enabled", r.get("name"), "disableLocalAccounts=false", "cluster admin certificate bypasses Entra", s)
        elif not r.get("localAccounts"):
            add("low", "aks-local-accounts-unknown", r.get("name"), "disableLocalAccounts not set", "local accounts are enabled by default; confirm the cluster setting", s)
        is_private = str(r.get("publicFqdn") or "").lower() == "true"
        if is_private:
            add("info", "aks-private-cluster", r.get("name"), "enablePrivateCluster=true", "API server only reachable from the peered network", s)
        else:
            if not r.get("apiRanges"):
                add("high", "aks-public-api-server", r.get("name"), "enablePrivateCluster=false authorizedIpRanges=0 fqdn=" + str(r.get("fqdn")), "API server reachable from any address", s)
            else:
                add("info", "aks-api-ip-restricted", r.get("name"), "authorizedIpRanges=" + str(len(r.get("apiRanges") or [])), "API server limited to a source list", s)
        rbac = tri(r.get("rbac"))
        if rbac is False:
            add("high", "aks-kubernetes-rbac-disabled", r.get("name"), "enableRBAC=false", "no Kubernetes RBAC; every authenticated principal is cluster-admin", s)
        elif rbac is None:
            add("low", "aks-kubernetes-rbac-unknown", r.get("name"), "enableRBAC not returned", "RBAC state could not be read; confirm the cluster setting", s)


@check("sub-entra-ds")
def c_entra_ds(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.aad/domainservices' | project name, subscriptionId, props=properties", ctx["subs"])
    if rows is None:
        note("sub-entra-ds", 0, denied=1)
        return
    note("sub-entra-ds", len(rows))
    for r in rows:
        s = r.get("subscriptionId")
        p = r.get("props") or {}
        sec = p.get("domainSecuritySettings") or {}
        ldaps = p.get("ldapsSettings") or {}
        if tri(sec.get("ntlmV1Enabled")) is True:
            add("high", "entra-ds-ntlmv1", dig(r, "name"), "ntlmV1Enabled=true", "legacy NTLM accepted on the managed domain", s)
        if tri(sec.get("tlsV1Enabled")) is True:
            add("medium", "entra-ds-tlsv1", dig(r, "name"), "tlsV1Enabled=true", "legacy TLS accepted", s)
        if sec.get("syncNtlmPasswords") in ("Enabled", True):
            add("medium", "entra-ds-ntlm-sync", r.get("name"), "syncNtlmPasswords=Enabled", "NTLM hashes present; pass-the-hash against the managed domain", s)
        if ldaps.get("externalAccess") in ("Enabled", True):
            add("high", "entra-ds-ldaps-internet", r.get("name"), "ldapsSettings.externalAccess=Enabled", "LDAPS reachable from the internet", s)


@check("sub-management-groups")
def c_mg(ctx):
    url = ARM_BASE + "/providers/Microsoft.Management/managementGroups?api-version=2021-04-01"
    LAST_QUERY[CURRENT["check"]] = "az rest --url " + repr(url)
    groups = []
    pages = 0
    while url and pages < 20:
        doc = arm(url)
        if doc is None:
            if not groups:
                note("sub-management-groups", 0, denied=1)
                return
            capped("sub-management-groups", len(groups), "management group pages")
            break
        groups.extend(lst(dig(doc, "value")))
        url = str(val(dig(doc, "nextLink"), ""))
        pages += 1
    if url:
        capped("sub-management-groups", len(groups), "management group pages")
    note("sub-management-groups", len(groups))
    for g in groups:
        add("info", "management-group", g.get("name"), "displayName=" + str((g.get("properties") or {}).get("displayName")), "hierarchy level; inherited assignments apply to every child")
    if not groups:
        add("info", "no-management-groups", "tenant", "0 management groups", "all subscriptions are flat")


@check("sub-azure-pim")
def c_azure_pim(ctx):
    q = "AuthorizationResources | where type =~ 'microsoft.authorization/roleeligibilityschedules' | where subscriptionId in (" + subq(ctx["subs"]) + ") | project name, subscriptionId, principalId=tostring(properties.principalId)"
    rows = arg_rows(q, ctx["subs"], scoped=False)
    if rows is None:
        note("sub-azure-pim", 0, denied=1)
        return
    note("sub-azure-pim", len(rows))
    if not rows:
        add("medium", "no-azure-pim-eligibility", "all", "0 eligibility schedules", "every Azure role assignment is permanent", "tenant")


@check("sub-kv-legacy")
def c_kv_legacy(ctx):
    q = "Resources | where type =~ 'microsoft.keyvault/vaults' | project name, subscriptionId, deploy=tostring(properties.enabledForDeployment), tpl=tostring(properties.enabledForTemplateDeployment), disk=tostring(properties.enabledForDiskEncryption)"
    rows2 = arg_rows(q, ctx["subs"])
    if rows2 is None:
        note("sub-kv-legacy", 0, denied=1)
        return
    note("sub-kv-legacy", len(rows2))
    for r in rows2:
        for key, label in (("deploy", "enabledForDeployment"), ("tpl", "enabledForTemplateDeployment"), ("disk", "enabledForDiskEncryption")):
            if r.get(key) == "true":
                add("medium", "keyvault-legacy-access", r.get("name"), label + "=true", "ARM can read secrets for deployments, widening the trust boundary", r.get("subscriptionId"))


@check("sub-appservice-basic-auth")
def c_basic_auth(ctx):
    q = "Resources | where type =~ 'microsoft.web/sites' | project name, subscriptionId, rg=resourceGroup"
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-appservice-basic-auth", 0, denied=1)
        return
    note("sub-appservice-basic-auth", len(rows))
    for r in rows[:15]:
        url = ARM_BASE + "/subscriptions/" + str(r.get("subscriptionId")) + "/resourceGroups/" + str(r.get("rg")) + "/providers/Microsoft.Web/sites/" + str(r.get("name")) + "/basicPublishingCredentialsPolicies?api-version=2022-09-01"
        doc = az(["rest", "--url", url])
        if doc is None:
            deny("sub-appservice-basic-auth")
            continue
        for pol in doc.get("value") or []:
            if (pol.get("properties") or {}).get("allow"):
                add("medium", "appservice-basic-auth-allowed", r.get("name"), "policy=" + str(pol.get("name")) + " allow=true", "publishing credentials bypass Entra", r.get("subscriptionId"))
    sample("sub-appservice-basic-auth", min(len(rows), 15), len(rows), "web apps")


@check("sub-sentinel")
def c_sentinel(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.securityinsights/onboardings' | project name, subscriptionId", ctx["subs"])
    if rows is None:
        note("sub-sentinel", 0, denied=1)
        return
    note("sub-sentinel", len(rows))
    if not rows:
        add("medium", "no-sentinel", "all", "0 Sentinel onboardings", "no SIEM attached to the subscriptions", "tenant")


@check("sub-waf")
def c_waf(ctx):
    q = """Resources
| where subscriptionId in (""" + subq(ctx["subs"]) + """)
| where type =~ 'microsoft.network/frontdoors' or type =~ 'microsoft.network/applicationgateways' or type =~ 'microsoft.cdn/profiles'
| project name, type, subscriptionId, props=properties"""
    rows = arg_rows(q, ctx["subs"], scoped=False)
    if rows is None:
        note("sub-waf", 0, denied=1)
        return
    note("sub-waf", len(rows))
    for r in rows:
        props = dig(r, "props")
        modes = [str(val(dig(props, "webApplicationFirewallConfiguration.firewallMode"), "")),
                 str(val(dig(props, "policySettings.mode"), "")),
                 str(val(dig(props, "webApplicationFirewallPolicyLink"), ""))]
        mode = next((m for m in modes if m and not m.startswith("/")), "")
        s = str(dig(r, "subscriptionId"))
        if mode.lower() == "detection":
            add("high", "waf-detection-mode", dig(r, "name"), "type=" + str(dig(r, "type")).split("/")[-1] + " mode=" + mode, "malicious requests are logged, not blocked", s)
        elif not mode and not dig(props, "firewallPolicy") and not dig(props, "webApplicationFirewallPolicyLink"):
            add("medium", "waf-not-configured", dig(r, "name"), "type=" + str(dig(r, "type")).split("/")[-1] + " no inline config or policy link", "no web application firewall is attached", s)


@check("sub-template-specs")
def c_templatespecs(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.resources/templatespecs' or type =~ 'microsoft.resources/templatespecversions' | project name, type, subscriptionId", ctx["subs"])
    if rows is None:
        note("sub-template-specs", 0, denied=1)
        return
    note("sub-template-specs", len(rows))
    for r in rows:
        add("info", "template-spec", dig(r, "name"), "type=" + str(dig(r, "type")).split("/")[-1], "reusable deployment content", str(dig(r, "subscriptionId")))
    deployments = arg_rows("Resources | where type =~ 'microsoft.resources/deployments' | project name, subscriptionId, params=properties.parameters, template=properties.template", ctx["subs"])
    if deployments is None:
        denied_now("sub-template-specs")
        return
    for d in deployments:
        s = str(dig(d, "subscriptionId"))
        params = dig(d, "params")
        if isinstance(params, dict):
            for key, node in params.items():
                value = dig(node, "value")
                named = bool(SECRET_PAT.search(str(key))) and not SECRET_NOISE.search(str(key))
                literal = isinstance(value, str) and len(value) > 8 and not value.lower().startswith("http")
                if named and literal:
                    add("high", "deployment-parameter-secret", str(dig(d, "name")), "parameter=" + str(key), "a credential is passed as a plain deployment parameter and is retained in deployment history", s)
        blob = str(dig(d, "template"))
        if "reference(" in blob and "listKeys" in blob:
            add("low", "deployment-listkeys", str(dig(d, "name")), "template calls listKeys", "the deployment reads account keys at runtime", s)


@check("entra-ca-matrix")
def c_ca_matrix(ctx):
    pols = ca_all("policies", limit=5)
    if pols is None:
        note("entra-ca-matrix", 0, denied=1)
        return
    enabled = [p for p in pols if p.get("state") == "enabled"]
    note("entra-ca-matrix", len(enabled))
    apps = {}
    for target, label in (
        ("00000003-0000-0000-c000-000000000000", "Microsoft Graph"),
        ("00000002-0000-0ff1-ce00-000000000000", "Exchange Online"),
        ("797f4846-ba00-4fd7-ba43-dac1f8f63013", "Azure Service Management"),
        ("00000003-0000-0ff1-ce00-000000000000", "SharePoint Online"),
    ):
        covering = []
        for p in enabled:
            applications = dig(p, "conditions.applications")
            inc = lst(dig(applications, "includeApplications"))
            exc = lst(dig(applications, "excludeApplications"))
            if ("All" in inc or target in inc) and target not in exc:
                holes = len(lst(dig(p, "conditions.users.excludeUsers"))) + len(lst(dig(p, "conditions.users.excludeGroups"))) + len(exc)
                covering.append(str(dig(p, "displayName")) + ("(exclusions=" + str(holes) + ")" if holes else ""))
        apps[label] = covering
        if not covering:
            if not pols:
                add("low", "ca-app-unverifiable", label, "0 policies returned by the tenant", "coverage cannot be assessed; read the policy list first")
            else:
                excluded = [str(dig(p, "displayName")) for p in enabled if target in [str(x) for x in lst(dig(p, "conditions.applications.excludeApplications"))]]
                add("high", "ca-app-uncovered", label, "policies=" + str(len(pols)) + " enabled=" + str(len(enabled)) + (" excludedBy=" + ",".join(excluded)[:60] if excluded else ""), "no enforced policy includes this application" + ("; it is excluded explicitly" if excluded else ""))
        else:
            add("info", "ca-app-coverage", label, "policies=" + str(len(covering)) + " first=" + str(covering[0]), "coverage present; exclusions in brackets are bypasses")
    users_with_exclusion = 0
    for p in enabled:
        u = (p.get("conditions") or {}).get("users") or {}
        users_with_exclusion += len([x for x in (u.get("excludeUsers") or []) if x])
    if users_with_exclusion:
        add("medium", "ca-user-exclusions", "tenant", "excluded user entries=" + str(users_with_exclusion), "each exclusion is a bypass for that account")


@check("entra-per-user-mfa-methods")
def c_peruser_mfa(ctx):
    users = graph_all("users?$select=id,userPrincipalName,accountEnabled", limit=10)
    if users is None:
        note("entra-per-user-mfa-methods", 0, denied=1)
        return
    note("entra-per-user-mfa-methods", len(users))
    for u in users[:15]:
        doc = graph("users/" + str(dig(u, "id")) + "/authentication/methods")
        if doc is None:
            denied_now("entra-per-user-mfa-methods")
            continue
        methods = [str(dig(m, "@odata.type") or "").split(".")[-1] for m in lst(dig(doc, "value"))]
        strong = [m for m in methods if m in ("fido2AuthenticationMethod", "windowsHelloForBusinessAuthenticationMethod")]
        if not strong:
            add("medium", "no-phishing-resistant-method-sampled", dig(u, "userPrincipalName"), "methods=" + ",".join(methods)[:60], "MFA relies on OTP, SMS or password only")
    sample("entra-per-user-mfa-methods", min(len(users), 15), len(users), "users")


@check("entra-domain-dns")
def c_domain_dns(ctx):
    rows = graph_all("domains?$select=id,isVerified,isDefault,authenticationType,isAdminManaged", limit=3)
    if rows is None:
        note("entra-domain-dns", 0, denied=1)
        return
    note("entra-domain-dns", len(rows))
    for d in rows:
        name = str(dig(d, "id"))
        if dig(d, "isVerified") is not True:
            continue
        add("info", "domain-dns-manual", name, "verification TXT not re-resolved", "confirm the TXT or MX record still exists before treating the domain as stable")


@check("sub-storage-advanced")
def c_storage_advanced(ctx):
    q = """Resources
| where type =~ 'microsoft.storage/storageaccounts'
| project name, subscriptionId, sftp=tostring(properties.isSftpEnabled), localUser=tostring(properties.isLocalUserEnabled),
          nfs=tostring(properties.isNfsV3Enabled), keySource=tostring(properties.encryption.keySource),
          infra=tostring(properties.encryption.requireInfrastructureEncryption),
          https=tostring(properties.supportsHttpsTrafficOnly), sas=tostring(properties.sasPolicy.sasExpirationPeriod),
          sharedKey=tostring(properties.allowSharedKeyAccess), blobPublic=tostring(properties.allowBlobPublicAccess),
          filesAuth=tostring(properties.azureFilesIdentityBasedAuthentication.directoryServiceOptions)"""
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-storage-advanced", 0, denied=1)
        return
    note("sub-storage-advanced", len(rows))
    for r in rows:
        s = r.get("subscriptionId")
        n = r.get("name")
        if r.get("sftp") == "true":
            add("medium", "storage-sftp-enabled", n, "isSftpEnabled=true", "SFTP endpoint with local users widens the auth surface", s)
        if r.get("localUser") == "true":
            add("medium", "storage-local-users-enabled", n, "isLocalUserEnabled=true", "SMB local identities bypass Entra", s)
        if r.get("nfs") == "true":
            add("low", "storage-nfs-enabled", n, "isNfsV3Enabled=true", "NFS has no Entra authentication", s)
        if str(r.get("keySource") or "").lower() == "microsoft.keyvault":
            add("info", "storage-cmk", n, "keySource=Microsoft.KeyVault", "customer-managed key in use", s)
        else:
            add("low", "storage-microsoft-managed-key", n, "keySource=" + str(val(dig(r, "keySource"), "unset")), "no customer-managed key", s)
        if str(r.get("infra") or "").lower() == "false":
            add("low", "storage-no-infrastructure-encryption", n, "requireInfrastructureEncryption=false", "double encryption not enforced", s)
        if tri(r.get("https")) is False:
            add("high", "storage-http-allowed", n, "supportsHttpsTrafficOnly=false", "plaintext storage traffic accepted", s)
        auth = str(r.get("filesAuth") or "").upper()
        if auth in ("", "NONE"):
            add("low", "storage-files-no-identity", n, "filesAuth=None", "SMB access uses the account key, not Entra identity", s)
        elif auth == "AADKERB":
            add("info", "storage-files-kerberos", n, "filesAuth=AADKERB", "SMB identity comes from Entra Domain Services; verify the domain join", s)
        if not dig(r, "sas"):
            add("low", "storage-no-sas-expiry", n, "sasPolicy.sasExpirationPeriod unset", "account SAS has no maximum lifetime", s)
        if not dig(r, "sharedKey"):
            add("low", "storage-sharedkey-unknown", n, "allowSharedKeyAccess not returned", "shared-key access is enabled by default; confirm the setting", s)
        elif tri(dig(r, "sharedKey")) is True:
            add("medium", "storage-shared-key-enabled", n, "allowSharedKeyAccess=true", "account keys can read and write all data", s)
        if not dig(r, "blobPublic"):
            add("low", "storage-blobpublic-unknown", n, "allowBlobPublicAccess not returned", "anonymous blob access is permitted by default; confirm the setting", s)
        elif tri(dig(r, "blobPublic")) is True:
            add("medium", "storage-blobpublic-enabled", n, "allowBlobPublicAccess=true", "a container can be made anonymous", s)
    q2 = "Resources | where type =~ 'microsoft.storage/storageaccounts/blobservices' | project name, subscriptionId, static=tostring(properties.staticWebsite.enabled)"
    rows2 = arg_rows(q2, ctx["subs"])
    for r in unread_list(rows2, "blob service settings", "storage-blobservices-unreadable"):
        if r.get("static") == "true":
            add("medium", "storage-static-website", r.get("name"), "staticWebsite.enabled=true", "public HTTP endpoint with no identity boundary", r.get("subscriptionId"))



@check("sub-sql-advanced")
def c_sql_advanced(ctx):
    q = "Resources | where type =~ 'microsoft.sql/servers' | project name, subscriptionId, rg=resourceGroup"
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-sql-advanced", 0, denied=1)
        return
    note("sub-sql-advanced", min(len(rows), 20))
    sample("sub-sql-advanced", min(len(rows), 20), len(rows), "SQL servers")
    for r in rows[:20]:
        base = ARM_BASE + "/subscriptions/" + str(r.get("subscriptionId")) + "/resourceGroups/" + str(r.get("rg")) + "/providers/Microsoft.Sql/servers/" + str(r.get("name"))
        atp = az(["rest", "--url", base + "/advancedThreatProtectionSettings/Default?api-version=2022-05-01-preview"])
        if atp is None:
            deny("sub-sql-advanced")
        elif str((atp.get("properties") or {}).get("state")) != "Enabled":
            add("medium", "sql-atp-disabled", r.get("name"), "advancedThreatProtection=" + str((atp.get("properties") or {}).get("state")), "no anomaly detection on the server", r.get("subscriptionId"))
        va = az(["rest", "--url", base + "/vulnerabilityAssessments/default?api-version=2022-05-01-preview"])
        if va is not None:
            p = va.get("properties") or {}
            if tri(dig(p, "recurringScans.isEnabled")) is not True or not dig(p, "storageContainerPath"):
                add("low", "sql-va-not-configured", r.get("name"), "vulnerabilityAssessment unset", "no recurring vulnerability scan", r.get("subscriptionId"))
        fg = az(["rest", "--url", base + "/failoverGroups?api-version=2022-05-01-preview"])
        if fg is not None:
            n = len(fg.get("value") or [])
            add("info", "sql-failover-groups", r.get("name"), "count=" + str(n), "regional resilience inventory", r.get("subscriptionId"))
        aad = az(["rest", "--url", base + "/azureADOnlyAuthentications/default?api-version=2022-05-01-preview"])
        if aad is not None:
            st = tri((aad.get("properties") or {}).get("azureADOnlyAuthentication"))
            add("info" if st is True else "medium", "sql-aad-only-auth", r.get("name"), "azureADOnlyAuthentication=" + str(st), "Entra-only authentication" if st is True else "SQL logins remain enabled or unset")
    sample("sub-sql-advanced", min(len(rows), 20), len(rows), "SQL servers")


@check("sub-automation-webhooks")
def c_webhooks(ctx):
    q = "Resources | where type =~ 'microsoft.automation/automationaccounts/webhooks' | project name, subscriptionId, enabled=tostring(properties.isEnabled), expiry=properties.expiryTime"
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-automation-webhooks", 0, denied=1)
        return
    note("sub-automation-webhooks", len(rows))
    for r in rows:
        if r.get("enabled") == "true":
            add("high", "automation-webhook-enabled", r.get("name"), "isEnabled=true expiry=" + str(r.get("expiry")), "unauthenticated URL triggers a runbook", r.get("subscriptionId"))
        else:
            add("low", "automation-webhook", r.get("name"), "isEnabled=" + str(r.get("enabled")), "webhook present", r.get("subscriptionId"))


@check("sub-private-dns")
def c_private_dns(ctx):
    zones = arg_rows("Resources | where type =~ 'microsoft.network/privatednszones' | project name, subscriptionId, records=properties.numberOfRecordSets", ctx["subs"])
    if zones is None:
        note("sub-private-dns", 0, denied=1)
        return
    links = arg_rows("Resources | where type =~ 'microsoft.network/privatednszones/virtualnetworklinks' | project name, subscriptionId, state=tostring(properties.virtualNetworkLinkState)", ctx["subs"])
    links_ok = links is not None
    if not links_ok:
        denied_now("sub-private-dns")
    links = lst(links)
    note("sub-private-dns", len(zones) + len(links))
    for z in zones:
        add("info", "private-dns-zone", z.get("name"), "recordSets=" + str(z.get("records")), "private resolution zone", z.get("subscriptionId"))
    if zones and not links and links_ok:
        add("medium", "private-dns-no-links", "all", "zones=" + str(len(zones)) + " links=0", "private zones exist but are not linked to any network")
    elif zones and not links_ok:
        add("low", "private-dns-links-unreadable", "all", "zones=" + str(len(zones)) + " links unreadable", "zone linkage cannot be confirmed")
    for l in links:
        if str(l.get("state") or "").lower() not in ("completed", ""):
            add("low", "private-dns-link-not-complete", l.get("name"), "state=" + str(l.get("state")), "resolution may not work for this link", l.get("subscriptionId"))


@check("sub-subnet-posture")
def c_subnets(ctx):
    q = """Resources
| where type =~ 'microsoft.network/virtualnetworks'
| mv-expand sn = properties.subnets
| project name, subscriptionId, subnet=tostring(sn.name), nsg=tostring(sn.properties.networkSecurityGroup.id), se=tostring(sn.properties.serviceEndpoints), pe=tostring(sn.properties.privateEndpointNetworkPolicies)"""
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-subnet-posture", 0, denied=1)
        return
    note("sub-subnet-posture", len(rows))
    for r in rows:
        sn = str(r.get("subnet") or "")
        if not r.get("nsg") and sn not in ("GatewaySubnet", "AzureFirewallSubnet", "AzureBastionSubnet", "AzureFirewallManagementSubnet"):
            add("medium", "subnet-without-nsg", str(r.get("name")) + "/" + sn, "networkSecurityGroup=null", "no NSG applies to this subnet", r.get("subscriptionId"))
        if r.get("se") and r.get("se") != "[]":
            add("info", "subnet-service-endpoints", str(r.get("name")) + "/" + sn, "serviceEndpoints=" + str(r.get("se"))[:60], "service endpoint routes bypass the firewall", r.get("subscriptionId"))
        if str(r.get("pe") or "").lower() == "disabled":
            add("low", "subnet-private-endpoint-policy-disabled", str(r.get("name")) + "/" + sn, "privateEndpointNetworkPolicies=Disabled", "NSG rules are not applied to private endpoints here", r.get("subscriptionId"))


@check("sub-abac-conditions")
def c_abac(ctx):
    q = """AuthorizationResources
| where type =~ 'microsoft.authorization/roleassignments'
| where subscriptionId in (""" + subq(ctx["subs"]) + """)
| project principalId=tostring(properties.principalId), principalType=tostring(properties.principalType), roleId=tostring(properties.roleDefinitionId), scope=tostring(properties.scope), condition=tostring(properties.condition)"""
    rows = arg_rows(q, ctx["subs"], scoped=False)
    if rows is None:
        note("sub-abac-conditions", 0, denied=1)
        return
    note("sub-abac-conditions", len(rows))
    for r in rows:
        if r.get("condition"):
            add("info", "abac-condition", r.get("principalId"), "condition=" + str(r.get("condition"))[:70], "assignment is narrowed by an attribute condition", ctx_sub(r), r.get("scope"))
        if str(r.get("principalType") or "") in ("Unknown", "ForeignGroup"):
            add("high", "foreign-or-unknown-principal", r.get("principalId"), "principalType=" + str(r.get("principalType")) + " scope=" + str(r.get("scope")), "assignment to an external or unresolved principal", ctx_sub(r), r.get("scope"))


@check("sub-lighthouse-assignments")
def c_lh_assign(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.managedservices/registrationassignments' | project name, subscriptionId, props=properties", ctx["subs"])
    if rows is None:
        note("sub-lighthouse-assignments", 0, denied=1)
        return
    note("sub-lighthouse-assignments", len(rows))
    defs = arg_rows("Resources | where type =~ 'microsoft.managedservices/registrationdefinitions' | project id=tolower(id), tenant=tostring(properties.managedByTenantId)", ctx["subs"])
    managers = {}
    if defs is None:
        denied_now("sub-lighthouse-assignments")
    else:
        for d in defs:
            managers[str(val(dig(d, "id"), "")).lower()] = str(val(dig(d, "tenant"), ""))
    for r in rows:
        p = r.get("props") or {}
        definition = str(val(dig(p, "registrationDefinitionId"), ""))
        manager = managers.get(definition.lower(), "")
        if defs is None:
            continue
        rel = tenant_rel(manager)
        if rel == "home":
            add("info", "lighthouse-assignment-same-tenant", str(dig(r, "name")), "managedByTenantId=" + manager + " definition=" + definition, "the managing tenant is this tenant", str(dig(r, "subscriptionId")))
            continue
        if not manager:
            add("low", "lighthouse-assignment-unresolved", str(dig(r, "name")), "definition=" + definition + " managedByTenantId unreadable", "the assignment exists but the managing tenant could not be resolved; it is not reported as external", str(dig(r, "subscriptionId")))
            continue
        if rel == "unknown":
            undecided("lighthouse-assignment-tenant-unknown", "definition=" + definition, "the home tenant was not read, so the managing tenant cannot be classified")
            continue
        add("high", "lighthouse-assignment", str(dig(r, "name")), "definition=" + definition + " managedByTenantId=" + manager + " scope=" + str(val(dig(p, "registrationDefinitionName"), "")), "an external tenant actively manages this scope", str(dig(r, "subscriptionId")))
    if not rows:
        add("info", "no-lighthouse-assignment", "all", "0 registration assignments", "no delegated external management", "tenant")


@check("sub-resource-diagnostics")
def c_resource_diag(ctx):
    q = """Resources
| where subscriptionId in (""" + subq(ctx["subs"]) + """)
| where type in~ ('microsoft.storage/storageaccounts','microsoft.keyvault/vaults','microsoft.sql/servers','microsoft.containerregistry/registries','microsoft.containerservice/managedclusters','microsoft.network/azurefirewalls','microsoft.web/sites')
| project name, type, subscriptionId, rg=resourceGroup, id"""
    rows = arg_rows(q, ctx["subs"], scoped=False)
    if rows is None:
        note("sub-resource-diagnostics", 0, denied=1)
        return
    checked = 0
    for r in rows[:25]:
        url = ARM_BASE + str(r.get("id")) + "/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview"
        doc = az(["rest", "--url", url])
        if doc is None:
            deny("sub-resource-diagnostics")
            continue
        checked += 1
        settings = doc.get("value") or []
        cats = []
        for item in settings:
            for log in ((item.get("properties") or {}).get("logs") or []):
                if log.get("enabled"):
                    cats.append(log.get("category"))
        if not settings:
            add("medium", "resource-no-diagnostics", str(r.get("name")) + " " + str(r.get("type")).split("/")[-1], "0 diagnostic settings", "resource-level events are not retained", r.get("subscriptionId"))
        elif not cats:
            add("low", "resource-diagnostics-no-logs", r.get("name"), "settings=" + str(len(settings)) + " categories=0", "settings exist without log categories", r.get("subscriptionId"))
    note("sub-resource-diagnostics", checked, denied=DENIED["sub-resource-diagnostics"])
    sample("sub-resource-diagnostics", min(len(rows), 25), len(rows), "resources")


@check("sub-defender-assessments")
def c_assessments(ctx):
    res = per_sub(ctx["subs"], "providers/Microsoft.Security/assessments", "2021-06-01", lambda d: d.get("value") or [])
    note("sub-defender-assessments", sum(1 for v in res.values() if v is not None), denied=sum(1 for v in res.values() if v is None))
    for s, items in res.items():
        for a in items or []:
            p = a.get("properties") or {}
            if (p.get("status") or {}).get("code") == "Unhealthy":
                add("medium", "defender-unhealthy-assessment", p.get("displayName"), "assessment=" + str(a.get("name"))[:40], "Defender reports this control as failing", s)


@check("sub-sql-databases")
def c_sql_db(ctx):
    q = "Resources | where type =~ 'microsoft.sql/servers/databases' | where name != 'master' | extend seg=split(id, '/') | project name, subscriptionId, rg=resourceGroup, server=tostring(seg[8]), ledger=tostring(properties.ledgerOn)"
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-sql-databases", 0, denied=1)
        return
    note("sub-sql-databases", min(len(rows), 20))
    sample("sub-sql-databases", min(len(rows), 20), len(rows), "databases")
    for r in rows[:20]:
        base = ARM_BASE + "/subscriptions/" + str(r.get("subscriptionId")) + "/resourceGroups/" + str(r.get("rg")) + "/providers/Microsoft.Sql/servers/" + str(r.get("server")) + "/databases/" + str(r.get("name"))
        tde = az(["rest", "--url", base + "/transparentDataEncryption/current?api-version=2021-11-01"])
        if tde is None:
            deny("sub-sql-databases")
        elif str((tde.get("properties") or {}).get("state")) != "Enabled":
            add("high", "sql-db-tde-disabled", r.get("name"), "TDE state=" + str((tde.get("properties") or {}).get("state")), "database files unprotected at rest", r.get("subscriptionId"))
        if tri(r.get("ledger")) is False:
            add("low", "sql-db-no-ledger", r.get("name"), "ledgerOn=" + str(r.get("ledger")), "no tamper-evident audit", r.get("subscriptionId"))
    sample("sub-sql-databases", min(len(rows), 20), len(rows), "databases")


@check("sub-disks")
def c_disks(ctx):
    q = "Resources | where type =~ 'microsoft.compute/disks' | project name, subscriptionId, netAccess=tostring(properties.networkAccessPolicy)"
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-disks", 0, denied=1)
        return
    note("sub-disks", len(rows))
    for r in rows:
        if str(r.get("netAccess") or "") == "AllowAll":
            add("high", "disk-public-export", r.get("name"), "networkAccessPolicy=AllowAll", "a SAS URL can export the disk from any network", r.get("subscriptionId"))


@check("sub-webapp-slots")
def c_slots(ctx):
    q = "Resources | where type =~ 'microsoft.web/sites/slots' | project name, subscriptionId, rg=resourceGroup, id=id, https=properties.httpsOnly"
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-webapp-slots", 0, denied=1)
        return
    note("sub-webapp-slots", min(len(rows), 25))
    sample("sub-webapp-slots", min(len(rows), 25), len(rows), "slots")
    for r in rows[:25]:
        https = tri(r.get("https"))
        if https is False:
            add("medium", "slot-http-allowed", r.get("name"), "httpsOnly=false", "slot accepts plaintext traffic", r.get("subscriptionId"))
        elif https is None:
            add("low", "slot-http-unknown", r.get("name"), "httpsOnly not returned", "slot transport cannot be confirmed", r.get("subscriptionId"))
        url = ARM_BASE + str(r.get("id")) + "/config/web?api-version=2022-09-01"
        LAST_QUERY[CURRENT["check"]] = "az rest --url " + repr(url)
        cfg = az(["rest", "--url", url])
        if cfg is None:
            deny("sub-webapp-slots")
            continue
        if str((cfg.get("properties") or {}).get("ftpsState") or "") == "AllAllowed":
            add("medium", "slot-ftp-enabled", r.get("name"), "ftpsState=AllAllowed", "slot allows FTP", r.get("subscriptionId"))
    sample("sub-webapp-slots", min(len(rows), 25), len(rows), "slots")


@check("sub-acr")
def c_acr(ctx):
    q = "Resources | where type =~ 'microsoft.containerregistry/registries' | project name, subscriptionId, anon=tostring(properties.anonymousPullEnabled), net=tostring(properties.networkRuleSet.defaultAction), trust=tostring(properties.policies.trustPolicy.status), quarantine=tostring(properties.policies.quarantinePolicy.status)"
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-acr", 0, denied=1)
        return
    note("sub-acr", len(rows))
    for r in rows:
        s = r.get("subscriptionId")
        if r.get("anon") == "true":
            add("high", "acr-anonymous-pull", r.get("name"), "anonymousPullEnabled=true", "images readable without authentication", s)
        if str(r.get("net") or "") == "Allow":
            add("medium", "acr-open-network", r.get("name"), "networkRuleSet.defaultAction=Allow", "registry reachable from any network", s)
        if str(r.get("trust") or "") != "enabled":
            add("low", "acr-content-trust-off", r.get("name"), "trustPolicy=" + str(r.get("trust")), "image signatures not enforced", s)
        if str(r.get("quarantine") or "") != "enabled":
            add("low", "acr-quarantine-off", r.get("name"), "quarantinePolicy=" + str(r.get("quarantine")), "unscanned images usable", s)


@check("sub-waf-policies")
def c_wafpol(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.network/frontdoorwebapplicationfirewallpolicies' | project name, subscriptionId, mode=tostring(properties.policySettings.mode), enabled=tostring(properties.policySettings.enabledState)", ctx["subs"])
    if rows is None:
        note("sub-waf-policies", 0, denied=1)
        return
    note("sub-waf-policies", len(rows))
    for r in rows:
        if str(r.get("mode") or "").lower() == "detection":
            add("high", "waf-policy-detection", r.get("name"), "mode=Detection enabled=" + str(r.get("enabled")), "WAF logs attacks but does not block them", r.get("subscriptionId"))
        if str(r.get("enabled") or "").lower() != "enabled":
            add("high", "waf-policy-disabled", r.get("name"), "enabledState=" + str(r.get("enabled")), "policy attached but inactive", r.get("subscriptionId"))


@check("sub-firewall-rules")
def c_fwrules(ctx):
    q = """Resources
| where type =~ 'microsoft.network/firewallpolicies/rulecollectiongroups'
| mv-expand rc = properties.ruleCollections
| mv-expand rule = rc.rules
| extend action=tostring(rc.action.type), src=tostring(rule.sourceAddresses), dst=tostring(rule.destinationAddresses), port=tostring(rule.destinationPorts), fqdn=tostring(rule.targetFqdns), rtype=tostring(rc.ruleCollectionType)
| project name, subscriptionId, collection=tostring(rc.name), rule=tostring(rule.name), action, src, dst, port, fqdn, rtype"""
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-firewall-rules", 0, denied=1)
        return
    note("sub-firewall-rules", len(rows))
    for r in rows:
        if str(r.get("action") or "").lower() != "allow":
            continue
        src = str(r.get("src") or "")
        dst = str(r.get("dst") or "")
        port = str(r.get("port") or "")
        s = str(dig(r, "subscriptionId"))
        label = str(dig(r, "name")) + " " + str(dig(r, "rule"))
        if ("*" in src or "0.0.0.0/0" in src) and ("*" in dst or "0.0.0.0/0" in dst) and ("*" in port or "any" in port.lower()):
            add("high", "firewall-allow-any", label, "src=" + src[:30] + " dst=" + dst[:30] + " port=" + port[:20], "firewall permits any to any", s)
        fqdn = str(val(dig(r, "fqdn"), ""))
        if fqdn:
            targets = [t.strip(' []"\'') for t in fqdn.strip("[]").split(",") if t.strip(' []"\'')]
            wild = [t for t in targets if t.startswith("*.") or t == "*"]
            broad = [t for t in wild if t.count(".") <= 2]
            if broad:
                add("high", "firewall-fqdn-wildcard-broad", label, "targets=" + ",".join(broad[:3]), "the application rule permits an entire top-level domain space", s)
            elif wild:
                add("medium", "firewall-fqdn-wildcard", label, "targets=" + ",".join(wild[:3]), "the application rule permits every host under a domain", s)


@check("sub-flexible-servers")
def c_flex(ctx):
    q = """Resources
| where subscriptionId in (""" + subq(ctx["subs"]) + """)
| where type in~ ('microsoft.dbforpostgresql/flexibleservers','microsoft.dbformysql/flexibleservers')
| project name, type, subscriptionId, publicNet=tostring(properties.network.publicNetworkAccess), tls=tostring(properties.requireSecureTransport), pwdAuth=tostring(properties.authConfig.passwordAuth), aadAuth=tostring(properties.authConfig.activeDirectoryAuth)"""
    rows = arg_rows(q, ctx["subs"], scoped=False)
    if rows is None:
        note("sub-flexible-servers", 0, denied=1)
        return
    note("sub-flexible-servers", len(rows))
    for r in rows:
        s = r.get("subscriptionId")
        if str(r.get("publicNet") or "") in ("0.0.0.0", "Enabled", "All"):
            add("medium", "db-public-access", r.get("name"), "publicNetworkAccess=" + str(r.get("publicNet")), "database reachable from the internet", s)
        if str(r.get("tls") or "").lower() == "false":
            add("high", "db-no-tls", r.get("name"), "requireSecureTransport=false", "credentials and data in plaintext", s)
        pwd = str(val(dig(r, "pwdAuth"), "")).lower()
        aad = str(val(dig(r, "aadAuth"), "")).lower()
        if pwd == "enabled" and aad != "enabled":
            add("high", "db-password-only-auth", dig(r, "name"), "passwordAuth=Enabled aadAuth=" + (aad or "unset"), "the only authentication path is a stored password", s)
        elif pwd == "enabled" and aad == "enabled":
            add("medium", "db-password-auth-enabled", dig(r, "name"), "passwordAuth=Enabled aadAuth=Enabled", "password authentication still accepted alongside Entra", s)
        elif pwd == "disabled":
            add("info", "db-aad-only", r.get("name"), "passwordAuth=Disabled", "Entra-only authentication", s)


@check("sub-arc")
def c_arc(ctx):
    q = "Resources | where type =~ 'microsoft.hybridcompute/machines' or type =~ 'microsoft.kubernetes/connectedclusters' | project name, type, subscriptionId, status=tostring(properties.status), agent=tostring(properties.agentVersion)"
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-arc", 0, denied=1)
        return
    note("sub-arc", len(rows))
    for r in rows:
        add("info", "arc-resource", r.get("name"), "type=" + str(r.get("type")).split("/")[-1] + " status=" + str(r.get("status")), "on-prem or multi-cloud asset represented in Azure; extensions not assessed", r.get("subscriptionId"))


@check("sub-data-platforms")
def c_dataplatforms(ctx):
    q = """Resources
| where subscriptionId in (""" + subq(ctx["subs"]) + """)
| where type in~ ('microsoft.datafactory/factories','microsoft.synapse/workspaces','microsoft.apimanagement/service','microsoft.databricks/workspaces')
| project name, type, subscriptionId, publicNet=tostring(properties.publicNetworkAccess), managedVnet=tostring(properties.managedVirtualNetwork)"""
    rows = arg_rows(q, ctx["subs"], scoped=False)
    if rows is None:
        note("sub-data-platforms", 0, denied=1)
        return
    note("sub-data-platforms", len(rows))
    for r in rows:
        t = str(r.get("type")).split("/")[-1]
        exposure = tri(dig(r, "publicNet"))
        if exposure is True or str(val(dig(r, "publicNet"), "")).lower() == "enabled":
            add("medium", "data-platform-public", str(r.get("name")) + " " + t, "publicNetworkAccess=" + str(val(dig(r, "publicNet"), "Enabled")), "data platform reachable from the internet", r.get("subscriptionId"))
        elif exposure is None:
            add("low", "data-platform-public-unknown", str(dig(r, "name")) + " " + t, "publicNetworkAccess not returned or unrecognised", "exposure cannot be assessed from the control plane", str(dig(r, "subscriptionId")))
        if not r.get("managedVnet"):
            add("low", "data-platform-no-managed-vnet", str(r.get("name")) + " " + t, "managedVirtualNetwork=none", "no isolation between integration runtimes", r.get("subscriptionId"))


@check("sub-backup-coverage")
def c_backup_coverage(ctx):
    inv = arg_rows("Resources | where subscriptionId in (" + subq(ctx["subs"]) + ") | where type in~ ('microsoft.compute/virtualmachines','microsoft.sql/servers/databases','microsoft.storage/storageaccounts') | where name != 'master' | summarize n=count() by type, subscriptionId", ctx["subs"], scoped=False)
    if inv is None:
        note("sub-backup-coverage", 0, denied=1)
        return
    note("sub-backup-coverage", len(inv))
    prot = unread(arg_rows("Resources | where type =~ 'microsoft.recoveryservices/vaults/backuppolicies' or type =~ 'microsoft.dataprotection/backupvaults/backuppolicies' | summarize n=count() by subscriptionId", ctx["subs"]),
                  "backup policies", "backup-policies-unreadable")
    if prot is None:
        return
    pol_by_sub = {}
    for r in prot:
        s = str(dig(r, "subscriptionId"))
        pol_by_sub[s] = pol_by_sub.get(s, 0) + num(dig(r, "n"), 0)
    items = unread(arg_rows("Resources | where type =~ 'microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems' | extend kind=tolower(tostring(properties.protectedItemType)) | summarize n=count() by subscriptionId, kind", ctx["subs"]),
                   "protected items", "backup-items-unreadable")
    if items is None:
        return
    covered = {}
    kind_map = {"vm": "virtualmachines", "virtualmachines": "virtualmachines", "sqldatabase": "databases", "azurefileshare": "storageaccounts", "saphanadatabase": "databases", "sapasedatabase": "databases", "saphana": "databases", "sapase": "databases", "azureblobs": "storageaccounts"}
    for r in items:
        s = str(dig(r, "subscriptionId"))
        kind = str(dig(r, "kind") or "").lower().split("/")[-1]
        target = kind_map.get(kind, kind)
        covered[(s, target)] = covered.get((s, target), 0) + num(dig(r, "n"), 0)
    for r in inv:
        s = str(dig(r, "subscriptionId"))
        kind = str(dig(r, "type") or "").split("/")[-1]
        n = num(dig(r, "n"), 0)
        if not pol_by_sub.get(s):
            add("medium", "no-backup-policy", kind, "resources=" + str(n) + " policies=0", "no backup policy is defined in this subscription", s)
            continue
        have = covered.get((s, kind), 0)
        if n and have == 0:
            add("medium", "backup-type-uncovered", kind, "resources=" + str(n) + " protectedItems=0", "no protected item of this resource type exists", s)
        elif n and have < n:
            add("low", "backup-type-partial", kind, "resources=" + str(n) + " protectedItems=" + str(have), "fewer protected items than resources of this type", s)


@check("sub-law-local-auth")
def c_law_auth(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.operationalinsights/workspaces' | project name, subscriptionId, localAuth=tostring(properties.features.disableLocalAuth)", ctx["subs"])
    if rows is None:
        note("sub-law-local-auth", 0, denied=1)
        return
    note("sub-law-local-auth", len(rows))
    for r in rows:
        if tri(dig(r, "localAuth")) is False:
            add("medium", "loganalytics-local-auth", r.get("name"), "features.disableLocalAuth=" + str(val(dig(r, "localAuth"), "not returned")), "shared key authentication is enabled; the key bypasses Entra ID", r.get("subscriptionId"))


@check("sub-mg-assignments")
def c_mg_assign(ctx):
    q = """AuthorizationResources
| where subscriptionId in (""" + subq(ctx["subs"]) + """)
| where tostring(properties.scope) startswith '/providers/Microsoft.Management'
| project principalId=tostring(properties.principalId), principalType=tostring(properties.principalType), roleId=tostring(properties.roleDefinitionId), scope=tostring(properties.scope)"""
    rows = arg_rows(q, ctx["subs"], scoped=False)
    if rows is None:
        note("sub-mg-assignments", 0, denied=1)
        return
    note("sub-mg-assignments", len(rows))
    for r in rows:
        sev = "high" if str(r.get("roleId") or "").endswith(BUILTIN_ROLE_OWNER) or str(r.get("roleId") or "").endswith(BUILTIN_ROLE_UAA) else "medium"
        add(sev, "management-group-assignment", r.get("principalId"), "type=" + str(r.get("principalType")) + " scope=" + str(r.get("scope")), "inherited by every subscription below the group")


@check("sub-locks-detail")
def c_locks_detail(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.authorization/locks' | project name, subscriptionId, level=properties.level, id=id", ctx["subs"])
    if rows is None:
        note("sub-locks-detail", 0, denied=1)
        return
    note("sub-locks-detail", len(rows))
    lv = Counter(str(r.get("level")) for r in rows)
    for k, v in lv.items():
        add("info", "lock-level", k, "count=" + str(v), "ReadOnly prevents change; CanNotDelete only prevents deletion")
    if not rows:
        add("low", "locks-absent-detail", "all", "0 locks", "nothing protects critical resources", "tenant")


@check("sub-vm-posture")
def c_vm(ctx):
    if not ctx.get("include_vms"):
        note("sub-vm-posture", 0)
        add("info", "vm-surface-excluded", "all", "VMs excluded by client instruction", "extensions, JIT, encryption, boot diagnostics and serial console not assessed", "tenant")
        return
    q = """Resources
| where type =~ 'microsoft.compute/virtualmachines'
| project name, subscriptionId, rg=resourceGroup, os=properties.storageProfile.osDisk.managedDisk.id,
          secureBoot=properties.securityProfile.uefiSettings.secureBootEnabled,
          vtmp=properties.securityProfile.uefiSettings.vTpmEnabled,
          diag=tostring(properties.diagnosticsProfile.bootDiagnostics.enabled)"""
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-vm-posture", 0, denied=1)
        return
    note("sub-vm-posture", len(rows))
    for r in rows:
        s = r.get("subscriptionId")
        if tri(r.get("secureBoot")) is False or tri(r.get("vtmp")) is False:
            add("medium", "vm-trusted-launch-off", r.get("name"), "secureBoot=" + str(r.get("secureBoot")) + " vTpm=" + str(r.get("vtmp")), "boot integrity not enforced", s)
        diag_state = tri(dig(r, "diag"))
        if diag_state is False:
            add("low", "vm-boot-diagnostics-off", dig(r, "name"), "bootDiagnostics.enabled=false", "no console output for forensics", s)
        elif diag_state is None:
            add("low", "vm-boot-diagnostics-unknown", dig(r, "name"), "bootDiagnostics not returned", "console capture cannot be confirmed", s)
    ext = arg_rows("Resources | where type =~ 'microsoft.compute/virtualmachines/extensions' | project name, subscriptionId, publisher=tostring(properties.publisher), settings=tostring(properties.settings)", ctx["subs"])
    for r in unread_list(ext, "virtual machine extensions", "vm-extensions-unreadable"):
        if SECRET_PAT.search(str(r.get("settings")) or ""):
            add("high", "vm-extension-secret", r.get("name"), "publisher=" + str(r.get("publisher")), "extension settings contain a credential", r.get("subscriptionId"))
    disks = arg_rows("Resources | where type =~ 'microsoft.compute/disks' | project name, subscriptionId, enc=tostring(properties.encryption.type), setId=tostring(properties.encryption.diskEncryptionSetId)", ctx["subs"])
    for r in unread_list(disks, "managed disks", "vm-disks-unreadable"):
        if not r.get("setId"):
            add("medium", "disk-no-cmk", r.get("name"), "encryption.type=" + str(r.get("enc") or "Platform") + " diskEncryptionSetId absent", "disk is encrypted with platform keys only", r.get("subscriptionId"))
    jit = arg_rows("Resources | where type =~ 'microsoft.security/pricings' | where name =~ 'VirtualMachines' | project subscriptionId, tier=tostring(properties.pricingTier)", ctx["subs"])
    for r in unread_list(jit, "Defender for Servers pricing", "vm-jit-pricing-unreadable"):
        if str(r.get("tier")) not in ("Standard", "Standard_DC"):
            add("medium", "jit-not-enabled", r.get("subscriptionId"), "pricingTier=" + str(r.get("tier")), "just-in-time VM access needs Defender for Servers", r.get("subscriptionId"))
    snap = arg_rows("Resources | where type =~ 'microsoft.compute/snapshots' | project name, type, subscriptionId, netAccess=tostring(properties.networkAccessPolicy)", ctx["subs"])
    for r in unread_list(snap, "snapshots", "vm-snapshots-unreadable"):
        if str(r.get("netAccess") or "") == "AllowAll":
            add("high", "snapshot-public-export", r.get("name"), "networkAccessPolicy=AllowAll", "SAS export of the image from any network", r.get("subscriptionId"))


@check("sub-net-path")
def c_net_path(ctx):
    q = """Resources
| where type =~ 'microsoft.network/publicipaddresses'
| project name, subscriptionId, ip=properties.ipAddress, nic=tostring(properties.ipConfiguration.id)"""
    pips = arg_rows(q, ctx["subs"])
    if pips is None:
        note("sub-net-path", 0, denied=1)
        return
    nics = arg_rows("Resources | where type =~ 'microsoft.network/networkinterfaces' | project name, rg=resourceGroup, subscriptionId, subnet=tostring(properties.ipConfigurations[0].properties.subnet.id), nsg=tostring(properties.networkSecurityGroup.id)", ctx["subs"])
    subnets = arg_rows("Resources | where type =~ 'microsoft.network/virtualnetworks' | mv-expand sn = properties.subnets | project subnetId=tostring(sn.id), nsg=tostring(sn.properties.networkSecurityGroup.id), subscriptionId", ctx["subs"])
    if nics is None or subnets is None:
        note("sub-net-path", 0, denied=1)
        return
    sub_map = {str(x.get("subnetId")).lower(): x.get("nsg") for x in subnets}
    note("sub-net-path", len(pips))
    for p in pips:
        nic = str(p.get("nic") or "")
        if not nic or "/networkInterfaces/" not in nic:
            continue
        match = None
        parts = nic.rstrip("/").split("/")
        want_rg = parts[parts.index("resourceGroups") + 1] if "resourceGroups" in parts and len(parts) > parts.index("resourceGroups") + 1 else ""
        nic_name = parts[parts.index("networkInterfaces") + 1] if "networkInterfaces" in parts and len(parts) > parts.index("networkInterfaces") + 1 else ""
        for n in nics:
            if (str(dig(n, "name")).lower() == nic_name.lower()
                    and str(dig(n, "subscriptionId")).lower() == str(dig(p, "subscriptionId")).lower()
                    and str(val(dig(n, "rg"), "")).lower() == want_rg.lower()):
                match = n
                break
        if not match:
            continue
        nsg = match.get("nsg") or sub_map.get(str(match.get("subnet") or "").lower())
        add("high" if not nsg else "medium", "public-ip-path", p.get("name"), "ip=" + str(p.get("ip")) + " nic=" + str(match.get("name")) + " nsg=" + str(nsg or "none"), "internet path to a VM interface" + ("" if nsg else " with no NSG"), p.get("subscriptionId"))


@check("sub-data-services")
def c_data_services(ctx):
    q = """Resources
| where subscriptionId in (""" + subq(ctx["subs"]) + """)
| where type in~ ('microsoft.documentdb/databaseaccounts','microsoft.servicebus/namespaces','microsoft.eventhub/namespaces','microsoft.cache/redis','microsoft.sql/managedinstances','microsoft.search/searchservices','microsoft.machinelearningservices/workspaces','microsoft.logic/workflows','microsoft.apimanagement/service','microsoft.appconfiguration/configurationstores')
| project name, type, subscriptionId, props=properties"""
    rows = arg_rows(q, ctx["subs"], scoped=False)
    if rows is None:
        note("sub-data-services", 0, denied=1)
        return
    note("sub-data-services", len(rows))
    for r in rows:
        p = r.get("props") or {}
        t = str(r.get("type")).split("/")[-1]
        s = r.get("subscriptionId")
        if t == "databaseaccounts":
            if p.get("disableKeyBasedMetadataWriteAccess") not in (True, "true", "True"):
                add("medium", "cosmos-metadata-write-via-key", r.get("name"), "disableKeyBasedMetadataWriteAccess=" + str(p.get("disableKeyBasedMetadataWriteAccess")), "account key can change metadata", s)
            if not p.get("keyVaultKeyUri"):
                add("low", "cosmos-no-cmk", r.get("name"), "keyVaultKeyUri absent", "no customer-managed key", s)
        if t in ("namespaces",):
            tls = str(p.get("minimumTlsVersion") or "").strip()
            if tls and tls not in ("1.2", "1.3"):
                add("medium", "messaging-legacy-tls", str(r.get("name")) + " " + t, "minimumTlsVersion=" + tls, "legacy TLS accepted", s)
            elif not tls:
                add("low", "messaging-tls-unknown", str(r.get("name")) + " " + t, "minimumTlsVersion not returned", "namespace default applies", s)
            if not p.get("networkRuleSet") or str((p.get("networkRuleSet") or {}).get("defaultAction") or "Allow") == "Allow":
                add("medium", "messaging-open-network", str(r.get("name")) + " " + t, "networkRuleSet.defaultAction=Allow", "namespace reachable from any network", s)
        if t == "redis":
            if str(p.get("publicNetworkAccess") or "Enabled") == "Enabled":
                add("medium", "redis-public", r.get("name"), "publicNetworkAccess=Enabled", "cache reachable from the internet", s)
        if t == "searchservices":
            add("info", "search-service", r.get("name"), "publicNetworkAccess=" + str(p.get("publicNetworkAccess")), "query and admin keys bypass Entra", s)
        if t in ("workflows",):
            acc = p.get("accessControl") or {}
            if not acc:
                add("low", "logicapp-no-accesscontrol", r.get("name"), "accessControl absent", "trigger authentication depends on the workflow definition", s)
        if str(r.get("type")).lower() == "microsoft.apimanagement/service":
            add("info", "apim-instance", r.get("name"), "gateway=" + str(p.get("gatewayUrl")), "subscription keys are the default credential", s)


@check("sub-storage-keys")
def c_storage_keys(ctx):
    q = "Resources | where type =~ 'microsoft.storage/storageaccounts' | project name, subscriptionId, created=properties.keyCreationTime.key1, keyExpiry=toint(properties.keyPolicy.keyExpirationPeriodInDays)"
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-storage-keys", 0, denied=1)
        return
    note("sub-storage-keys", len(rows))
    blobs = unread_list(arg_rows("Resources | where type =~ 'microsoft.storage/storageaccounts/blobservices' | mv-expand c = properties.cors.corsRules | project account=split(id, '/')[8], subscriptionId, origins=tostring(c.allowedOrigins), methods=tostring(c.allowedMethods)", ctx["subs"]),
                        "blob service CORS rules", "storage-cors-unreadable")
    for b in blobs:
        if "*" in str(dig(b, "origins")):
            add("medium", "storage-cors-wildcard", dig(b, "account"), "allowedOrigins=" + str(dig(b, "origins")) + " methods=" + str(dig(b, "methods")), "any origin can call the blob endpoint from a browser", str(dig(b, "subscriptionId")))
    for r in rows:
        s = r.get("subscriptionId")
        created = str(val(dig(r, "created"), ""))[:19]
        if created:
            try:
                age = int((time.time() - calendar.timegm(time.strptime(created, "%Y-%m-%dT%H:%M:%S"))) / 86400)
            except ValueError:
                age = -1
            if age > 365:
                add("medium", "storage-key-stale", dig(r, "name"), "key1Created=" + created + " ageDays=" + str(age), "an account key outlived its rotation cycle", s)
            elif age >= 0:
                add("info", "storage-key-age", dig(r, "name"), "key1Created=" + created + " ageDays=" + str(age), "account key age", s)
        period = num(dig(r, "keyExpiry"))
        if not isinstance(period, int) or period <= 0:
            add("medium", "storage-key-no-expiry-policy", dig(r, "name"), "keyPolicy.keyExpirationPeriodInDays=" + str(val(dig(r, "keyExpiry"), "unset")), "account keys never expire; rotation depends on a manual process", s)
        elif period > 180:
            add("low", "storage-key-long-expiry", dig(r, "name"), "keyExpirationPeriodInDays=" + str(period), "the key expiry reminder is longer than half a year", s)
        else:
            add("info", "storage-key-expiry-policy", dig(r, "name"), "keyExpirationPeriodInDays=" + str(period), "account key expiry policy in force", s)



@check("sub-aks-depth")
def c_aks_depth(ctx):
    q = "Resources | where type =~ 'microsoft.containerservice/managedclusters' | project name, subscriptionId, aad=tostring(properties.aadProfile), netpol=tostring(properties.networkProfile.networkPolicy), kms=tostring(properties.securityProfile.azureKeyVaultKms.enabled), pools=properties.agentPoolProfiles"
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-aks-depth", 0, denied=1)
        return
    note("sub-aks-depth", len(rows))
    for r in rows:
        s = r.get("subscriptionId")
        if not r.get("aad") or str(r.get("aad")) in ("None", ""):
            add("high", "aks-no-entra-integration", r.get("name"), "aadProfile absent", "no Entra authentication for the cluster", s)
        if str(val(dig(r, "netpol"), "")).lower() in ("none", ""):
            add("medium", "aks-no-network-policy", r.get("name"), "networkPolicy=" + str(r.get("netpol")), "pod-to-pod traffic unrestricted", s)
        if tri(dig(r, "kms")) is not True:
            add("low", "aks-no-kms", r.get("name"), "azureKeyVaultKms=" + str(r.get("kms")), "secrets encrypted with platform keys only", s)
        for pool in r.get("pools") or []:
            if pool.get("enableNodePublicIP") in (True, "true", "True"):
                add("high", "aks-nodes-public-ip", str(dig(r, "name")) + " " + str(dig(pool, "name")), "enableNodePublicIP=true", "nodes directly reachable", s)


@check("sub-defender-depth")
def c_defender_depth(ctx):
    res = per_sub(ctx["subs"], "providers/Microsoft.Security/autoProvisioningSettings", "2017-08-01-preview", lambda d: d.get("value") or [])
    note("sub-defender-depth", sum(1 for v in res.values() if v is not None), denied=sum(1 for v in res.values() if v is None))
    for s, items in res.items():
        for a in items or []:
            if str((a.get("properties") or {}).get("autoProvision") or "").lower() != "on":
                add("low", "defender-autoprovision-off", s + " " + str(a.get("name")), "autoProvision=" + str((a.get("properties") or {}).get("autoProvision")), "agents are not deployed automatically", s)
    sup = per_sub(ctx["subs"], "providers/Microsoft.Security/alertsSuppressionRules", "2023-01-01-preview", lambda d: d.get("value") or [])
    for s, items in sup.items():
        for a in items or []:
            add("medium", "defender-suppression-rule", s + " " + str(a.get("name")), "state=" + str((a.get("properties") or {}).get("state")), "alerts matching this rule are hidden", s)


@check("sub-sentinel-depth")
def c_sentinel_depth(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.securityinsights/alertrules' or type =~ 'microsoft.securityinsights/dataconnectors' or type =~ 'microsoft.securityinsights/automationrules' | summarize n=count() by type, subscriptionId", ctx["subs"])
    if rows is None:
        note("sub-sentinel-depth", 0, denied=1)
        return
    note("sub-sentinel-depth", len(rows))
    kinds = Counter()
    for r in rows:
        kinds[str(r.get("type")).split("/")[-1].lower()] += r.get("n") or 0
    for k, v in kinds.items():
        add("info", "sentinel-content", k, "count=" + str(v), "detection content inventory")
    for expected in ("alertrules", "dataconnectors", "automationrules"):
        if not kinds.get(expected):
            add("medium", "sentinel-missing-content", expected, "0 configured", "no " + expected + " in the workspace")


@check("sub-policy-depth")
def c_policy_depth(ctx):
    sets = arg_rows("PolicyResources | where type =~ 'microsoft.authorization/policysetdefinitions' | where subscriptionId in (" + subq(ctx["subs"]) + ") or isempty(tostring(subscriptionId)) | project name, subscriptionId, id", ctx["subs"], scoped=False)
    if sets is None:
        note("sub-policy-depth", 0, denied=1)
        return
    note("sub-policy-depth", len(sets))
    add("info", "policy-initiatives", "all", "count=" + str(len(sets)), "initiative inventory")
    dis = arg_rows("PolicyResources | where type =~ 'microsoft.authorization/policydefinitions' | where subscriptionId in (" + subq(ctx["subs"]) + ") or isempty(tostring(subscriptionId)) | where tostring(properties.policyRule.then.effect) == 'Disabled' | project name, subscriptionId", ctx["subs"], scoped=False)
    for r in unread_list(dis, "disabled policy definitions", "policy-disabled-definitions-unreadable"):
        add("medium", "policy-effect-disabled", r.get("name"), "effect=Disabled", "definition never evaluates", r.get("subscriptionId"))
    audit = arg_rows("PolicyResources | where type =~ 'microsoft.authorization/policydefinitions' | where subscriptionId in (" + subq(ctx["subs"]) + ") or isempty(tostring(subscriptionId)) | where tostring(properties.policyRule.then.effect) == 'Audit' | summarize n=count() by subscriptionId", ctx["subs"], scoped=False)
    for r in unread_list(audit, "audit-only policy definitions", "policy-audit-definitions-unreadable"):
        add("info", "policy-audit-only", r.get("subscriptionId"), "definitions=" + str(r.get("n")), "audit-only definitions do not block")


@check("sub-backup-items")
def c_backup_items(ctx):
    items = arg_rows("Resources | where type =~ 'microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems' | summarize n=count() by subscriptionId", ctx["subs"])
    if items is None:
        note("sub-backup-items", 0, denied=1)
        return
    note("sub-backup-items", len(items))
    have = {r.get("subscriptionId"): r.get("n") for r in items}
    for s in ctx["subs"]:
        if not have.get(s):
            add("medium", "no-protected-backup-items", s, "0 protected items", "no workload is registered for backup", s)


@check("entra-hybrid-sync")
def c_hybrid(ctx):
    idx = ctx["idx"]
    msol = [u for u in idx.users() if str(idx.props(u).get("userPrincipalName") or "").upper().startswith("MSOL_")]
    org = graph("organization")
    if org is None and not msol:
        note("entra-hybrid-sync", 0, denied=1)
        return
    note("entra-hybrid-sync", len(msol))
    for u in msol:
        add("high", "directory-sync-account", idx.props(u).get("userPrincipalName"), "enabled=" + str(idx.props(u).get("accountEnabled")), "the sync account can replicate directory changes and reach on-premises hashes")
    if org:
        o = (org.get("value") or [{}])[0]
        last = str(o.get("onPremisesLastSyncDateTime") or "")
        if o.get("onPremisesSyncEnabled") and last:
            try:
                age = (time.time() - calendar.timegm(time.strptime(last[:19], "%Y-%m-%dT%H:%M:%S"))) / 3600.0
                if age > 24:
                    add("high", "sync-stalled", "tenant", "lastSync=" + last + " ageHours=" + str(round(age, 1)), "directory sync has stopped; changes are not propagating")
            except ValueError:
                add("info", "sync-time-unparsed", "tenant", "lastSync=" + last, "timestamp format unexpected")
    if not msol:
        add("info", "no-sync-account", "tenant", "0 MSOL_ accounts in dataset", "no hybrid sync account visible")


@check("entra-pim-role-settings")
def c_pim_settings(ctx):
    defs = graph_all("roleManagement/directory/roleDefinitions", limit=5)
    if defs is None:
        note("entra-pim-role-settings", 0, denied=1)
        return
    roles = [d for d in defs if is_escalation(d)]
    note("entra-pim-role-settings", len(roles))
    for r in roles[:8]:
        pol = graph("policies/roleManagementPolicyAssignments?$filter=roleDefinitionId eq '" + str(r.get("id")) + "' and scopeId eq '/'&$expand=policy($expand=rules)", beta=True)
        if pol is None:
            deny("entra-pim-role-settings")
            continue
        for a in pol.get("value") or []:
            rules = (a.get("policy") or {}).get("rules") or []
            approval = any("Approval" in str(x.get("@odata.type")) for x in rules)
            authctx = any("AuthenticationContext" in str(x.get("@odata.type")) for x in rules)
            maxdur = ""
            for x in rules:
                if "Expiration" in str(x.get("@odata.type")):
                    maxdur = str(x.get("maximumDuration"))
            add("high" if not approval else "info", "pim-role-no-approval" if not approval else "pim-role-approved", r.get("displayName"), "approval=" + str(approval) + " authContext=" + str(authctx) + " maxDuration=" + maxdur, "activation requirements for a privileged role")
    sample("entra-pim-role-settings", min(len(roles), 8), len(roles), "privileged roles")


@check("entra-access-review-scope")
def c_review_scope(ctx):
    rows = graph_all("identityGovernance/accessReviews/definitions", limit=5, beta=True)
    if rows is None:
        note("entra-access-review-scope", 0, denied=1)
        return
    note("entra-access-review-scope", len(rows))
    privileged = 0
    for r in rows:
        scope = dig(r, "scope")
        q = str(val(dig(scope, "@odata.type"), ""))
        enumeration = dig(r, "instanceEnumerationScope")
        target = q or str(val(dig(enumeration, "query"), ""))
        if not target:
            add("low", "access-review-scope-unreadable", str(val(dig(r, "displayName"), "review")), "scope object not returned", "the reviewed object type cannot be confirmed")
            continue
        if any(t in target.lower() for t in ("group", "role", "accesspackage")):
            privileged += 1
            add("info", "access-review-scope", str(val(dig(r, "displayName"), "review")), "scope=" + target.split(".")[-1][:40] + " status=" + str(val(dig(r, "status"), "unknown")), "recertification covers a privileged object")
    if rows and not privileged:
        add("medium", "access-reviews-only-apps", "tenant", "reviews=" + str(len(rows)) + " privileged=0", "no review covers roles, groups or access packages")


@check("entra-risky-signins")
def c_risky_signins(ctx):
    rows = graph_all("identityProtection/riskyServicePrincipals", limit=5, beta=True)
    signins = graph_all("auditLogs/signIns?$filter=riskLevelDuringSignIn ne 'none'&$top=50", limit=3, beta=True)
    if rows is None and signins is None:
        note("entra-risky-signins", 0, denied=1)
        return
    if rows is None or signins is None:
        deny("entra-risky-signins")
    note("entra-risky-signins", len(lst(rows)) + len(lst(signins)))
    for r in lst(rows):
        add("high", "risky-service-principal", r.get("appId"), "risk=" + str(r.get("riskLevel")) + " state=" + str(r.get("riskState")), "a workload identity is flagged as compromised")
    for s in lst(signins)[:10]:
        add("high", "risky-signin", s.get("userPrincipalName"), "risk=" + str(s.get("riskLevelDuringSignIn")) + " at=" + str(s.get("createdDateTime")) + " app=" + str(s.get("appDisplayName")), "sign-in flagged as risky and not remediated")


@check("entra-token-lifetime")
def c_token_lifetime(ctx):
    rows = graph_all("policies/tokenLifetimePolicies", limit=3)
    if rows is None:
        note("entra-token-lifetime", 0, denied=1)
        return
    note("entra-token-lifetime", len(rows))
    for p in rows:
        for d in lst(dig(p, "definition")):
            minutes = str(val(dig(d, "MaxInactiveTime"), ""))
            add("info", "token-lifetime-policy", dig(p, "displayName"), "MaxInactiveTime=" + (minutes or "unset") + " definition=" + str(d)[:80], "token lifetime policy in force")
    if not rows:
        add("info", "token-lifetime-default", "tenant", "0 tokenLifetimePolicies returned", "token lifetime is governed by platform defaults and by conditional access session controls; this endpoint does not describe them")


@check("entra-app-ownerless")
def c_ownerless(ctx):
    apps = graph_all("applications?$select=appId,displayName,createdDateTime,passwordCredentials", limit=10)
    if apps is None:
        note("entra-app-ownerless", 0, denied=1)
        return
    note("entra-app-ownerless", len(apps))
    for a in apps[:25]:
        owners = graph("applications(appId='" + str(a.get("appId")) + "')/owners?$select=id")
        if owners is None:
            deny("entra-app-ownerless")
            continue
        if not (owners.get("value") or []) and (a.get("passwordCredentials") or []):
            add("medium", "app-credential-without-owner", a.get("displayName"), "credentials=" + str(len(a.get("passwordCredentials") or [])) + " owners=0", "nobody is accountable for rotating this credential")
    sample("entra-app-ownerless", min(len(apps), 25), len(apps), "applications")


@check("entra-device-compliance")
def c_device_compliance(ctx):
    rows = graph_all("deviceManagement/deviceCompliancePolicies", limit=5, beta=True)
    if rows is None:
        note("entra-device-compliance", 0, denied=1)
        return
    note("entra-device-compliance", len(rows))
    if not rows:
        add("medium", "no-device-compliance-policy", "tenant", "0 compliance policies", "device compliance cannot be a CA condition")
    for p in rows:
        assign = graph("deviceManagement/deviceCompliancePolicies/" + str(dig(p, "id")) + "/assignments", beta=True)
        if assign is None:
            denied_now("entra-device-compliance")
            continue
        n = len(lst(dig(assign, "value")))
        if not n:
            add("medium", "compliance-policy-unassigned", dig(p, "displayName"), "assignments=0", "a policy without an assignment enforces nothing")
        else:
            add("info", "compliance-policy-assigned", dig(p, "displayName"), "assignments=" + str(n), "policy is assigned and can be required by conditional access")


@check("sub-privileged-roles")
def c_priv_roles(ctx):
    q = """AuthorizationResources
| where type =~ 'microsoft.authorization/roleassignments'
| where subscriptionId in (""" + subq(ctx["subs"]) + """)
| project principalId=tostring(properties.principalId), principalType=tostring(properties.principalType), roleId=tostring(properties.roleDefinitionId), scope=tostring(properties.scope)"""
    rows = arg_rows(q, ctx["subs"], scoped=False)
    if rows is None:
        note("sub-privileged-roles", 0, denied=1)
        return
    defs = {}
    role_rows = unread(arg_rows(tenant_wide("AuthorizationResources | where type =~ 'microsoft.authorization/roledefinitions' | project id, name=properties.roleName, perms=properties.permissions"), ctx["subs"], scoped=False),
                      "role definitions", "privileged-role-definitions-unreadable")
    if role_rows is None:
        return
    for r in role_rows:
        defs[str(dig(r, "id")).lower()] = (dig(r, "name"), lst(dig(r, "perms")))
    note("sub-privileged-roles", len(rows), denied=deny("sub-privileged-roles", 0))
    for r in rows:
        rid = str(r.get("roleId") or "").lower()
        name, perms = defs.get(rid, (rid.split("/")[-1], []))
        broad = any(str(a).strip() == "*" for p in perms for a in lst(dig(p, "actions")))
        grant = grants_role_write(perms) or any(permits(p, "microsoft.authorization/roledefinitions/write") for p in perms)
        secrets = [t for t in ("microsoft.keyvault/vaults/secrets/read", "microsoft.keyvault/vaults/keys/*", "microsoft.keyvault/vaults/secrets/delete", "microsoft.keyvault/vaults/purge/action") if any(permits(p, t) for p in perms)]
        if broad:
            add("high", "privileged-builtin-role", str(r.get("principalId")), "role=" + str(name) + " wildcard actions scope=" + str(r.get("scope")), "wildcard permissions", ctx_sub(r), r.get("scope"))
        elif grant:
            add("medium", "role-can-grant-access", str(r.get("principalId")), "role=" + str(name) + " scope=" + str(r.get("scope")), "role can create role assignments", ctx_sub(r), r.get("scope"))
        elif secrets:
            add("medium", "role-can-touch-secrets", str(r.get("principalId")), "role=" + str(name) + " actions=" + ",".join(sorted(set(secrets))[:3]), "role can read or destroy vault material", ctx_sub(r), r.get("scope"))


@check("sub-alert-content")
def c_alert_content(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.insights/activitylogalerts' | project name, subscriptionId, cond=properties.condition", ctx["subs"])
    if rows is None:
        note("sub-alert-content", 0, denied=1)
        return
    note("sub-alert-content", len(rows))
    watched = []
    for r in rows:
        blob = json.dumps(r.get("cond")).lower()
        watched.append(blob)
    wanted = {
        "role assignment": ("roleassignments",),
        "policy assignment": ("policyassignments",),
        "key vault write": ("microsoft.keyvault/vaults",),
        "policy exemption": ("policyexemptions",),
        "nsg change": ("networksecuritygroups",),
        "diagnostic setting change": ("diagnosticsettings",),
    }
    for label, tokens in wanted.items():
        if not any(t in blob for blob in watched for t in tokens):
            add("medium", "alert-coverage-gap", label, "no rule condition matches", "this event class raises no alert")


@check("sub-appservice-auth")
def c_web_auth(ctx):
    q = "Resources | where type =~ 'microsoft.web/sites' | project name, subscriptionId, rg=resourceGroup, identity=identity"
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-appservice-auth", 0, denied=1)
        return
    note("sub-appservice-auth", len(rows))
    for r in rows[:15]:
        url = ARM_BASE + "/subscriptions/" + str(r.get("subscriptionId")) + "/resourceGroups/" + str(r.get("rg")) + "/providers/Microsoft.Web/sites/" + str(r.get("name")) + "/config/authsettingsV2?api-version=2022-09-01"
        LAST_QUERY[CURRENT["check"]] = "az rest --url " + repr(url)
        doc = az(["rest", "--url", url])
        if doc is None:
            denied_now("sub-appservice-auth")
            continue
        enabled = ((doc.get("properties") or {}).get("platform") or {}).get("enabled")
        ident = r.get("identity") or {}
        if not enabled:
            add("low", "appservice-easyauth-off", dig(r, "name"), "authsettingsV2.platform.enabled=" + str(enabled), "the platform does not authenticate requests; the app must enforce its own authentication", str(dig(r, "subscriptionId")))
        if not ident:
            add("low", "appservice-no-managed-identity", r.get("name"), "identity=none", "secrets must be stored instead of using an identity", r.get("subscriptionId"))
    sample("sub-appservice-auth", min(len(rows), 15), len(rows), "web apps")


@check("sub-network-inventory")
def c_net_inv(ctx):
    q = """Resources
| where subscriptionId in (""" + subq(ctx["subs"]) + """)
| where type in~ ('microsoft.network/loadbalancers','microsoft.network/bastionhosts','microsoft.network/ddosprotectionplans','microsoft.network/virtualnetworkgateways','microsoft.network/routetables')
| project name, type, subscriptionId, sku=tostring(properties.sku.name)"""
    rows = arg_rows(q, ctx["subs"], scoped=False)
    if rows is None:
        note("sub-network-inventory", 0, denied=1)
        return
    note("sub-network-inventory", len(rows))
    kinds = Counter(str(r.get("type")).split("/")[-1] for r in rows)
    for k, v in kinds.items():
        add("info", "network-component", k, "count=" + str(v), "network trust component inventory")
    if not kinds.get("ddosprotectionplans"):
        add("low", "no-ddos-plan", "all", "0 DDoS protection plans", "public endpoints rely on platform protection only")


@check("sub-kv-pe-state")
def c_kv_pe(ctx):
    vaults = _kv_rows(ctx["subs"])
    if vaults is None:
        note("sub-kv-pe-state", 0, denied=1)
        return
    with_pe = [v for v in vaults if lst(dig(v, "properties.privateEndpointConnections"))]
    pend = arg_rows("Resources | where type =~ 'microsoft.keyvault/vaults/privateendpointconnections' | project name, subscriptionId, state=tostring(properties.privateLinkServiceConnectionState.status)", ctx["subs"])
    if pend is None:
        note("sub-kv-pe-state", len(vaults), denied=1)
        return
    note("sub-kv-pe-state", len(vaults))
    add("info", "keyvault-private-endpoint-inventory", "all", "vaults=" + str(len(vaults)) + " withPrivateEndpoint=" + str(len(with_pe)) + " connections=" + str(len(pend)), "private path inventory")
    for r in pend:
        if str(r.get("state") or "").lower() != "approved":
            add("medium", "keyvault-private-endpoint-pending", r.get("name"), "connectionState=" + str(r.get("state")), "private path not established", r.get("subscriptionId"))


@check("entra-mfa-baseline")
def c_mfa_baseline(ctx):
    sd = graph("policies/identitySecurityDefaultsEnforcementPolicy")
    pols = ca_all("policies", limit=5)
    if sd is None and pols is None:
        note("entra-mfa-baseline", 0, denied=1)
        return
    if sd is None:
        note("entra-mfa-baseline", len(lst(pols)), denied=1)
        add("info", "mfa-baseline-partial", "tenant", "security defaults unreadable", "MFA requirement not assessed")
        return
    if pols is None:
        note("entra-mfa-baseline", 1, denied=1)
        add("info", "mfa-baseline-policies-unreadable", "tenant", "securityDefaults=" + str(bool(dig(sd, "isEnabled"))) + " conditionalAccessPolicies unreadable", "the tenant-wide MFA requirement was not assessed")
        return
    enabled = [p for p in pols if p.get("state") == "enabled"]
    note("entra-mfa-baseline", len(pols))
    sd_on = dig(sd, "isEnabled") is True
    if sd_on:
        add("info", "security-defaults-enabled", "tenant", "isEnabled=true", "MFA required for all users by baseline policy")
        return
    covers_all = []
    strengths = _strengths()
    strength_unknown = strengths is None
    for p in enabled:
        users = (p.get("conditions") or {}).get("users") or {}
        apps = (p.get("conditions") or {}).get("applications") or {}
        gc = p.get("grantControls") or {}
        controls = [str(c) for c in (gc.get("builtInControls") or [])]
        all_users = "All" in (users.get("includeUsers") or [])
        all_apps = "All" in (apps.get("includeApplications") or [])
        sid = dig(gc, "authenticationStrength.id")
        entry = dig(strengths, str(sid)) if sid and strengths is not None else None
        combos = [str(c).lower() for c in (entry[1] if isinstance(entry, tuple) and len(entry) > 1 else [])]
        multi = ("password,microsoftauthenticatorpush", "fido2", "windowshelloforbusiness", "x509certificatemultifactor", "microsoftauthenticatorpush", "softwareoath", "temporaryaccesspass")
        strength_ok = bool(sid) and any(any(t in c for t in multi) and "singlefactor" not in c for c in combos)
        holes = len(lst(dig(users, "excludeUsers"))) + len(lst(dig(users, "excludeGroups"))) + len(lst(dig(users, "excludeRoles"))) + len(lst(dig(apps, "excludeApplications")))
        if all_users and all_apps and (("mfa" in controls) or strength_ok):
            covers_all.append(str(dig(p, "displayName")) + ("(exclusions=" + str(holes) + ")" if holes else ""))
    if covers_all:
        add("info", "mfa-all-users-covered", "tenant", "policies=" + ",".join([str(x) for x in covers_all]), "an enforced policy requires MFA for all users and apps; any exclusion shown in brackets is a bypass")
    elif strength_unknown and any(val(dig(p, "grantControls.authenticationStrength"), "") for p in enabled):
        add("info", "mfa-baseline-unassessed", "tenant", "authenticationStrength unreadable enforcedPolicies=" + str(len(enabled)), "the policy set uses custom authentication strengths, so the MFA requirement cannot be confirmed or denied")
    elif not ca_complete():
        capped("entra-mfa-baseline", len(pols), "conditional access policy pages")
    else:
        add("high", "mfa-not-required-for-all", "tenant", "securityDefaults=off coveringPolicies=0 enforcedPolicies=" + str(len(enabled)), "no policy requires MFA for all users and all applications")


@check("entra-ca-inventory")
def c_ca_inventory(ctx):
    pols = ca_all("policies", limit=5)
    if pols is None:
        note("entra-ca-inventory", 0, denied=1)
        return
    note("entra-ca-inventory", len(pols))
    st = Counter(str(p.get("state")) for p in pols)
    for k, v in st.items():
        add("info", "ca-state", k, "count=" + str(v), "policy state distribution")
    if not pols:
        confirm = graph_all("conditionalAccessPolicies", limit=3)
        if confirm:
            add("low", "ca-path-discrepancy", "tenant", "canonical path returned 0 policies, legacy path returned " + str(len(confirm)), "the endpoints disagree; verify before trusting either")
            pols = confirm
        elif confirm is None:
            add("medium", "ca-unconfirmed-empty", "tenant", "canonical read returned 0 policies, legacy endpoint unavailable", "no policy was returned, and the second endpoint could not confirm it")
        else:
            add("high", "ca-no-policies", "tenant", "0 policies returned by both endpoints", "no conditional access exists")
    for p in pols:
        cond = p.get("conditions") or {}
        users = cond.get("users") or {}
        sc = p.get("sessionControls") or {}
        if users.get("includeGuestsOrExternalUsers"):
            add("info", "ca-guest-scope", p.get("displayName"), "includeGuestsOrExternalUsers set", "guests are addressed explicitly")
        if users.get("excludeGuestsOrExternalUsers"):
            add("medium", "ca-guest-excluded", p.get("displayName"), "excludeGuestsOrExternalUsers set", "external identities skip this control")
        pb = (sc.get("persistentBrowser") or {}).get("mode")
        if str(p.get("state")) == "enabled" and str(pb or "").lower() == "always":
            add("low", "ca-persistent-browser", p.get("displayName"), "persistentBrowser=always", "browser sessions survive sign-out")
        cas = (sc.get("cloudAppSecurity") or {}).get("cloudAppSecurityType")
        if cas:
            add("info", "ca-mcas-control", p.get("displayName"), "cloudAppSecurityType=" + str(cas), "session control via Defender for Cloud Apps")


@check("entra-auth-methods-policy")
def c_auth_methods(ctx):
    pol = graph("policies/authenticationMethodsPolicy")
    if pol is None:
        note("entra-auth-methods-policy", 0, denied=1)
        return
    cfgs = pol.get("authenticationMethodConfigurations") or []
    note("entra-auth-methods-policy", len(cfgs))
    states = {}
    for c in cfgs:
        mid = str(c.get("@odata.type") or "").split(".")[-1]
        states[mid] = str(c.get("state"))
        if mid == "emailOtpAuthenticationMethodConfiguration" and str(c.get("state")).lower() == "enabled":
            add("medium", "email-otp-enabled", mid, "state=enabled", "email one-time passcode is weaker than an authenticator")
        if mid in ("smsAuthenticationMethodConfiguration", "voiceAuthenticationMethodConfiguration") and str(c.get("state")).lower() == "enabled":
            add("medium", "sms-voice-mfa-enabled", mid, "state=enabled", "SMS and voice are interceptable factors")
        if mid == "fido2AuthenticationMethodConfiguration":
            aaguids = c.get("keyRestrictions") or {}
            if aaguids.get("isEnforced"):
                add("info", "fido2-aaguid-restricted", mid, "allowedAaguids=" + str(len(aaguids.get("aaGuids") or [])), "only listed authenticator models are accepted")
    if not states.get("fido2AuthenticationMethodConfiguration") == "enabled":
        add("medium", "fido2-disabled", "tenant", "fido2=" + str(states.get("fido2AuthenticationMethodConfiguration")), "no phishing-resistant authenticator is enabled")


@check("entra-external-collab")
def c_external(ctx):
    d = graph("policies/crossTenantAccessPolicy/default", beta=True)
    if d is None:
        note("entra-external-collab", 0, denied=1)
        return
    note("entra-external-collab", 1)
    b2b = (d.get("b2bCollaborationOutbound") or {})
    inbound = (d.get("b2bCollaborationInbound") or {})
    for label, blk in (("outbound", b2b), ("inbound", inbound)):
        users = str((blk.get("usersAndGroups") or {}).get("accessType") or "")
        apps = str((blk.get("applications") or {}).get("accessType") or "")
        if users == "allowed" and apps == "allowed":
            add("medium", "b2b-" + label + "-unrestricted", "default", "users=" + users + " applications=" + apps, "any external tenant can collaborate in this direction")
    tr = graph("policies/crossTenantAccessPolicy/default", beta=True)
    if tr is None:
        unread(tr, "cross-tenant access default policy", "b2b-tenant-restrictions-unreadable")
    elif not tr.get("tenantRestrictions"):
        add("low", "b2b-tenant-restrictions-absent", "default", "tenantRestrictions not returned", "no per-partner restriction configured")


@check("entra-stale-invites")
def c_stale_invites(ctx):
    users = graph_all("users?$select=userPrincipalName,externalUserState,createdDateTime,accountEnabled", limit=10)
    if users is None:
        note("entra-stale-invites", 0, denied=1)
        return
    guests = [u for u in users if str(u.get("externalUserState") or "") == "PendingAcceptance"]
    note("entra-stale-invites", len(guests))
    now = time.time()
    for g in guests:
        created = str(g.get("createdDateTime") or "")
        age = -1
        if created:
            try:
                age = int((now - calendar.timegm(time.strptime(created[:19], "%Y-%m-%dT%H:%M:%S"))) / 86400)
            except ValueError:
                age = -1
        if age > 30 or age < 0:
            add("low", "guest-invite-unaccepted", g.get("userPrincipalName"), "state=PendingAcceptance ageDays=" + str(age), "an object exists for an invitation that was never accepted")


@check("entra-delegated-grants")
def c_delegated(ctx):
    grants = graph_all("oauth2PermissionGrants?$select=clientId,consentType,scope,resourceId", limit=10)
    if grants is None:
        note("entra-delegated-grants", 0, denied=1)
        return
    note("entra-delegated-grants", len(grants))
    sp_rows = unread(graph_all("servicePrincipals?$select=id,appId,displayName", limit=10),
                     "service principals for grant attribution", "delegated-grant-principals-unreadable")
    if sp_rows is None:
        return
    sps = {}
    for sp in sp_rows:
        sps[sp.get("id")] = sp
    for g in grants:
        scope = str(g.get("scope") or "")
        write = write_scope(scope)
        tenant_wide = str(g.get("consentType")) == "AllPrincipals"
        if write and tenant_wide:
            res = sps.get(g.get("resourceId")) or {}
            add("high", "delegated-write-tenant-wide", str((sps.get(g.get("clientId")) or {}).get("displayName")), "resource=" + str(res.get("displayName")) + " scope=" + scope, "every user can exercise write access to this resource")


@check("entra-domain-takeover")
def c_domains(ctx):
    rows = graph_all("domains", limit=3)
    if rows is None:
        note("entra-domain-takeover", 0, denied=1)
        return
    note("entra-domain-takeover", len(rows))
    for d in rows:
        name = d.get("id")
        if d.get("isVerified") is False:
            add("medium", "domain-unverified", name, "isVerified=false", "an unverified domain object exists in the tenant")
        if d.get("isAdminManaged") is False:
            add("medium", "domain-not-admin-managed", name, "isAdminManaged=false", "the domain is federated to an external directory")
        if not d.get("isDefault") and d.get("isInitial") is False and str(d.get("authenticationType")) == "Managed" and d.get("isVerified"):
            add("info", "domain-managed-verified", name, "authType=Managed verified=true", "check the DNS TXT record still exists before calling this stable")


@check("sub-policy-coverage")
def c_policy_coverage(ctx):
    rows = arg_rows("PolicyResources | where type =~ 'microsoft.authorization/policyassignments' | where subscriptionId in (" + subq(ctx["subs"]) + ") or tostring(properties.scope) startswith '/providers/Microsoft.Management/' | project name, subscriptionId, scope=tostring(properties.scope), effect=tostring(properties.enforcementMode)", ctx["subs"], scoped=False)
    if rows is None:
        note("sub-policy-coverage", 0, denied=1)
        return
    note("sub-policy-coverage", len(rows))
    sub_scoped = [r for r in rows if "/subscriptions/" in str(r.get("scope")) or "/managementGroups/" in str(r.get("scope"))]
    dont = [r for r in rows if str(r.get("effect")) == "DoNotEnforce"]
    mg_scoped = [r for r in rows if "/managementgroups/" in str(dig(r, "scope")).lower()]
    inherited = {}
    if mg_scoped:
        hierarchy = arg_rows("ResourceContainers | where type =~ 'microsoft.resources/subscriptions' | where subscriptionId in (" + subq(ctx["subs"]) + ") | project id=tolower(id), mg=tostring(properties.managementGroupAncestorsChain)", ctx["subs"], scoped=False)
        if hierarchy is None:
            denied_now("sub-policy-coverage")
        else:
            for h in hierarchy:
                chain_raw = dig(h, "mg")
                if isinstance(chain_raw, str):
                    try:
                        chain_raw = json.loads(chain_raw) if chain_raw.strip() else []
                    except ValueError:
                        chain_raw = []
                inherited[str(dig(h, "id"))] = {str(dig(a, "name")).lower() for a in lst(chain_raw)}
    for s in ctx["subs"]:
        direct = len([r for r in rows if str(dig(r, "subscriptionId")) == s or s in str(dig(r, "scope"))])
        if direct:
            continue
        ancestors = inherited.get("/subscriptions/" + s.lower(), set())
        covered = [r for r in mg_scoped if str(dig(r, "scope")).lower().split("/")[-1] in ancestors]
        if covered:
            add("info", "policy-inherited-from-mg", "subscription", "managementGroupAssignments=" + str(len(covered)), "guardrails reach this subscription through its management group", s, "/subscriptions/" + s)
        elif mg_scoped and not inherited:
            add("low", "policy-inheritance-unresolved", "subscription", "managementGroupAssignments=" + str(len(mg_scoped)) + " ancestry unreadable", "inheritance cannot be confirmed", s, "/subscriptions/" + s)
        else:
            add("medium", "no-policy-assignment", "subscription", "assignments=0 managementGroupAssignments=" + str(len(mg_scoped)), "no guardrail is applied to this subscription", s, "/subscriptions/" + s)
    for r in dont:
        add("medium", "policy-not-enforced", dig(r, "name"), "enforcementMode=DoNotEnforce", "the assignment evaluates but does not enforce", str(dig(r, "subscriptionId")))
    add("info", "policy-assignment-count", "all", "total=" + str(len(rows)) + " subscriptionOrMgScoped=" + str(len(sub_scoped)) + " disabled=" + str(len(dont)), "guardrail inventory")


@check("sub-activity-log-retention")
def c_log_profiles(ctx):
    rows = per_sub(ctx["subs"], "providers/Microsoft.Insights/logprofiles", "2016-03-01", lambda d: d.get("value") or [])
    note("sub-activity-log-retention", sum(1 for v in rows.values() if v is not None), denied=sum(1 for v in rows.values() if v is None))
    for s, items in rows.items():
        if items is None:
            continue
        if not items:
            add("medium", "no-activity-log-profile", "subscription", "logprofiles=0", "activity log is kept only for the platform default of 90 days", s, "/subscriptions/" + s)
        for p in items:
            props = p.get("properties") or {}
            days = props.get("retentionPolicy") or {}
            add("info", "activity-log-retention", "subscription", "enabled=" + str(dig(days, "enabled")) + " days=" + str(dig(days, "days")), "activity log retention", s, "/subscriptions/" + s)


@check("sub-kv-object-posture")
def c_kv_objects(ctx):
    vaults = _kv_vaults(ctx["subs"])
    if vaults is None:
        note("sub-kv-object-posture", 0, denied=1)
        return
    note("sub-kv-object-posture", len(vaults))
    for raw, v in vaults:
        s = raw.get("subscriptionId")
        name = raw.get("name")
        days = v["softDays"]
        if days is not MISSING and days is not None and days <= 0:
            add("medium", "keyvault-softdelete-retention-zero", name, "softDeleteRetentionInDays=" + str(days), "retention window is zero; deleted objects are unrecoverable", s)
        if v["policies"]:
            ids = {(p or {}).get("objectId") for p in v["policies"] if (p or {}).get("objectId")}
            add("info", "keyvault-policy-principals", name, "principals=" + str(len(ids)), "access policy model in force; each principal holds vault-wide rights", s)



@check("sub-appgw-tls")
def c_appgw(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.network/applicationgateways' | project name, subscriptionId, ssl=tostring(properties.sslPolicy), listeners=properties.httpListeners", ctx["subs"])
    if rows is None:
        note("sub-appgw-tls", 0, denied=1)
        return
    note("sub-appgw-tls", len(rows))
    for r in rows:
        s = r.get("subscriptionId")
        policy = str(r.get("ssl") or "")
        if not policy or policy in ("None", "{}", "null", "[]"):
            add("medium", "appgw-no-tls-policy", r.get("name"), "sslPolicy=unset", "listeners use the default TLS policy", s)
        elif "minProtocolVersion" not in policy and "policyType" not in policy:
            add("low", "appgw-tls-policy-unparsed", r.get("name"), "sslPolicy=" + policy[:40], "policy object shape unexpected; version not verified", s)
        for l in lst(dig(r, "listeners")):
            props = dig(l, "properties")
            proto = str(val(dig(props, "protocol"), "unknown")).upper()
            redirect = dig(props, "redirectConfiguration")
            if proto == "HTTP" and not dig(props, "sslCertificate") and redirect:
                add("info", "appgw-listener-redirect", str(dig(r, "name")) + " " + str(dig(l, "name")), "protocol=Http redirectConfiguration=present", "the listener redirects clients to HTTPS", s)
            elif proto == "HTTP" and not dig(props, "sslCertificate"):
                add("high", "appgw-listener-plaintext", str(dig(r, "name")) + " " + str(dig(l, "name")), "protocol=Http sslCertificate=none redirectConfiguration=none", "the listener accepts unencrypted traffic from clients", s)
            elif proto == "HTTPS" and not dig(props, "sslCertificate"):
                add("medium", "appgw-listener-no-cert", str(dig(r, "name")) + " " + str(dig(l, "name")), "protocol=Https sslCertificate=none", "the listener references no certificate; configuration is incomplete", s)


@check("sub-rbac-scope-breadth")
def c_rbac_breadth(ctx):
    rows = arg_rows("AuthorizationResources | where type =~ 'microsoft.authorization/roleassignments' | where subscriptionId in (" + subq(ctx["subs"]) + ") | project principalId=tostring(properties.principalId), roleId=tostring(properties.roleDefinitionId), scope=tostring(properties.scope), subscriptionId", ctx["subs"], scoped=False)
    if rows is None:
        note("sub-rbac-scope-breadth", 0, denied=1)
        return
    note("sub-rbac-scope-breadth", len(rows))
    depth = Counter()
    for r in rows:
        sc = str(r.get("scope") or "")
        if "/resourceGroups/" in sc and sc.count("/") >= 5:
            depth["resource"] += 1
        elif "/resourceGroups/" in sc:
            depth["resourceGroup"] += 1
        elif sc.count("/") == 2:
            depth["subscription"] += 1
        else:
            depth["managementGroupOrRoot"] += 1
    for k, v in depth.items():
        add("info", "rbac-scope-depth", k, "assignments=" + str(v), "assignment scope distribution")
    for r in rows:
        sc = str(r.get("scope") or "")
        if "/resourceGroups/" in sc and "/providers/" in sc:
            add("low", "rbac-resource-scope", str(r.get("principalId")), "scope=" + sc, "a per-resource assignment; review whether it is still needed", r.get("subscriptionId"))


@check("entra-app-publisher")
def c_publisher(ctx):
    apps = graph_all("applications?$select=appId,displayName,verifiedPublisher,publisherDomain,signInAudience", limit=10)
    if apps is None:
        note("entra-app-publisher", 0, denied=1)
        return
    note("entra-app-publisher", len(apps))
    for a in apps:
        vp = a.get("verifiedPublisher") or {}
        if not vp.get("verifiedPublisherId"):
            add("low", "app-publisher-unverified", a.get("displayName"), "verifiedPublisher=none domain=" + str(a.get("publisherDomain")), "consent screen shows no verified publisher; check who controls the publisher domain")
        dom = str(a.get("publisherDomain") or "")
        if dom and not dom.lower().endswith((".onmicrosoft.com",)) and vp.get("verifiedPublisherId"):
            add("info", "app-external-publisher", a.get("displayName"), "publisherDomain=" + dom, "publisher is a third party; consent grants carry their risk")


@check("entra-saml-config")
def c_saml_config(ctx):
    sps = graph_all("servicePrincipals?$filter=preferredSingleSignOnMode eq 'saml'&$select=id,displayName,preferredSingleSignOnMode,samlSingleSignOnSettings,notificationEmailAddresses,preferredTokenSigningKeyThumbprint", limit=10)
    if sps is None:
        note("entra-saml-config", 0, denied=1)
        return
    note("entra-saml-config", len(sps))
    for sp in sps:
        st = sp.get("samlSingleSignOnSettings") or {}
        relay = str(st.get("relayState") or "")
        if relay.lower().startswith("http://"):
            add("high", "saml-relay-state-plaintext", sp.get("displayName"), "relayState=" + relay[:60], "assertion posted over plaintext HTTP")
        if not (sp.get("notificationEmailAddresses") or []):
            add("low", "saml-no-cert-contacts", sp.get("displayName"), "notificationEmailAddresses empty", "certificate expiry warnings have no recipient")
        if not sp.get("preferredTokenSigningKeyThumbprint"):
            add("medium", "saml-no-pinned-key", sp.get("displayName"), "preferredTokenSigningKeyThumbprint unset", "either signing certificate is accepted; rotation can be hijacked")


@check("entra-admin-unit-scope")
def c_au_scope(ctx):
    aus = graph_all("directory/administrativeUnits", limit=5)
    if aus is None:
        note("entra-admin-unit-scope", 0, denied=1)
        return
    note("entra-admin-unit-scope", len(aus))
    for au in aus:
        members = graph_all("directory/administrativeUnits/" + str(au.get("id")) + "/scopedRoleMembers", limit=3)
        if members is None:
            denied_now("entra-admin-unit-scope")
            continue
        for m in members:
            rid = str(m.get("roleId") or "")
            add("medium", "admin-unit-scoped-role", au.get("displayName"), "roleId=" + rid + " principal=" + str(m.get("roleMemberInfo", {}).get("displayName")), "delegated administration confined to this container; verify the containment")


@check("entra-app-management-policy")
def c_app_mgmt_policy(ctx):
    pol = graph("policies/defaultAppManagementPolicy")
    if pol is None:
        note("entra-app-management-policy", 0, denied=1)
        return
    note("entra-app-management-policy", 1)
    res = pol.get("restrictions") or {}
    keys = set(res.keys())
    if not keys:
        add("high", "app-policy-empty", "default", "restrictions empty", "no tenant-wide cap on credential lifetime or secret addition")
        return
    pw = res.get("passwordCredentials") or []
    max_days = 0
    for item in pw:
        if str(item.get("restrictionType")) == "passwordAddition" and item.get("maxLifetime") is None:
            add("high", "app-policy-allows-unbounded-secret", "default", "passwordAddition without maxLifetime", "an application secret can be created with unlimited lifetime")
        if item.get("maxLifetime"):
            raw = str(item.get("maxLifetime")).upper().replace("P", "")
            days = 0
            for num, unit in re.findall(r"(\d+)([YMWD])", raw):
                days += int(num) * {"Y": 365, "M": 30, "W": 7, "D": 1}[unit]
            max_days = max(max_days, days)
    add("info", "app-policy-credential-cap", "default", "restrictions=" + ",".join(sorted(keys)) + " maxDays=" + str(max_days), "tenant-wide credential rules")


@check("sub-mgmt-hierarchy")
def c_mgmt_hierarchy(ctx):
    rows = arg_rows(tenant_wide("ResourceContainers | where type =~ 'microsoft.management/managementgroups' | project name, id, parent=tostring(properties.details.parent.id), children=properties.details.children"), ctx["subs"], scoped=False)
    if rows is None:
        note("sub-mgmt-hierarchy", 0, denied=1)
        return
    note("sub-mgmt-hierarchy", len(rows))
    roots = [r for r in rows if not r.get("parent")]
    for r in roots:
        add("info", "management-group-root", r.get("name"), "children=" + str(len(r.get("children") or [])), "hierarchy root; Owner here covers every subscription below")
    arr = unread(arg_rows(tenant_wide("AuthorizationResources | where type =~ 'microsoft.authorization/roleassignments' | where tostring(properties.scope) == '/' | project principalId=tostring(properties.principalId), roleId=tostring(properties.roleDefinitionId), principalType=tostring(properties.principalType)"), ctx["subs"], scoped=False),
                 "tenant root role assignments", "tenant-root-assignments-unreadable")
    if arr is None:
        return
    for r in arr:
        rid = str(r.get("roleId") or "")
        if rid.endswith(BUILTIN_ROLE_OWNER) or rid.endswith(BUILTIN_ROLE_UAA):
            add("critical", "tenant-root-role-assignment", str(r.get("principalId")), "role=" + rid + " type=" + str(r.get("principalType")), "assignment at tenant root covers every subscription and management group")


@check("sub-diag-content")
def c_diag_content(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.insights/diagnosticsettings' | project name, subscriptionId, target=tostring(properties.storageAccountId), workspace=tostring(properties.workspaceId), logs=properties.logs, retention=properties.retentionPolicy", ctx["subs"])
    if rows is None:
        note("sub-diag-content", 0, denied=1)
        return
    note("sub-diag-content", len(rows))
    for r in rows:
        s = r.get("subscriptionId")
        ret = r.get("retention") or {}
        ws = str(r.get("workspace") or "")
        tgt = str(r.get("target") or "")
        if ws and "/subscriptions/" in ws and ws.split("/subscriptions/")[-1].split("/")[0] != str(s):
            add("medium", "diag-cross-subscription-target", r.get("name"), "workspace=" + ws.split("/")[-1], "log destination sits in another subscription", s)
        if tgt and not ws:
            add("low", "diag-storage-only", r.get("name"), "destination=storage only", "no query surface; retention depends on the account policy", s)
        if not ret.get("enabled"):
            add("low", "diag-retention-default", r.get("name"), "retentionPolicy.enabled=false", "logs are dropped at the default platform retention", s)


@check("sub-storage-cmk")
def c_storage_cmk(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.storage/storageaccounts' | project name, subscriptionId, keySource=tostring(properties.encryption.keySource), kvUri=tostring(properties.encryption.keyVaultProperties.keyVaultUri), keyName=tostring(properties.encryption.keyVaultProperties.keyName), keyVersion=tostring(properties.encryption.keyVaultProperties.keyVersion), ident=tostring(identity.type)", ctx["subs"])
    if rows is None:
        note("sub-storage-cmk", 0, denied=1)
        return
    note("sub-storage-cmk", len(rows))
    for r in rows:
        s = r.get("subscriptionId")
        if str(r.get("keySource") or "").lower() == "microsoft.keyvault":
            if not dig(r, "keyVersion"):
                add("info", "storage-cmk-auto-rotation", dig(r, "name"), "keyVaultProperties.keyVersion absent", "the account follows the latest key version, which is the recommended rotation behaviour", s)
            else:
                add("low", "storage-cmk-pinned-version", dig(r, "name"), "keyVersion=" + str(dig(r, "keyVersion")), "a pinned version does not follow key rotation", s)
            if not r.get("ident"):
                add("high", "storage-cmk-no-identity", r.get("name"), "identity.type=none with keySource=Keyvault", "the account cannot unwrap its own key; access depends on a shared secret", s)


@check("sub-sql-outbound")
def c_sql_outbound(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.sql/servers' | project name, subscriptionId, rg=resourceGroup, outbound=properties.restrictOutboundNetworkAccess, publicNet=tostring(properties.publicNetworkAccess)", ctx["subs"])
    if rows is None:
        note("sub-sql-outbound", 0, denied=1)
        return
    note("sub-sql-outbound", len(rows))
    for r in rows:
        s = r.get("subscriptionId")
        if str(r.get("outbound") or "").lower() in ("enabled", "true"):
            add("info", "sql-outbound-restricted", r.get("name"), "restrictOutboundNetworkAccess=Enabled", "server egress is limited to the outbound firewall list", s)
        else:
            add("low", "sql-outbound-open", r.get("name"), "restrictOutboundNetworkAccess not Enabled", "server can reach arbitrary endpoints; usable for exfiltration", s)


@check("sub-net-routes")
def c_routes(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.network/routetables' | mv-expand rt = properties.routes | extend hop=tostring(rt.properties.nextHopType), addr=tostring(rt.properties.addressPrefix) | where addr in ('0.0.0.0/0','0.0.0.0/1','0.0.0.0/0-0.0.0.0/0') | project name, subscriptionId, route=tostring(rt.name), hop=hop, addr=addr", ctx["subs"])
    if rows is None:
        note("sub-net-routes", 0, denied=1)
        return
    note("sub-net-routes", len(rows))
    for r in rows:
        hop = str(r.get("hop") or "")
        if hop in ("Internet", "None"):
            add("medium", "route-default-to-internet", r.get("name"), "route=" + str(r.get("route")) + " nextHop=" + hop, "all egress bypasses inspection", r.get("subscriptionId"))
        else:
            add("info", "route-default-captured", r.get("name"), "route=" + str(r.get("route")) + " nextHop=" + hop, "default route is captured by an appliance")


@check("sub-appservice-net")
def c_web_net(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.web/sites' | project name, subscriptionId, rg=resourceGroup, publicNet=tostring(properties.publicNetworkAccess)", ctx["subs"])
    if rows is None:
        note("sub-appservice-net", 0, denied=1)
        return
    note("sub-appservice-net", len(rows))
    cfg = unread(arg_rows("Resources | where type =~ 'microsoft.web/sites/config' | where name =~ 'web' | project parent=tolower(substring(id, 0, indexof(tolower(id), '/config/'))), subnet=tostring(properties.virtualNetworkSubnetId), routeAll=tostring(properties.vnetRouteAllEnabled)", ctx["subs"]),
                 "web app site configurations", "appservice-net-configs-unreadable")
    if cfg is None:
        return
    vnet = {}
    for c in cfg:
        vnet[str(dig(c, "parent")).lower()] = c
    for r in rows[:25]:
        s = r.get("subscriptionId")
        key = ("/subscriptions/" + str(s) + "/resourcegroups/" + str(r.get("rg")) + "/providers/microsoft.web/sites/" + str(r.get("name"))).lower()
        c = vnet.get(key)
        if c is None:
            add("low", "appservice-vnet-unreadable", r.get("name"), "siteConfig not returned", "VNet integration cannot be confirmed", s)
            continue
        subnet = str(val(dig(c, "subnet"), ""))
        public = str(val(dig(r, "publicNet"), "")).lower() or "enabled"
        if public == "enabled" and not subnet:
            add("medium", "appservice-public-no-vnet", r.get("name"), "publicNetworkAccess=Enabled vnetIntegration=none", "the app is reachable without a private path", s)
        if subnet and tri(dig(c, "routeAll")) is not True:
            add("low", "appservice-vnet-routes-not-all", r.get("name"), "vnetRouteAllEnabled not true", "only default traffic uses the VNet", s)
    sample("sub-appservice-net", min(len(rows), 25), len(rows), "web apps")


@check("sub-aks-wi")
def c_aks_wi(ctx):
    q = "Resources | where type =~ 'microsoft.containerservice/managedclusters' | project name, subscriptionId, oidc=tostring(properties.oidcIssuerProfile.enabled), wi=tostring(properties.securityProfile.workloadIdentity.enabled), policy=tostring(properties.addonProfiles.azurepolicy.enabled), privateFqdn=tostring(properties.privateFQDN)"
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-aks-wi", 0, denied=1)
        return
    note("sub-aks-wi", len(rows))
    for r in rows:
        s = r.get("subscriptionId")
        oidc_state = tri(dig(r, "oidc"))
        wi_state = tri(dig(r, "wi"))
        if oidc_state is False:
            add("medium", "aks-no-oidc-issuer", dig(r, "name"), "oidcIssuerProfile.enabled=false", "no workload identity federation possible", s)
        elif oidc_state is None:
            add("low", "aks-oidc-state-unknown", dig(r, "name"), "oidcIssuerProfile not returned", "workload identity federation cannot be confirmed", s)
        if wi_state is False and oidc_state is True:
            add("low", "aks-workload-identity-off", r.get("name"), "workloadIdentity.enabled=" + str(r.get("wi")), "pods must use node identity", s)
        if tri(dig(r, "policy")) is False:
            add("medium", "aks-policy-addon-off", r.get("name"), "addonProfiles.azurepolicy.enabled=" + str(r.get("policy")), "no admission control from Azure Policy", s)
        if not r.get("privateFqdn"):
            add("low", "aks-api-public", r.get("name"), "privateFQDN absent", "API server name resolves publicly", s)


GRAPH_SUB_CHECKS = ("sub-orphans", "sub-approle-orphans", "sub-arm-orphans", "sub-sql-orphans", "sub-guest-rbac", "sub-rbac-write", "sub-managed-identities")


@check("entra-ca-scope-detail")
def c_ca_scope(ctx):
    pols = ca_all("policies", limit=5)
    if pols is None:
        note("entra-ca-scope-detail", 0, denied=1)
        return
    note("entra-ca-scope-detail", len(pols))
    for p in pols:
        if p.get("state") != "enabled":
            continue
        cond = p.get("conditions") or {}
        name = p.get("displayName")
        apps = cond.get("applications") or {}
        for ex in apps.get("excludeApplications") or []:
            add("medium", "ca-app-excluded", name, "excludeApplications=" + str(ex), "that workload skips the policy")
        users = cond.get("users") or {}
        if users.get("includeRoles"):
            covered = len(users.get("includeRoles") or [])
            add("info", "ca-role-scoped", name, "includeRoles=" + str(covered), "policy covers selected directory roles only")
        platforms = cond.get("platforms") or {}
        included = [str(x) for x in lst(dig(platforms, "includePlatforms"))]
        if included and "all" not in [i.lower() for i in included]:
            add("low", "ca-platform-restricted", name, "includePlatforms=" + ",".join(included), "other platforms are outside this control")
        dev = cond.get("devices") or {}
        include_states = [str(x) for x in lst(dig(dev, "deviceStates.includeStates"))]
        if include_states and "all" not in [x.lower() for x in include_states]:
            add("low", "ca-device-state-restricted", name, "deviceStates=" + ",".join(include_states), "device filter narrows the population")
        locs = cond.get("locations") or {}
        if locs.get("includeLocations") and "All" not in (locs.get("includeLocations") or []):
            add("low", "ca-location-restricted", name, "includeLocations=" + str(len(locs.get("includeLocations") or [])), "only listed locations are covered")
    roles = graph_all("roleManagement/directory/roleDefinitions", limit=5)
    if roles is None:
        note("entra-ca-scope-detail", len(pols), denied=1)
        add("info", "ca-role-coverage-unassessed", "tenant", "roleDefinitions unreadable", "privileged role coverage was not assessed")
        return
    wanted = {dig(d, "id"): dig(d, "displayName") for d in roles if is_escalation(d)}
    covered_roles = set()
    for p in pols:
        if p.get("state") != "enabled":
            continue
        cond = p.get("conditions") or {}
        users = cond.get("users") or {}
        apps = cond.get("applications") or {}
        gc = p.get("grantControls") or {}
        excluded_roles = set(users.get("excludeRoles") or [])
        apps_all_excluded = "All" in lst(dig(apps, "excludeApplications")) and "All" in lst(dig(apps, "includeApplications"))
        if apps_all_excluded:
            continue
        covered_roles.update([r for r in lst(dig(users, "includeRoles")) if r not in excluded_roles])
        if "All" in lst(dig(users, "includeUsers")) and gc.get("builtInControls"):
            covered_roles.update([r for r in wanted if r not in excluded_roles])
        if lst(dig(users, "excludeGroups")) or lst(dig(users, "excludeUsers")):
            add("info", "ca-role-coverage-exclusions", str(val(dig(p, "displayName"), "policy")), "excludeUsers=" + str(len(lst(dig(users, "excludeUsers")))) + " excludeGroups=" + str(len(lst(dig(users, "excludeGroups")))), "the policy still covers roles; these identities are the exception")
    uncovered = [label for rid, label in wanted.items() if rid not in covered_roles]
    enabled_total = len([p for p in pols if str(dig(p, "state")) == "enabled"])
    if not enabled_total and uncovered:
        add("medium", "ca-roles-unconstrained", "tenant", "roles=" + str(len(uncovered)) + " enabledPolicies=0", "no enforced policy exists, so no privileged role is constrained")
    else:
        for label in uncovered:
            add("medium", "ca-role-uncovered", label, "no enforced policy names this role", "administrative sign-in is not constrained by conditional access")


@check("entra-implicit-grant")
def c_implicit(ctx):
    apps = graph_all("applications?$select=appId,displayName,web,signInAudience", limit=10)
    if apps is None:
        note("entra-implicit-grant", 0, denied=1)
        return
    note("entra-implicit-grant", len(apps))
    for a in apps:
        imp = dig(a, "web.implicitGrantSettings", {})
        redirects = [str(u) for u in lst(dig(a, "web.redirectUris"))]
        if not redirects:
            continue
        if tri(dig(imp, "enableAccessTokenIssuance")) is True:
            weak = [u for u in redirects if not u.lower().startswith("https://")]
            add("high", "implicit-access-token", dig(a, "displayName"),
                "enableAccessTokenIssuance=true redirectUris=" + str(len(redirects)) + (" nonHttps=" + str(len(weak)) if weak else ""),
                "the implicit flow is reachable: an access token returns in the fragment and no PKCE protects the response")
        if tri(dig(imp, "enableIdTokenIssuance")) is True:
            add("low", "implicit-id-token", dig(a, "displayName"), "enableIdTokenIssuance=true redirectUris=" + str(len(redirects)), "implicit id token flow enabled on a reachable web redirect URI")


@check("entra-api-scopes")
def c_api_scopes(ctx):
    apps = graph_all("applications?$select=appId,displayName,api,identifierUris", limit=10)
    if apps is None:
        note("entra-api-scopes", 0, denied=1)
        return
    note("entra-api-scopes", len(apps))
    for a in apps:
        scopes = (a.get("api") or {}).get("oauth2PermissionScopes") or []
        if not scopes:
            continue
        admin = [s.get("value") for s in scopes if str(s.get("type") or "").lower() == "admin" or s.get("adminConsentRequired")]
        add("info" if not admin else "medium", "tenant-api-scope-exposed", a.get("displayName"), "scopes=" + str(len(scopes)) + " admin=" + str(len(admin)), "the tenant publishes delegated scopes; other tenants can consent to them")


@check("entra-redirect-uri")
def c_redirect(ctx):
    apps = graph_all("applications?$select=appId,displayName,web,spa,publicClient", limit=10)
    if apps is None:
        note("entra-redirect-uri", 0, denied=1)
        return
    note("entra-redirect-uri", len(apps))
    for a in apps:
        uris = []
        for key in ("web", "spa", "publicClient"):
            uris.extend([str(u) for u in ((a.get(key) or {}).get("redirectUris") or [])])
        for u in uris:
            low = u.lower()
            if "*" in low:
                add("high", "redirect-uri-wildcard", a.get("displayName"), "uri=" + u[:80], "a wildcard redirect lets an attacker receive the code")
            elif low.startswith("http://") and "localhost" not in low:
                add("high", "redirect-uri-plaintext", a.get("displayName"), "uri=" + u[:80], "authorization code returned over plaintext HTTP")
            elif "localhost" in low:
                add("low", "redirect-uri-localhost", a.get("displayName"), "uri=" + u[:80], "loopback redirect; verify the client is public-only")


@check("sub-policy-notscopes")
def c_policy_notscopes(ctx):
    rows = arg_rows("PolicyResources | where type =~ 'microsoft.authorization/policyassignments' | where array_length(properties.notScopes) > 0 | extend ns=properties.notScopes | mv-expand n=ns | project name, subscriptionId, excluded=tostring(n)", ctx["subs"])
    if rows is None:
        note("sub-policy-notscopes", 0, denied=1)
        return
    note("sub-policy-notscopes", len(rows))
    for r in rows:
        add("medium", "policy-scope-excluded", r.get("name"), "notScopes=" + str(r.get("excluded")), "this resource tree is outside the guardrail", r.get("subscriptionId"))


@check("sub-cosmos-net")
def c_cosmos_net(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.documentdb/databaseaccounts' | project name, subscriptionId, publicNet=tostring(properties.publicNetworkAccess), vnet=tostring(properties.isVirtualNetworkFilterEnabled), ipRules=properties.ipRules, bypass=tostring(properties.networkAclBypass)", ctx["subs"])
    if rows is None:
        note("sub-cosmos-net", 0, denied=1)
        return
    note("sub-cosmos-net", len(rows))
    for r in rows:
        s = r.get("subscriptionId")
        ip_rules = lst(dig(r, "ipRules"))
        if str(val(dig(r, "publicNet"), "")).lower() == "enabled" and tri(dig(r, "vnet")) is False:
            if ip_rules:
                add("low", "cosmos-public-ip-restricted", dig(r, "name"), "publicNetworkAccess=Enabled ipRules=" + str(len(ip_rules)), "the public endpoint is limited to listed addresses", s)
            else:
                add("medium", "cosmos-public-no-vnet", dig(r, "name"), "publicNetworkAccess=Enabled vnetFilter=false ipRules=0", "account reachable from any network", s)
        if str(r.get("bypass") or "") == "AzureServices":
            add("low", "cosmos-azure-services-bypass", r.get("name"), "networkAclBypass=AzureServices", "trusted-service bypass remains open", s)


@check("sub-backup-vault-posture")
def c_backup_vault(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.recoveryservices/vaults' | project name, subscriptionId, props=properties", ctx["subs"])
    if rows is None:
        note("sub-backup-vault-posture", 0, denied=1)
        return
    note("sub-backup-vault-posture", len(rows))
    for r in rows:
        s = r.get("subscriptionId")
        p = r.get("props") or {}
        sec = p.get("securitySettings") or {}
        red = p.get("redundancySettings") or {}
        soft = sec.get("softDeleteSettings") or {}
        sd_state = on_off(soft.get("softDeleteState"))
        if sd_state == "off":
            add("medium", "backup-vault-softdelete-off", dig(r, "name"), "softDeleteState=" + str(dig(soft, "softDeleteState")), "deleted backups cannot be recovered", s)
        elif sd_state == "unknown":
            add("low", "backup-vault-softdelete-unknown", r.get("name"), "softDeleteState not returned", "recovery capability cannot be confirmed", s)
        if on_off(soft.get("enhancedSecurityState")) != "on":
            add("low", "backup-vault-mua-off", dig(r, "name"), "enhancedSecurityState=" + str(dig(soft, "enhancedSecurityState")), "multi-user authorisation not enforced", s)
        if str(red.get("standardTierStorageRedundancy") or "").lower() in ("locallyredundant", "lrs"):
            add("low", "backup-vault-lrs", r.get("name"), "standardTierStorageRedundancy=LRS", "vault is not resilient to a region failure", s)


@check("sub-aks-kv-provider")
def c_aks_kv(ctx):
    q = "Resources | where type =~ 'microsoft.containerservice/managedclusters' | project name, subscriptionId, kv=tostring(properties.addonProfiles.azureKeyvaultSecretsProvider.enabled), csi=tostring(properties.addonProfiles.azureKeyvaultSecretsProvider.config.enableSecretRotation), ident=tostring(properties.identity.type), kubelet=tostring(properties.identityProfile.kubeletidentity.objectId), pools=properties.agentPoolProfiles"
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-aks-kv-provider", 0, denied=1)
        return
    note("sub-aks-kv-provider", len(rows))
    for r in rows:
        s = r.get("subscriptionId")
        kv = tri(r.get("kv"))
        if kv is False:
            add("info", "aks-no-kv-provider", r.get("name"), "azureKeyvaultSecretsProvider=disabled", "secrets are stored in cluster objects, not Key Vault", s)
        elif tri(r.get("csi")) is not True:
            add("low", "aks-kv-secret-rotation-off", r.get("name"), "enableSecretRotation not true", "rotated vault secrets are not refreshed in the pod", s)
        kubelet = str(val(dig(r, "kubelet"), ""))
        if not kubelet:
            add("medium", "aks-no-kubelet-identity", dig(r, "name"), "identityProfile.kubeletidentity.objectId not returned", "kubelet has no dedicated managed identity to scope the node resource group", s)
        elif str(val(dig(r, "ident"), "")).lower() not in ("systemassigned", "userassigned"):
            add("low", "aks-no-cluster-identity", dig(r, "name"), "identity.type=" + str(val(dig(r, "ident"), "none")) + " kubeletIdentity=present", "the cluster control plane has no identity of its own", s)


@check("entra-sp-credential-expiry")
def c_sp_cred(ctx):
    sps = graph_all("servicePrincipals?$select=id,displayName,passwordCredentials,keyCredentials", limit=10)
    if sps is None:
        note("entra-sp-credential-expiry", 0, denied=1)
        return
    note("entra-sp-credential-expiry", len(sps))
    horizon = time.time() + 730 * 86400
    for sp in sps:
        for kind in ("passwordCredentials", "keyCredentials"):
            for cred in lst(dig(sp, kind)):
                end = str(dig(cred, "endDateTime") or "")
                if not end:
                    add("high", "sp-credential-no-expiry", dig(sp, "displayName"), kind + " without endDateTime", "the credential never expires")
                    continue
                stamp = _stamp(end)
                if stamp is None:
                    add("low", "sp-credential-unparsed-expiry", dig(sp, "displayName"), kind + " end=" + end, "expiry cannot be read")
                    continue
                if stamp > horizon:
                    add("medium", "sp-credential-long-lived", dig(sp, "displayName"), kind + " end=" + end, "credential valid for more than two years")


@check("entra-dormant-guests")
def c_dormant_guests(ctx):
    guests = graph_all("users?$filter=userType eq 'Guest'&$select=id,userPrincipalName,signInActivity,createdDateTime", limit=10)
    if guests is None:
        note("entra-dormant-guests", 0, denied=1)
        return
    note("entra-dormant-guests", len(guests))
    cutoff = time.time() - 90 * 86400
    for g in guests:
        act = g.get("signInActivity") or {}
        last = str(act.get("lastSignInDateTime") or "")
        if not last:
            add("medium", "guest-never-signed-in", g.get("userPrincipalName"), "created=" + str(g.get("createdDateTime")), "guest object exists with no sign-in record")
        elif (_stamp(last) or 0.0) < cutoff:
            add("low", "guest-dormant", g.get("userPrincipalName"), "lastSignIn=" + last, "external identity unused for more than 90 days")


@check("entra-deleted-service-principals")
def c_deleted_sps(ctx):
    deleted = graph_all("directory/deletedItems/microsoft.graph.servicePrincipal?$select=id,appId,displayName,deletedDateTime", limit=5)
    if deleted is None:
        note("entra-deleted-service-principals", 0, denied=1)
        return
    note("entra-deleted-service-principals", len(deleted))
    if not deleted:
        return
    ids = {d.get("id") for d in deleted}
    assignments = graph_all("roleManagement/directory/roleAssignments", limit=5)
    if assignments is None:
        deny("entra-deleted-service-principals")
        return
    for a in assignments:
        if a.get("principalId") in ids:
            add("high", "deleted-sp-holds-role", str(a.get("principalId")), "role=" + str(a.get("roleDefinitionId")), "soft-deleted workload identity still referenced by an assignment")


@check("sub-uami-fic-arm")
def c_uami_arm(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.managedidentity/userassignedidentities/federatedidentitycredentials' | project name, subscriptionId, issuer=tostring(properties.issuer), subject=tostring(properties.subject), audiences=properties.audiences", ctx["subs"])
    if rows is None:
        note("sub-uami-fic-arm", 0, denied=1)
        return
    note("sub-uami-fic-arm", min(len(rows), 25))
    sample("sub-uami-fic-arm", min(len(rows), 25), len(rows), "federated credentials")
    for r in rows[:25]:
        sub = str(r.get("subject") or "")
        issuer = str(r.get("issuer") or "")
        wildcard = "*" in sub
        foreign = bool(issuer) and not any(issuer.startswith(k) for k in KNOWN_FIC_ISSUERS)
        sev = "high" if wildcard or foreign else "medium"
        add(sev, "uami-fic-arm", dig(r, "name"), "issuer=" + issuer + " subject=" + sub, "ARM-level federation for a user-assigned identity" + ("; issuer is not a known token service" if foreign else ""), str(dig(r, "subscriptionId")))


@check("sub-waf-attachment")
def c_waf_attach(ctx):
    gw = arg_rows("Resources | where type =~ 'microsoft.network/applicationgateways' | project name, subscriptionId, policy=tostring(properties.firewallPolicy.id), waf=tostring(properties.webApplicationFirewallConfiguration.enabled), mode=tostring(properties.webApplicationFirewallConfiguration.firewallMode)", ctx["subs"])
    if gw is None:
        note("sub-waf-attachment", 0, denied=1)
        return
    note("sub-waf-attachment", len(gw))
    for r in gw:
        s = r.get("subscriptionId")
        if not dig(r, "policy") and tri(dig(r, "waf")) is not True:
            add("high", "appgw-no-waf", r.get("name"), "firewallPolicy=none waf=disabled", "the gateway is published without a web application firewall", s)
        elif str(r.get("mode") or "").lower() == "detection":
            add("medium", "appgw-waf-detection-only", r.get("name"), "firewallMode=Detection", "rules log but do not block", s)


@check("sub-pim-azure-approval")
def c_pim_azure(ctx):
    rows = arg_rows("AuthorizationResources | where type =~ 'microsoft.authorization/roleeligibilityschedules' | project name, subscriptionId, scope=tostring(properties.scope), principalId=tostring(properties.principalId), roleId=tostring(properties.roleDefinitionId)", ctx["subs"])
    if rows is None:
        note("sub-pim-azure-approval", 0, denied=1)
        return
    note("sub-pim-azure-approval", len(rows))
    if not rows:
        add("info", "azure-pim-eligibility-unreadable", "all", "0 eligibility schedules visible", "either no PIM use or the caller cannot read schedules")
        return
    for r in rows:
        add("info", "azure-pim-eligible", str(r.get("principalId")), "role=" + str(r.get("roleId")) + " scope=" + str(r.get("scope")), "eligible assignment; activation rules are not readable through ARG")


@check("entra-pim-groups")
def c_pim_groups(ctx):
    rows = graph_all("identityGovernance/privilegedAccess/group/eligibilityScheduleInstances", limit=5, beta=True)
    if rows is None:
        note("entra-pim-groups", 0, denied=1)
        return
    note("entra-pim-groups", len(rows))
    if not rows:
        add("info", "no-pim-groups", "tenant", "0 group eligibility instances visible", "either PIM for Groups is unused or unreadable")
        return
    for r in rows:
        add("info", "pim-group-eligible", dig(r, "groupId"), "accessId=" + str(dig(r, "accessId")) + " schedule=" + str(dig(r, "scheduleInfo.expiration.type")), "group membership is assignable through PIM")


@check("entra-pim-alerts")
def c_pim_alerts(ctx):
    rows = graph_all("identityGovernance/roleManagementAlerts/alerts", limit=5, beta=True)
    if rows is None:
        note("entra-pim-alerts", 0, denied=1)
        return
    note("entra-pim-alerts", len(rows))
    for r in rows:
        state = str(dig(r, "alertConfiguration.isEnabled"))
        incidents = lst(dig(r, "alertIncidents"))
        add("info", "pim-alert", dig(r, "alertDefinition.displayName") or dig(r, "id"), "enabled=" + state + " incidents=" + str(len(incidents)), "PIM alert configuration")


@check("entra-access-review-results")
def c_review_results(ctx):
    rows = graph_all("identityGovernance/accessReviews/definitions", limit=5)
    if rows is None:
        note("entra-access-review-results", 0, denied=1)
        return
    note("entra-access-review-results", min(len(rows), 5))
    sample("entra-access-review-results", min(len(rows), 5), len(rows), "access review definitions read")
    for r in rows[:5]:
        rid = dig(r, "id")
        inst = graph("identityGovernance/accessReviews/definitions/" + str(rid) + "/instances", beta=True)
        if inst is None:
            denied_now("entra-access-review-results")
            continue
        items = lst(dig(inst, "value"))
        decided = [i for i in items if str(dig(i, "status")).lower() in ("completed", "applied")]
        add("info" if decided else "low", "review-instance-state" if decided else "review-never-run", dig(r, "displayName"), "instances=" + str(len(items)) + " completed=" + str(len(decided)), "recertification actually ran" if decided else "review definition has no completed instance")


@check("entra-legacy-auth-block")
def c_legacy_block(ctx):
    pols = ca_all("policies", limit=5)
    if pols is None:
        note("entra-legacy-auth-block", 0, denied=1)
        return
    note("entra-legacy-auth-block", len(pols))
    blocks = []
    for p in pols:
        if dig(p, "state") != "enabled":
            continue
        ctypes = [str(c).lower() for c in lst(dig(p, "conditions.clientAppTypes"))]
        controls = [str(c).lower() for c in lst(dig(p, "grantControls.builtInControls"))]
        users = dig(p, "conditions.users")
        excludes = lst(dig(users, "excludeUsers")) + lst(dig(users, "excludeGroups")) + lst(dig(users, "excludeRoles"))
        if ("other" in ctypes or "exchangeactivesync" in ctypes or "all" in ctypes) and "block" in controls:
            blocks.append(str(dig(p, "displayName")) + ("(exclusions=" + str(len(excludes)) + ")" if excludes else ""))
    if not ca_complete():
        capped("entra-legacy-auth-block", len(pols), "conditional access policy pages")
        return
    if blocks:
        add("info", "legacy-auth-blocked", "tenant", "policies=" + ",".join(str(b) for b in blocks), "legacy authentication is blocked by an enforced policy")
    else:
        add("high", "ca-legacy-auth-not-blocked", "tenant", "0 enforced Block policies for legacy clients", "IMAP, POP, SMTP and other legacy clients can authenticate")


@check("entra-ca-breakglass-sanity")
def c_breakglass_sanity(ctx):
    pols = ca_all("policies", limit=5)
    assignments = graph_all("roleManagement/directory/roleAssignments", limit=5)
    defs = graph_all("roleManagement/directory/roleDefinitions", limit=5)
    if pols is None or assignments is None or defs is None:
        note("entra-ca-breakglass-sanity", 0, denied=1)
        return
    note("entra-ca-breakglass-sanity", len(pols))
    ga = {dig(d, "id") for d in defs if str(dig(d, "templateId") or "").lower() == "62e90394-69f5-4237-9190-012177145e10"}
    holders = {dig(a, "principalId") for a in assignments if dig(a, "roleDefinitionId") in ga}
    excluded = set()
    excluded_groups = set()
    for p in pols:
        if dig(p, "state") == "enabled":
            excluded.update(lst(dig(p, "conditions.users.excludeUsers")))
            excluded_groups.update(str(g) for g in lst(dig(p, "conditions.users.excludeGroups")))
    group_members = set()
    trunc("entra-ca-breakglass-sanity", len(list(excluded_groups)[:10]), len(excluded_groups), "excluded groups")
    for gid in list(excluded_groups)[:10]:
        doc = graph("groups/" + gid + "/members?$select=id")
        if doc is None:
            denied_now("entra-ca-breakglass-sanity")
            continue
        group_members.update(str(dig(m, "id")) for m in lst(dig(doc, "value")))
    protected_exclusions = holders & (excluded | group_members)
    if not holders:
        add("medium", "no-global-administrator", "tenant", "0 Global Administrator assignments", "administrative path unverified")
    elif not protected_exclusions:
        add("high", "ca-no-breakglass-exclusion", "tenant", "globalAdmins=" + str(len(holders)) + " excludedFromEnabledPolicies=0", "no administrator is exempt from policy; a broken policy locks the tenant out")
    elif len(protected_exclusions) > 3:
        add("medium", "ca-exclusion-sprawl", "tenant", "excludedGlobalAdmins=" + str(len(protected_exclusions)), "too many exempt administrators weakens every policy")


@check("entra-delegated-scope-risk")
def c_delegated_risk(ctx):
    grants = graph_all("oauth2PermissionGrants", limit=10)
    if grants is None:
        note("entra-delegated-scope-risk", 0, denied=1)
        return
    note("entra-delegated-scope-risk", len(grants))
    sp_names = {}
    for s in unread_list(graph_all("servicePrincipals?$select=id,appId,displayName", limit=10),
                         "service principals for grant attribution", "delegated-risk-principals-unreadable"):
        label = str(val(dig(s, "displayName"), ""))
        if label:
            sp_names[str(dig(s, "id"))] = label
            sp_names[str(dig(s, "appId"))] = label
    high = ("mail.readwrite", "mail.send", "files.readwrite.all", "sites.fullcontrol.all", "directory.readwrite.all",
            "rolemanagement.readwrite.directory", "user.readwrite.all", "group.readwrite.all", "contacts.readwrite",
            "calendars.readwrite", "notes.readwrite.all", "chat.readwrite", "channelmessage.send")
    for g in grants:
        scopes = [s.strip().lower() for s in str(dig(g, "scope") or "").split() if s.strip()]
        hits = [s for s in scopes if s in high]
        if not hits:
            continue
        tenant_wide = str(dig(g, "consentType")) == "AllPrincipals"
        names = sp_names
        client = names.get(str(dig(g, "clientId")), "") or str(dig(g, "clientId"))
        add("high" if tenant_wide else "medium", "delegated-high-risk-scope", client, "scopes=" + ",".join(hits[:4]) + " consent=" + str(dig(g, "consentType")), "delegated grant covers a high-risk scope" + (" for every user" if tenant_wide else ""))


@check("entra-graph-approles-paged")
def c_approles_paged(ctx):
    sps = graph_all("servicePrincipals?$select=id,appId,displayName", limit=20)
    if sps is None:
        note("entra-graph-approles-paged", 0, denied=1)
        return
    note("entra-graph-approles-paged", len(sps))
    targets = (GRAPH_APP_ID, "00000002-0000-0ff1-ce00-000000000000", "00000003-0000-0ff1-ce00-000000000000")
    resource_ids = {str(dig(s, "id")) for s in sps if str(dig(s, "appId")) in targets}
    sampled = sps[:25]
    trunc("entra-graph-approles-paged", len(sampled), len(sps), "service principals queried for app role assignments")
    hits = 0
    checked = 0
    for sp in sampled:
        sid = dig(sp, "id")
        doc = graph("servicePrincipals/" + str(sid) + "/appRoleAssignments", beta=True)
        if doc is None:
            denied_now("entra-graph-approles-paged")
            continue
        checked += 1
        for a in lst(dig(doc, "value")):
            if str(dig(a, "resourceId")) in resource_ids:
                hits += 1
                add("info", "workload-app-role-assertion", dig(sp, "displayName"), "appRole=" + str(dig(a, "appRoleId")), "workload holds an application role")
    if hits == 0 and checked:
        add("info", "no-workload-app-roles", "tenant", "servicePrincipalsChecked=" + str(checked), "no application roles found across the sampled principals")


@check("entra-log-export-tenant")
def c_aadiam_logs(ctx):
    url = ARM_BASE + "/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01"
    LAST_QUERY[CURRENT["check"]] = "az rest --url " + repr(url)
    doc = arm(url)
    if doc is None:
        note("entra-log-export-tenant", 0, denied=1)
        add("info", "entra-log-export-unreadable", "tenant", "tenant-scope diagnosticSettings unavailable", "sign-in and audit export not assessed")
        return
    items = lst(dig(doc, "value"))
    note("entra-log-export-tenant", len(items))
    if not items:
        add("high", "entra-no-log-export", "tenant", "0 tenant diagnostic settings", "sign-in and audit logs are not exported; the gap is invisible after retention")
        return
    all_cats = set()
    for item in items:
        cats = [str(dig(c, "category")) for c in lst(dig(item, "properties.logs")) if dig(c, "enabled") is True]
        all_cats.update(cats)
        dest = "eventhub" if dig(item, "properties.eventHubAuthorizationRuleId") else ("workspace" if dig(item, "properties.workspaceId") else ("storage" if dig(item, "properties.storageAccountId") else "none"))
        add("info", "entra-log-export", dig(item, "name"), "destination=" + dest + " categories=" + ",".join(cats)[:80], "tenant audit export configuration")
    missing = [c for c in AAD_REQUIRED_CATEGORIES if c not in all_cats]
    if missing:
        add("medium", "entra-log-categories-missing", "tenant", "missing=" + ",".join(missing)[:80] + " settings=" + str(len(items)), "sign-in or audit category is exported by no setting; that gap is invisible after retention")
@check("sub-nsg-defaults")
def c_nsg_defaults(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.network/networksecuritygroups' | mv-expand r = properties.securityRules | extend prio=toint(r.properties.priority), acc=tostring(r.properties.access), dir=tostring(r.properties.direction), src=tostring(coalesce(r.properties.sourceAddressPrefix, strcat_array(r.properties.sourceAddressPrefixes, ','))), dst=tostring(coalesce(r.properties.destinationAddressPrefix, strcat_array(r.properties.destinationAddressPrefixes, ','))), port=tostring(coalesce(r.properties.destinationPortRange, strcat_array(r.properties.destinationPortRanges, ','))) | where dir=='Inbound' | project name, subscriptionId, rule=tostring(r.properties.name), prio=prio, src=src, dst=dst, port=port, acc=acc", ctx["subs"])
    if rows is None:
        note("sub-nsg-defaults", 0, denied=1)
        return
    note("sub-nsg-defaults", len(rows))
    by_nsg = defaultdict(list)
    for r in rows:
        by_nsg[(str(dig(r, "subscriptionId")), str(dig(r, "name")))].append(r)
    for (sub, nsg), rules in by_nsg.items():
        numbered = [(int(str(dig(r, "prio"))), r) for r in rules if str(dig(r, "prio")).isdigit()]
        ordered = [r for _, r in sorted(numbered, key=lambda pair: pair[0])]
        for idx_pos, r in enumerate(ordered):
            if str(dig(r, "acc")).lower() != "allow":
                continue
            wide = (any_source(dig(r, "src"))
                    and str(dig(r, "dst") or "").strip().lower() in ("*", "any", "")
                    and str(dig(r, "port") or "").strip().lower() in ("*", "any", "", "0-65535"))
            prio = dig(r, "prio")
            def covers(rule, r=r):
                dst_rule = str(dig(rule, "dst") or "").strip().lower()
                dst_here = str(dig(r, "dst") or "").strip().lower()
                port_rule = str(dig(rule, "port") or "").strip().lower()
                port_here = str(dig(r, "port") or "").strip().lower()
                wide_dst = dst_rule in ("*", "any", "")
                if not (wide_dst or (dst_here and dst_rule == dst_here) or cidr_covers(dst_rule, dst_here)):
                    return False
                harmless_port = port_rule in ("*", "any", "")
                if not (harmless_port or (port_here and port_rule == port_here) or port_covers(port_rule, port_here)):
                    return False
                return str(dig(rule, "acc")).lower() == "deny" and any_source(dig(rule, "src"))
            shadow = next((x for x in ordered[:idx_pos] if covers(x)), None)
            if shadow is not None:
                add("info", "nsg-allow-shadowed", nsg, "rule=" + str(dig(r, "rule")) + " priority=" + str(prio) + " shadowedBy=" + str(dig(shadow, "rule")), "a lower-numbered Deny rule already blocks this traffic", sub)
                continue
            if wide and isinstance(prio, int) and prio <= 200:
                add("high", "nsg-low-priority-allow-all", nsg, "rule=" + str(dig(r, "rule")) + " priority=" + str(prio), "a low-numbered rule allows any inbound traffic before the default deny", sub)


@check("sub-storage-immutability")
def c_storage_immut(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.storage/storageaccounts' | project name, subscriptionId, immut=tostring(properties.immutableStorageWithVersioning.enabled), allowBlobPublic=tostring(properties.allowBlobPublicAccess)", ctx["subs"])
    if rows is None:
        note("sub-storage-immutability", 0, denied=1)
        return
    note("sub-storage-immutability", len(rows))
    for r in rows:
        state = tri(dig(r, "immut"))
        s = str(dig(r, "subscriptionId"))
        if state is False:
            add("low", "storage-no-immutability", dig(r, "name"), "immutableStorageWithVersioning=false", "blob versions can be deleted before their retention", s)
    policies = arg_rows("Resources | where type =~ 'microsoft.storage/storageaccounts/blobservices/containers/immutabilitypolicies' | project container=split(id, '/')[12], account=split(id, '/')[8], subscriptionId, state=tostring(properties.immutabilityPeriodSinceCreationInDays), locked=tostring(properties.state)", ctx["subs"])
    if policies is None:
        denied_now("sub-storage-immutability")
        return
    if not policies:
        add("low", "storage-no-container-immutability", "all", "0 container immutability policies", "no container enforces a retention lock")
    for p in policies:
        label = str(dig(p, "account")) + "/" + str(dig(p, "container"))
        ps = str(dig(p, "subscriptionId"))
        if str(val(dig(p, "locked"), "")).lower() != "locked":
            add("medium", "storage-immutability-unlocked", label, "state=" + str(val(dig(p, "locked"), "unset")), "an unlocked policy can be removed by a privileged principal", ps)
        days = num(dig(p, "state"))
        if isinstance(days, int) and 0 < days < 90:
            add("low", "storage-immutability-short", label, "immutabilityPeriodInDays=" + str(days), "the retention lock is shorter than a quarter", ps)


@check("sub-storage-nsp")
def c_storage_nsp(ctx):
    perims = arg_rows("Resources | where type =~ 'microsoft.network/networksecurityperimeters' | project name, subscriptionId, id=tolower(id)", ctx["subs"])
    if perims is None:
        note("sub-storage-nsp", 0, denied=1)
        return
    note("sub-storage-nsp", len(perims))
    assoc = arg_rows("Resources | where type =~ 'microsoft.network/networksecurityperimeterassociations' | project name, subscriptionId, perimeter=tolower(tostring(properties.networkSecurityPerimeter.id)), resource=tolower(tostring(properties.privateLinkResourceId))", ctx["subs"])
    assoc_ok = assoc is not None
    if not assoc_ok:
        denied_now("sub-storage-nsp")
    assoc = lst(assoc)
    linked = {str(dig(a, "resource")) for a in assoc}
    vaults = unread(arg_rows("Resources | where type in~ ('microsoft.storage/storageaccounts','microsoft.keyvault/vaults') | project name, type, subscriptionId, id=tolower(id)", ctx["subs"]),
                    "perimeter-covered resource inventory", "nsp-inventory-unreadable")
    if vaults is None:
        return
    if not assoc_ok:
        add("low", "nsp-associations-unreadable", "all", "resources=" + str(len(vaults)) + " associations unreadable", "perimeter coverage cannot be confirmed")
        return
    for v in vaults:
        if dig(v, "id") not in linked:
            add("info", "nsp-not-covering", dig(v, "name"), "type=" + str(dig(v, "type")).split("/")[-1], "resource is outside every network security perimeter", str(dig(v, "subscriptionId")))


@check("sub-sql-db-audit")
def c_sql_db_audit(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.sql/servers/databases' | where name != 'master' | project name, type, subscriptionId, id", ctx["subs"])
    if rows is None:
        note("sub-sql-db-audit", 0, denied=1)
        return
    note("sub-sql-db-audit", min(len(rows), 20))
    sample("sub-sql-db-audit", min(len(rows), 20), len(rows), "databases")
    for r in rows[:20]:
        url = ARM_BASE + str(dig(r, "id")) + "/auditingSettings/default?api-version=2021-11-01"
        LAST_QUERY[CURRENT["check"]] = "az rest --url " + repr(url)
        doc = arm(url)
        if doc is None:
            denied_now("sub-sql-db-audit")
            continue
        props = dig(doc, "properties", {})
        if str(dig(props, "state")) != "Enabled":
            add("medium", "sql-db-audit-off", dig(r, "name"), "database auditing disabled", "no per-database query audit trail", str(dig(r, "subscriptionId")))
        else:
            dest = "blob" if dig(props, "storageEndpoint") else ("eventhub" if dig(props, "eventHubEndpointName") else ("workspace" if dig(props, "isAzureMonitorTargetEnabled") else "none"))
            add("info", "sql-db-audit", dig(r, "name"), "destination=" + dest + " retention=" + str(dig(props, "retentionDays")), "per-database audit destination", str(dig(r, "subscriptionId")))


@check("sub-appservice-certificate")
def c_web_cert(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.web/certificates' | project name, subscriptionId, expiry=tostring(properties.expirationDate), thumb=tostring(properties.thumbprint)", ctx["subs"])
    if rows is None:
        note("sub-appservice-certificate", 0, denied=1)
        return
    note("sub-appservice-certificate", len(rows))
    for r in rows:
        expiry = str(val(dig(r, "expiry"), ""))
        if not expiry:
            add("low", "certificate-expiry-unknown", dig(r, "name"), "expirationDate not returned", "expiry cannot be confirmed", str(dig(r, "subscriptionId")))
        elif _expired(expiry) is None:
            add("low", "certificate-expiry-unreadable", dig(r, "name"), "expirationDate=" + expiry, "the expiration date could not be parsed; expiry is unknown", str(dig(r, "subscriptionId")))
        elif _expired(expiry):
            add("high", "certificate-expired", dig(r, "name"), "expirationDate=" + expiry, "an expired certificate is still deployed", str(dig(r, "subscriptionId")))


@check("sub-backup-rsv-posture")
def c_rsv(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.recoveryservices/vaults' | project name, subscriptionId, soft=tostring(properties.securitySettings.softDeleteSettings.softDeleteState), enhanced=tostring(properties.securitySettings.softDeleteSettings.enhancedSecurityState), immut=tostring(properties.securitySettings.immutabilitySettings.state)", ctx["subs"])
    if rows is None:
        note("sub-backup-rsv-posture", 0, denied=1)
        return
    note("sub-backup-rsv-posture", len(rows))
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        soft_state = on_off(dig(r, "soft"))
        if soft_state == "off":
            add("medium", "rsv-softdelete-off", dig(r, "name"), "softDeleteState=" + str(dig(r, "soft")), "deleted backups cannot be recovered", s)
        elif soft_state == "unknown":
            add("low", "rsv-softdelete-unknown", dig(r, "name"), "softDeleteState=" + str(val(dig(r, "soft"), "not returned")), "recovery posture cannot be confirmed", s)
        immut = immutability(dig(r, "immut"))
        if immut == "off":
            add("medium", "rsv-immutability-off", dig(r, "name"), "immutabilityState=" + str(dig(r, "immut")), "backup data can be altered by a privileged principal", s)
        elif immut == "unknown":
            add("low", "rsv-immutability-unknown", dig(r, "name"), "immutabilityState=" + (str(val(dig(r, "immut"), "")) or "not returned"), "immutability cannot be confirmed", s)
        enhanced = on_off(dig(r, "enhanced"))
        if enhanced == "off":
            add("low", "rsv-enhanced-softdelete-off", dig(r, "name"), "enhancedSecurityState=" + str(dig(r, "enhanced")), "soft delete cannot be extended or made irreversible", s)
        elif enhanced == "unknown":
            add("low", "rsv-enhanced-softdelete-unknown", dig(r, "name"), "enhancedSecurityState=" + (str(val(dig(r, "enhanced"), "")) or "not returned"), "enhanced soft delete cannot be confirmed", s)


@check("sub-defender-securescore")
def c_securescore(ctx):
    scores = arg_rows("Resources | where type =~ 'microsoft.security/securescores' | project name, subscriptionId, current=todouble(properties.score.current), max=todouble(properties.score.max)", ctx["subs"])
    if scores is None:
        note("sub-defender-securescore", 0, denied=1)
        return
    note("sub-defender-securescore", len(scores))
    for r in scores:
        cur, mx = dig(r, "current"), dig(r, "max")
        if not isinstance(cur, (int, float)) or not isinstance(mx, (int, float)) or not mx:
            add("low", "secure-score-unparsed", dig(r, "subscriptionId"), "score fields absent", "secure score cannot be computed")
            continue
        pct = cur / mx * 100.0
        add("medium" if pct < 50 else "info", "defender-secure-score", dig(r, "subscriptionId"), "score=%.1f%% (%.1f/%.1f)" % (pct, cur, mx), "secure score below half of the maximum" if pct < 50 else "secure score")
    stds = unread(arg_rows("Resources | where type =~ 'microsoft.security/regulatorycompliancestandards' | summarize n=count() by subscriptionId", ctx["subs"]),
                  "regulatory compliance standards", "compliance-standards-unreadable")
    if stds is not None:
        have = {str(dig(x, "subscriptionId")) for x in stds}
        for s in ctx["subs"]:
            if s not in have:
                add("low", "no-regulatory-standard", s, "0 regulatory compliance standards", "no compliance baseline is tracked")


@check("sub-vm-host-encryption")
def c_vm_host(ctx):
    if not ctx["include_vms"]:
        note("sub-vm-host-encryption", 0)
        add("info", "vm-host-encryption-excluded", "all", "VM internals excluded", "run with --include-vms to assess host encryption")
        return
    rows = arg_rows("Resources | where type =~ 'microsoft.compute/virtualmachines' | project name, subscriptionId, hostEnc=tostring(properties.securityProfile.encryptionAtHost)", ctx["subs"])
    if rows is None:
        note("sub-vm-host-encryption", 0, denied=1)
        return
    note("sub-vm-host-encryption", len(rows))
    for r in rows:
        if tri(dig(r, "hostEnc")) is False:
            add("medium", "vm-encryption-at-host-off", dig(r, "name"), "encryptionAtHost=false", "guest OS temp disks are not encrypted at the host", str(dig(r, "subscriptionId")))
@check("sub-kv-object-expiry")
def c_kv_objects_expiry(ctx):
    keys = arg_rows("Resources | where type =~ 'microsoft.keyvault/vaults/keys' | project vault=split(id, '/')[8], name, subscriptionId, exp=todouble(properties.attributes.exp), enabled=tostring(properties.attributes.enabled), keyType=tostring(properties.kty), rot=tostring(properties.rotationPolicy.lifetimeActions)", ctx["subs"])
    if keys is None:
        note("sub-kv-object-expiry", 0, denied=1)
        return
    certs = unread(arg_rows("Resources | where type =~ 'microsoft.keyvault/vaults/certificates' | project vault=split(id, '/')[8], name, subscriptionId, exp=todouble(properties.attributes.exp), enabled=tostring(properties.attributes.enabled)", ctx["subs"]),
                   "key vault certificates", "kv-certificates-unreadable")
    cert_objects = []
    if certs is not None:
        cert_objects = certs
    note("sub-kv-object-expiry", len(keys) + len(cert_objects))
    now = time.time()
    for kind, rows in (("key", keys), ("certificate", cert_objects)):
        for r in rows:
            label = str(dig(r, "vault")) + "/" + str(dig(r, "name"))
            exp = dig(r, "exp")
            if tri(dig(r, "enabled")) is False:
                add("low", "kv-object-disabled", label, "kind=" + kind, "object is disabled but still present", str(dig(r, "subscriptionId")))
            if not isinstance(exp, (int, float)):
                add("low", "kv-object-no-expiry", label, "kind=" + kind, "object has no expiry date", str(dig(r, "subscriptionId")))
            elif exp < now:
                add("high", "kv-object-expired", label, "kind=" + kind + " exp=" + time.strftime("%Y-%m-%d", time.gmtime(exp)), "an expired object is still present", str(dig(r, "subscriptionId")))
            elif exp - now < 30 * 86400:
                add("medium", "kv-object-expiring", label, "kind=" + kind + " exp=" + time.strftime("%Y-%m-%d", time.gmtime(exp)), "object expires within 30 days", str(dig(r, "subscriptionId")))
            if kind == "key":
                actions = [a for a in str(val(dig(r, "rot"), "")).split(",") if a.strip() not in ("", "[]", "{}")]
                if not actions:
                    add("medium", "kv-key-no-rotation", label, "rotationPolicy.lifetimeActions=" + str(val(dig(r, "rot"), "[]")), "key is never rotated automatically", str(dig(r, "subscriptionId")))
    add("info", "kv-secrets-not-enumerated", "all", "secrets require the data plane", "secret expiry is not visible through the control plane")


@check("sub-sql-mi-posture")
def c_sql_mi(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.sql/managedinstances' | project name, subscriptionId, rg=resourceGroup, publicData=tostring(properties.publicDataEndpointEnabled), proxy=tostring(properties.proxyOverride), tls=tostring(properties.minimalTlsVersion), zone=tostring(properties.zoneRedundant), pool=tostring(properties.instancePoolId), storage=tostring(properties.storageSizeInGB), kms=tostring(properties.keyId)", ctx["subs"])
    if rows is None:
        note("sub-sql-mi-posture", 0, denied=1)
        return
    note("sub-sql-mi-posture", len(rows))
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        if str(dig(r, "publicData") or "").lower() in ("true", "enabled"):
            add("high", "sql-mi-public-data-endpoint", dig(r, "name"), "publicDataEndpointEnabled=true", "instance data endpoint is reachable from the internet", s)
        tls = str(val(dig(r, "tls"), ""))
        if tls in ("1.0", "1.1"):
            add("medium", "sql-mi-legacy-tls", dig(r, "name"), "minimalTLSVersion=" + tls, "legacy TLS accepted", s)
        elif tls == "":
            add("low", "sql-mi-tls-unknown", dig(r, "name"), "minimalTLSVersion not returned", "transport version cannot be confirmed", s)
        if tri(dig(r, "zone")) is False:
            add("low", "sql-mi-no-zone-redundancy", dig(r, "name"), "zoneRedundant=false", "instance has no zone resilience", s)
        if not dig(r, "kms"):
            add("medium", "sql-mi-platform-key", dig(r, "name"), "keyId absent", "TDE uses a platform-managed key", s)
    admin = arg_rows("Resources | where type =~ 'microsoft.sql/managedinstances/administrators' | project mi=tolower(substring(id, 0, indexof(tolower(id), '/administrators'))), login=tostring(properties.login)", ctx["subs"])
    if admin is None:
        denied_now("sub-sql-mi-posture")
        add("low", "sql-mi-admin-unreadable", "all", "administrator children unreadable", "the Entra administrative path cannot be confirmed")
        return
    have = {str(dig(a, "mi")) for a in admin}
    for r in rows:
        mi_id = ("/subscriptions/" + str(dig(r, "subscriptionId")) + "/resourcegroups/" + str(dig(r, "rg")) + "/providers/microsoft.sql/managedinstances/" + str(dig(r, "name"))).lower()
        if mi_id not in have:
            add("medium", "sql-mi-no-entra-admin", dig(r, "name"), "no managedinstances/administrators child resource", "no Entra administrative path", str(dig(r, "subscriptionId")))


@check("sub-storage-files")
def c_storage_files(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.storage/storageaccounts/fileservices' | project account=split(id, '/')[8], subscriptionId, shareSoft=tostring(properties.shareDeleteRetentionPolicy.enabled), shareDays=toint(properties.shareDeleteRetentionPolicy.days), smb=tostring(properties.protocolSettings.smb.versions), channel=tostring(properties.protocolSettings.smb.channelEncryption), auth=tostring(properties.protocolSettings.smb.authenticationMethods), kerberos=tostring(properties.protocolSettings.smb.kerberosTicketEncryption)", ctx["subs"])
    if rows is None:
        note("sub-storage-files", 0, denied=1)
        return
    note("sub-storage-files", len(rows))
    if not rows:
        add("info", "storage-files-not-indexed", "all", "0 file service child resources", "SMB posture cannot be assessed")
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        account = str(dig(r, "account"))
        if tri(dig(r, "shareSoft")) is not True:
            add("medium", "storage-files-share-softdelete-off", account, "shareDeleteRetentionPolicy.enabled=" + str(dig(r, "shareSoft")), "deleted file shares cannot be recovered", s)
        else:
            share_days = num(dig(r, "shareDays"))
            if isinstance(share_days, int) and share_days < 7:
                add("low", "storage-files-share-retention-short", account, "retentionDays=" + str(share_days), "share recovery window is shorter than a week", s)
        channel = str(dig(r, "channel") or "").lower()
        if channel and channel != "aes-256":
            add("medium", "storage-files-smb-weak-encryption", account, "channelEncryption=" + channel, "SMB channel encryption below AES-256", s)
        auth = str(dig(r, "auth") or "").lower()
        if "ntlmv1" in auth or ("kerberos" not in auth and auth):
            add("medium", "storage-files-weak-smb-auth", account, "authenticationMethods=" + auth, "SMB accepts a legacy authentication method", s)
        versions = str(dig(r, "smb") or "").lower()
        if versions and ("smb2.1" in versions or "smb3.0" in versions):
            add("low", "storage-files-old-smb", account, "versions=" + versions, "older SMB dialects are accepted", s)


@check("entra-deleted-groups-roles")
def c_deleted_groups(ctx):
    deleted = graph_all("directory/deletedItems/microsoft.graph.group?$select=id,displayName,deletedDateTime", limit=5)
    if deleted is None:
        note("entra-deleted-groups-roles", 0, denied=1)
        return
    note("entra-deleted-groups-roles", len(deleted))
    if not deleted:
        return
    ids = {str(dig(g, "id")) for g in deleted}
    assignments = graph_all("roleManagement/directory/roleAssignments", limit=5)
    if assignments is None:
        denied_now("entra-deleted-groups-roles")
        return
    for a in assignments:
        if str(dig(a, "principalId")) in ids:
            add("high", "deleted-group-holds-role", str(dig(a, "principalId")), "role=" + str(dig(a, "roleDefinitionId")), "soft-deleted group still referenced by a role assignment")


@check("entra-standing-global-admin")
def c_standing_ga(ctx):
    defs = graph_all("roleManagement/directory/roleDefinitions", limit=5)
    if defs is None:
        note("entra-standing-global-admin", 0, denied=1)
        return
    ga = {str(dig(d, "id")) for d in defs if str(dig(d, "templateId") or "").lower() == "62e90394-69f5-4237-9190-012177145e10"}
    if not ga:
        note("entra-standing-global-admin", 0, denied=1)
        add("low", "standing-ga-template-unresolved", "tenant", "roleDefinitions=" + str(len(defs)) + " globalAdminTemplates=0", "the Global Administrator role definition is not in the response, so permanent assignments cannot be identified")
        return
    inst = graph_all("roleManagement/directory/roleAssignmentScheduleInstances", limit=5, beta=True)
    if inst is None:
        note("entra-standing-global-admin", 0, denied=1)
        add("info", "standing-ga-unreadable", "tenant", "schedule instances unavailable", "permanent Global Administrator holds cannot be listed")
        return
    standing = [i for i in inst if str(dig(i, "roleDefinitionId")) in ga and str(dig(i, "assignmentType")) == "Assigned"]
    note("entra-standing-global-admin", len(inst))
    for i in standing:
        add("high", "standing-global-administrator", str(dig(i, "principalId")), "assignmentType=Assigned end=" + str(dig(i, "endDateTime")), "Global Administrator is permanently assigned, with no activation gate")
    if not standing:
        add("info", "no-standing-global-administrator", "tenant", "instances=" + str(len(inst)), "no permanently assigned Global Administrator in the schedule view")


@check("entra-managed-devices")
def c_managed_devices(ctx):
    rows = graph_all("deviceManagement/managedDevices?$select=id,deviceName,isEncrypted,jailBroken,managedDeviceOwnerType,complianceState,operatingSystem,lastSyncDateTime", limit=10, beta=True)
    if rows is None:
        note("entra-managed-devices", 0, denied=1)
        return
    note("entra-managed-devices", len(rows))
    if not rows:
        add("info", "no-managed-devices", "tenant", "0 devices", "no Intune-managed device inventory")
        return
    for d in rows:
        name = str(dig(d, "deviceName"))
        if dig(d, "isEncrypted") is False:
            add("medium", "device-not-encrypted", name, "os=" + str(dig(d, "operatingSystem")) + " compliance=" + str(dig(d, "complianceState")), "managed device stores data unencrypted")
        if str(dig(d, "jailBroken") or "").lower() not in ("", "unknown", "false"):
            add("high", "device-jailbroken", name, "jailBroken=" + str(dig(d, "jailBroken")), "managed device is rooted or jailbroken")
        if str(dig(d, "complianceState") or "").lower() in ("noncompliant", "error", "conflict"):
            add("medium", "device-noncompliant", name, "complianceState=" + str(dig(d, "complianceState")), "managed device does not meet policy")


@check("entra-security-alerts")
def c_security_alerts(ctx):
    rows = graph_all("security/alerts_v2?$top=100", limit=5)
    if rows is None:
        note("entra-security-alerts", 0, denied=1)
        return
    note("entra-security-alerts", len(rows))
    open_states = ("new", "inprogress", "in progress")
    for a in rows:
        if str(dig(a, "status") or "").lower() in open_states:
            sev = "high" if str(dig(a, "severity") or "").lower() in ("high", "critical") else "medium"
            add(sev, "open-security-alert", str(dig(a, "title"))[:60], "severity=" + str(dig(a, "severity")) + " status=" + str(dig(a, "status")) + " created=" + str(dig(a, "createdDateTime")), "Defender XDR alert is not resolved")


@check("entra-sp-creation-policy")
def c_sp_creation(ctx):
    doc = graph("policies/servicePrincipalCreationPolicies", beta=True)
    if doc is None:
        note("entra-sp-creation-policy", 0, denied=1)
        return
    items = lst(dig(doc, "value"))
    note("entra-sp-creation-policy", len(items))
    if not items:
        add("medium", "sp-creation-unrestricted", "tenant", "0 service principal creation policies", "any non-admin can register a service principal")
        return
    for p in items:
        if dig(p, "isEnabled") is False:
            add("medium", "sp-creation-policy-disabled", dig(p, "displayName"), "isEnabled=false", "the restriction exists but is not enforced")


@check("entra-external-id-policy")
def c_external_id_policy(ctx):
    doc = graph("policies/externalIdentitiesPolicy", beta=True)
    if doc is None:
        note("entra-external-id-policy", 0, denied=1)
        return
    note("entra-external-id-policy", 1)
    block_b2b = dig(doc, "allowExternalIdentitiesToLeave")
    delete_b2b = dig(doc, "allowDeletedIdentitiesDataRemoval")
    if block_b2b is True:
        add("medium", "guests-can-self-remove", "tenant", "allowExternalIdentitiesToLeave=true", "users can remove their own guest account and its data")
    if delete_b2b is True:
        add("low", "guest-data-removal-allowed", "tenant", "allowDeletedIdentitiesDataRemoval=true", "deleted guest data is purged without review")


@check("entra-b2x-userflows")
def c_b2x(ctx):
    rows = graph_all("identity/b2xUserFlows", limit=5, beta=True)
    if rows is None:
        note("entra-b2x-userflows", 0, denied=1)
        return
    note("entra-b2x-userflows", len(rows))
    for f in rows:
        name = str(dig(f, "displayName"))
        for side in ("apiConnectorConfiguration.postFederationSignup.identityProvider", "apiConnectorConfiguration.postAttributeCollection.identityProvider"):
            connector = dig(f, side)
            if connector:
                add("medium", "b2x-api-connector", name, "connector=" + str(dig(connector, "displayName")), "an external API connector runs during sign-up and holds its own credential")


@check("entra-consent-workflow-depth")
def c_consent_depth(ctx):
    pol = graph("policies/adminConsentRequestPolicy")
    if pol is None:
        note("entra-consent-workflow-depth", 0, denied=1)
        return
    note("entra-consent-workflow-depth", 1)
    if dig(pol, "isEnabled") is not True:
        add("high", "admin-consent-workflow-off", "tenant", "isEnabled=false", "users cannot request consent; they either cannot work or an admin grants broadly")
        return
    reviewers = lst(dig(pol, "reviewers"))
    duration = dig(pol, "requestDurationInDays")
    if not reviewers:
        add("medium", "admin-consent-no-reviewer", "tenant", "reviewers=0", "requests go to nobody")
    if isinstance(duration, int) and duration > 7:
        add("low", "admin-consent-long-window", "tenant", "requestDurationInDays=" + str(duration), "requests stay open for over a week")


@check("entra-credential-near-expiry")
def c_cred_near(ctx):
    sps = graph_all("servicePrincipals?$select=id,displayName,passwordCredentials,keyCredentials", limit=10)
    if sps is None:
        note("entra-credential-near-expiry", 0, denied=1)
        return
    note("entra-credential-near-expiry", len(sps))
    now = time.time()
    for sp in sps:
        for kind in ("passwordCredentials", "keyCredentials"):
            for cred in lst(dig(sp, kind)):
                end = str(dig(cred, "endDateTime") or "")
                if not end:
                    continue
                stamp = _stamp(end)
                if stamp is None:
                    add("low", "sp-credential-unparsed-expiry", dig(sp, "displayName"), kind + " end=" + end, "expiry cannot be read")
                    continue
                days = int((stamp - now) // 86400)
                if stamp < now:
                    add("high", "sp-credential-expired", dig(sp, "displayName"), kind + " end=" + end + " expiredDays=" + str(abs(days)), "the credential has expired; authentication with it now fails")
                elif 0 <= days <= 30:
                    add("high", "sp-credential-expiring-30d", dig(sp, "displayName"), kind + " end=" + end + " days=" + str(days), "credential expires inside a month; expect an outage or a rushed rotation")
                elif 30 < days <= 90:
                    add("low", "sp-credential-expiring-90d", dig(sp, "displayName"), kind + " end=" + end + " days=" + str(days), "credential expires inside a quarter")


@check("entra-sso-modes")
def c_sso_modes(ctx):
    rows = graph_all("servicePrincipals?$select=id,displayName,preferredSingleSignOnMode,loginUrl,notificationEmailAddresses", limit=10)
    if rows is None:
        note("entra-sso-modes", 0, denied=1)
        return
    note("entra-sso-modes", len(rows))
    counts = Counter()
    for sp in rows:
        mode = str(dig(sp, "preferredSingleSignOnMode") or "").lower()
        if not mode:
            continue
        counts[mode] += 1
        if mode in ("password", "headerbased", "linked"):
            add("medium", "password-based-sso", dig(sp, "displayName"), "mode=" + mode, "credentials are stored by the platform and replayed to the application")
        if mode == "wsfed" and not lst(dig(sp, "notificationEmailAddresses")):
            add("low", "wsfed-no-cert-contact", dig(sp, "displayName"), "notificationEmailAddresses empty", "signing certificate expiry has no recipient")
    if counts:
        add("info", "sso-mode-inventory", "tenant", ",".join(k + "=" + str(v) for k, v in counts.items()), "single sign-on mode distribution")


@check("entra-group-members-guest")
def c_group_members(ctx):
    assignments = graph_all("roleManagement/directory/roleAssignments", limit=5)
    if assignments is None:
        note("entra-group-members-guest", 0, denied=1)
        return
    note("entra-group-members-guest", len(assignments))
    principals = {str(dig(a, "principalId")) for a in assignments}
    if not principals:
        return
    groups = graph_all("groups?$select=id", limit=10)
    if groups is None:
        denied_now("entra-group-members-guest")
        return
    group_ids = principals & {str(dig(g, "id")) for g in groups}
    if not group_ids:
        add("info", "no-role-holding-groups", "tenant", "roleAssignments=" + str(len(assignments)) + " groupPrincipals=0", "no directory role is granted through a group")
        return
    guests = set(scan_guests(ctx) or set())
    trunc("entra-group-members-guest", len(list(group_ids)[:15]), len(group_ids), "role-holding groups")
    for gid in list(group_ids)[:15]:
        doc = graph("groups/" + gid + "/members?$select=id,displayName,userType", beta=True)
        if doc is None:
            denied_now("entra-group-members-guest")
            continue
        members = lst(dig(doc, "value"))
        guest_members = [m for m in members if str(dig(m, "userType") or "").lower() == "guest" or str(dig(m, "id")) in guests]
        if guest_members:
            add("high", "guest-member-of-role-group", gid, "guests=" + str(len(guest_members)) + " members=" + str(len(members)), "a guest inherits the directory role held by this group")


@check("sub-appinsights-keys")
def c_appinsights(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.insights/components' | project name, subscriptionId, publicIngest=tostring(properties.publicNetworkAccessForIngestion), publicQuery=tostring(properties.publicNetworkAccessForQuery), localAuth=tostring(properties.DisableLocalAuth), retention=tostring(properties.retentionInDays)", ctx["subs"])
    if rows is None:
        note("sub-appinsights-keys", 0, denied=1)
        return
    note("sub-appinsights-keys", len(rows))
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        name = str(dig(r, "name"))
        local_off = on_off(dig(r, "localAuth"))
        if local_off == "off":
            add("medium", "appinsights-local-auth", name, "DisableLocalAuth=" + str(dig(r, "localAuth")), "instrumentation keys allow unauthenticated log injection", s)
        elif local_off == "unknown":
            add("low", "appinsights-local-auth-unknown", name, "DisableLocalAuth not returned", "the platform default allows local auth; confirm the actual setting", s)
        if str(val(dig(r, "publicIngest"), "")).lower() == "enabled":
            add("low", "appinsights-public-ingest", name, "publicNetworkAccessForIngestion=Enabled", "telemetry ingestion accepts traffic from any network", s)
        days = num(dig(r, "retention"))
        if isinstance(days, int) and days < 90:
            add("low", "appinsights-short-retention", name, "retentionInDays=" + str(days), "telemetry expires sooner than a quarter", s)


@check("sub-datafactory-auth")
def c_adf(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.datafactory/factories/linkedservices' | project name, subscriptionId, factory=split(id, '/')[8], kind=tostring(properties.type), props=properties.typeProperties", ctx["subs"])
    if rows is None:
        note("sub-datafactory-auth", 0, denied=1)
        return
    note("sub-datafactory-auth", len(rows))
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        label = str(dig(r, "factory")) + "/" + str(dig(r, "name"))
        kind = str(dig(r, "kind") or "")
        blob = str(dig(r, "props"))
        referenced = "azurekeyvault" in blob.lower() or "secretname" in blob.lower()
        if referenced:
            add("info", "adf-linked-service-keyvault-ref", label, "kind=" + kind, "the credential is referenced from Key Vault, not stored inline", s)
            continue
        if "connectionstring" in blob.lower() or "accountkey" in blob.lower():
            add("medium", "adf-linked-service-key", label, "kind=" + kind, "linked service stores a key or connection string instead of a managed identity", s)
        if "password" in blob.lower() or "secret" in blob.lower():
            add("medium", "adf-linked-service-secret", label, "kind=" + kind, "linked service holds a stored credential", s)


@check("sub-datacollection")
def c_dcr(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.insights/datacollectionrules' | project name, subscriptionId, ident=tostring(identity.type), kind=tostring(properties.dataSources)", ctx["subs"])
    if rows is None:
        note("sub-datacollection", 0, denied=1)
        return
    note("sub-datacollection", len(rows))
    for r in rows:
        name = str(dig(r, "name"))
        if not dig(r, "ident"):
            add("low", "dcr-no-identity", name, "identity.type=none", "the rule writes to a workspace without its own identity", str(dig(r, "subscriptionId")))
        if "syslog" in str(dig(r, "kind")).lower():
            add("info", "dcr-syslog", name, "agent-based ingestion", "syslog collection widens the log injection surface", str(dig(r, "subscriptionId")))


@check("sub-security-settings")
def c_security_settings(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.security/settings' | project name, subscriptionId, enabled=tostring(properties.enabled)", ctx["subs"])
    if rows is None:
        note("sub-security-settings", 0, denied=1)
        return
    note("sub-security-settings", len(rows))
    seen = {str(dig(r, "name")).lower() for r in rows}
    for required in ("wdatp", "mcas", "sentinel"):
        if required not in seen:
            add("low", "security-setting-absent", required, "0 settings named " + required, "the integration is not configured for this subscription")
    for r in rows:
        if tri(dig(r, "enabled")) is False:
            add("medium", "security-setting-disabled", dig(r, "name"), "enabled=false", "integration is present but switched off", str(dig(r, "subscriptionId")))


@check("sub-policy-dine-identity")
def c_dine(ctx):
    rows = arg_rows("PolicyResources | where type =~ 'microsoft.authorization/policyassignments' | where tostring(identity.type) == 'SystemAssigned' | project name, subscriptionId, scope=tostring(properties.scope), def=tostring(properties.policyDefinitionId)", ctx["subs"])
    if rows is None:
        note("sub-policy-dine-identity", 0, denied=1)
        return
    note("sub-policy-dine-identity", len(rows))
    if not rows:
        return
    assignments = unread(arg_rows("AuthorizationResources | where type =~ 'microsoft.authorization/roleassignments' | where tostring(properties.principalType) == 'ServicePrincipal' | project principalId=tostring(properties.principalId), roleId=tostring(properties.roleDefinitionId), scope=tostring(properties.scope)", ctx["subs"]),
                         "role assignments held by service principals", "dine-identity-assignments-unreadable")
    if assignments is None:
        return
    owner_grants = [a for a in assignments if str(dig(a, "roleId")).lower().endswith(BUILTIN_ROLE_OWNER) or str(dig(a, "roleId")).lower().endswith(BUILTIN_ROLE_UAA)]
    owners = {str(dig(a, "principalId")) for a in owner_grants}
    add("info", "policy-managed-identity-inventory", "all", "assignmentsWithIdentity=" + str(len(rows)) + " ownerPrincipals=" + str(len(owners)), "managed identities used by policy assignments", "tenant")
    for a in owner_grants:
        add("high", "policy-identity-holds-owner", str(dig(a, "principalId")), "role=" + str(dig(a, "roleId")).split("/")[-1] + " scope=" + str(dig(a, "scope")), "a policy deployment identity can grant access to any principal at this scope", ctx_sub(a), str(dig(a, "scope")))


@check("sub-orphaned-scopes")
def c_orphan_scopes(ctx):
    rows = arg_rows("AuthorizationResources | where type =~ 'microsoft.authorization/roleassignments' | extend scope=tolower(tostring(properties.scope)) | where scope startswith '/subscriptions/' | where subscriptionId in (" + subq(ctx["subs"]) + ") | project principalId=tostring(properties.principalId), roleId=tostring(properties.roleDefinitionId), scope, subscriptionId", ctx["subs"], scoped=False)
    if rows is None:
        note("sub-orphaned-scopes", 0, denied=1)
        return
    note("sub-orphaned-scopes", len(rows))
    before = len(TRUNCATED)
    ids = arg_rows("Resources | project id=tolower(id)", ctx["subs"])
    if ids is None:
        denied_now("sub-orphaned-scopes")
        return
    if len(TRUNCATED) > before:
        note("sub-orphaned-scopes", len(rows), denied=1)
        add("low", "orphan-scope-check-truncated", "all", "resource id list capped at 10000 rows", "orphan detection is unreliable on tenants this large")
        return
    groups = arg_rows("ResourceContainers | where type =~ 'microsoft.resources/resourcegroups' | where subscriptionId in (" + subq(ctx["subs"]) + ") | project id=tolower(id)", ctx["subs"], scoped=False)
    if groups is None:
        denied_now("sub-orphaned-scopes")
        return
    known = {str(dig(i, "id")) for i in ids} | {str(dig(g, "id")) for g in groups}
    for r in rows:
        scope = str(dig(r, "scope"))
        if scope.count("/") <= 2:
            continue
        if scope not in known and "/resourcegroups/" in scope:
            add("medium", "role-assignment-orphaned-scope", scope.split("/")[-1], "principal=" + str(dig(r, "principalId")) + " role=" + str(dig(r, "roleId")).split("/")[-1], "assignment points at a resource that no longer exists", str(dig(r, "subscriptionId")))


@check("sub-kv-rbac-assignments")
def c_kv_rbac(ctx):
    vaults = arg_rows("Resources | where type =~ 'microsoft.keyvault/vaults' | project name, subscriptionId, id=tolower(id)", ctx["subs"])
    if vaults is None:
        note("sub-kv-rbac-assignments", 0, denied=1)
        return
    note("sub-kv-rbac-assignments", len(vaults))
    assignments = unread(arg_rows("AuthorizationResources | where type =~ 'microsoft.authorization/roleassignments' | where subscriptionId in (" + subq(ctx["subs"]) + ") | extend scope=tolower(tostring(properties.scope)) | where scope contains '/microsoft.keyvault/vaults/' | project principalId=tostring(properties.principalId), roleId=tostring(properties.roleDefinitionId), scope, subscriptionId", ctx["subs"], scoped=False),
                         "vault-scoped role assignments", "kv-rbac-assignments-unreadable")
    if assignments is None:
        return
    for a in assignments:
        add("info", "vault-scoped-role", str(dig(a, "scope")).split("/")[-1], "principal=" + str(dig(a, "principalId")) + " role=" + str(dig(a, "roleId")).split("/")[-1], "vault-scoped RBAC grant; verify it is narrower than vault-wide", str(dig(a, "subscriptionId")))


@check("sub-storage-queue-table")
def c_queue_table(ctx):
    q = "Resources | where type in~ ('microsoft.storage/storageaccounts/queueservices','microsoft.storage/storageaccounts/tableservices') | project account=split(id, '/')[8], type, subscriptionId, cors=properties.cors.corsRules"
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-storage-queue-table", 0, denied=1)
        return
    note("sub-storage-queue-table", len(rows))
    if not rows:
        add("info", "queue-table-not-indexed", "all", "0 queue or table service rows", "queue and table posture cannot be assessed")
    for r in rows:
        for rule in lst(dig(r, "cors")):
            origins = [str(o) for o in lst(dig(rule, "allowedOrigins"))]
            if "*" in origins:
                add("medium", "storage-queue-table-cors-any", str(dig(r, "account")), "service=" + str(dig(r, "type")).split("/")[-1] + " origins=" + ",".join(origins), "any browser origin can call the service", str(dig(r, "subscriptionId")))


@check("sub-aks-admin-group")
def c_aks_admin_group(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.containerservice/managedclusters' | project name, subscriptionId, groups=properties.aadProfile.adminGroupObjectIDs, aad=tostring(properties.aadProfile)", ctx["subs"])
    if rows is None:
        note("sub-aks-admin-group", 0, denied=1)
        return
    note("sub-aks-admin-group", len(rows))
    for r in rows:
        groups = lst(dig(r, "groups"))
        if groups:
            add("medium", "aks-cluster-admin-group", str(dig(r, "name")), "adminGroupObjectIDs=" + str(len(groups)), "members of these groups bypass Kubernetes RBAC", str(dig(r, "subscriptionId")))
        elif not dig(r, "aad"):
            add("high", "aks-local-admin-only", str(dig(r, "name")), "aadProfile absent", "cluster admin comes from a local certificate", str(dig(r, "subscriptionId")))


@check("sub-container-apps")
def c_containerapps(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.app/containerapps' | project name, subscriptionId, external=tostring(properties.configuration.ingress.external), allowInsecure=tostring(properties.configuration.ingress.allowInsecure), secrets=properties.configuration.secrets, ident=tostring(identity.type)", ctx["subs"])
    if rows is None:
        note("sub-container-apps", 0, denied=1)
        return
    note("sub-container-apps", len(rows))
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        name = str(dig(r, "name"))
        if str(val(dig(r, "external"), "")).lower() == "true" and str(val(dig(r, "allowInsecure"), "")).lower() == "true":
            add("medium", "containerapp-http-ingress", name, "external=true allowInsecure=true", "plaintext ingress from the internet", s)
        if lst(dig(r, "secrets")):
            add("low", "containerapp-static-secret", name, "secrets=" + str(len(lst(dig(r, "secrets")))), "container app stores credentials instead of using its identity", s)


@check("sub-single-server-db")
def c_single_db(ctx):
    rows = arg_rows("Resources | where type in~ ('microsoft.dbforpostgresql/servers','microsoft.dbformysql/servers') | project name, type, subscriptionId, ssl=tostring(properties.sslEnforcement), publicNet=tostring(properties.publicNetworkAccess), tls=tostring(properties.minimalTlsVersion)", ctx["subs"])
    if rows is None:
        note("sub-single-server-db", 0, denied=1)
        return
    note("sub-single-server-db", len(rows))
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        engine = str(dig(r, "type")).split("/")[0].replace("microsoft.", "")
        if str(val(dig(r, "ssl"), "")).lower() == "disabled":
            add("high", "db-ssl-disabled", str(dig(r, "name")), "engine=" + engine + " sslEnforcement=Disabled", "connections are not encrypted", s)
        if str(val(dig(r, "publicNet"), "")).lower() in ("enabled", "0.0.0.0"):
            add("medium", "db-public-network", str(dig(r, "name")), "engine=" + engine + " publicNetworkAccess=Enabled", "database is reachable from the internet", s)
        tls = str(val(dig(r, "tls"), ""))
        if tls in ("TLS1_0", "TLS1_1", "1.0", "1.1"):
            add("medium", "db-legacy-tls", str(dig(r, "name")), "engine=" + engine + " minimalTlsVersion=" + tls, "legacy TLS accepted", s)


@check("sub-rg-locks")
def c_rg_locks(ctx):
    groups = arg_rows("ResourceContainers | where type =~ 'microsoft.resources/resourcegroups' | where subscriptionId in (" + subq(ctx["subs"]) + ") | project name, subscriptionId, id=tolower(id)", ctx["subs"], scoped=False)
    if groups is None:
        note("sub-rg-locks", 0, denied=1)
        return
    note("sub-rg-locks", len(groups))
    lock_rows = arg_rows("Resources | where type =~ 'microsoft.authorization/locks' | project scope=tolower(tostring(properties.scope))", ctx["subs"])
    if lock_rows is None:
        denied_now("sub-rg-locks")
        return
    locked = {str(dig(l, "scope")) for l in lock_rows}
    for g in groups:
        gid = str(dig(g, "id"))
        sub_scope = "/subscriptions/" + str(dig(g, "subscriptionId"))
        if gid in locked or sub_scope in locked:
            continue
        add("low", "resourcegroup-unlocked", str(dig(g, "name")), "no lock at group or subscription scope", "nothing prevents accidental deletion of the whole group", str(dig(g, "subscriptionId")))


@check("entra-gdap")
def c_gdap(ctx):
    rels = graph_all("directory/delegatedAdminRelationships", limit=5, beta=True)
    if rels is None:
        note("entra-gdap", 0, denied=1)
        return
    note("entra-gdap", len(rels))
    add("info", "gdap-inbound-not-readable", "tenant", "endpoint lists relationships where this tenant is the managing partner", "inbound partner access to this tenant is not exposed by this API; confirm it in the partner portal")
    if not rels:
        add("info", "no-gdap-relationships", "tenant", "0 outbound relationships", "this tenant does not administer a customer tenant through GDAP")
        return
    for r in rels:
        active = str(dig(r, "status") or "").lower()
        roles = lst(dig(r, "accessDetails.unifiedRoles"))
        customer_id = str(val(dig(r, "customer.tenantId"), ""))
        customer = str(val(dig(r, "customer.displayName"), "")) or tenant_name(customer_id) or customer_id or "unknown"
        add("high" if active == "active" else "medium", "gdap-outbound-relationship", str(dig(r, "displayName")), "status=" + active + " customer=" + customer + " duration=" + str(dig(r, "duration")) + " roles=" + str(len(roles)), "identities in this tenant hold delegated administrative access to a customer tenant")


@check("entra-cross-tenant-access")
def c_xtp(ctx):
    pol = graph("policies/crossTenantAccessPolicy/partners", beta=True)
    if pol is None:
        note("entra-cross-tenant-access", 0, denied=1)
        return
    partners = lst(dig(pol, "value"))
    note("entra-cross-tenant-access", len(partners))
    for p in partners:
        name = str(val(dig(p, "tenantId"), "?"))
        inbound = dig(p, "b2bCollaborationInbound")
        outbound = dig(p, "b2bCollaborationOutbound")
        ia = str(val(dig(inbound, "usersAndGroups.accessType"), "unknown"))
        oa = str(val(dig(outbound, "usersAndGroups.accessType"), "unknown"))
        if ia.lower() == "allowed":
            add("low", "xtenant-inbound-open", name, "b2bCollaborationInbound=" + ia, "guests from this partner are admitted without restriction")
        if oa.lower() == "allowed":
            add("low", "xtenant-outbound-open", name, "b2bCollaborationOutbound=" + oa, "users may be invited into the partner tenant")
        trust = dig(p, "automaticUserConsentSettings.inboundAllowed")
        if trust is True:
            add("high", "xtenant-inbound-trust", name, "automaticUserConsentSettings.inboundAllowed=true", "users from this tenant are trusted without MFA prompts or consent")


@check("entra-terms-of-use")
def c_tou(ctx):
    docs = graph_all("identityGovernance/termsOfUse/agreements", limit=5)
    accept = graph_all("identityGovernance/termsOfUse/agreementAcceptances", limit=5)
    if docs is None:
        note("entra-terms-of-use", 0, denied=1)
        return
    note("entra-terms-of-use", len(docs))
    per_agreement = Counter(str(dig(a, "agreementId")) for a in (accept if accept is not None else []))
    for d in docs:
        if dig(d, "isViewingBeforeAcceptanceRequired") is False:
            add("low", "tou-not-gated", str(dig(d, "displayName")), "isViewingBeforeAcceptanceRequired=false", "the agreement is not required before access")
        add("info", "tou-agreement", str(dig(d, "displayName")), "acceptances=" + str(per_agreement.get(str(dig(d, "id")), 0)) + (" totalUnreadable" if accept is None else ""), "terms of use inventory")


@check("entra-method-targeting")
def c_method_targets(ctx):
    pol = graph("policies/authenticationMethodsPolicy")
    if pol is None:
        note("entra-method-targeting", 0, denied=1)
        return
    configs = lst(dig(pol, "authenticationMethodConfigurations"))
    note("entra-method-targeting", len(configs))
    weak = ("Sms", "Voice", "Email", "TemporaryAccessPass")
    for cfg in configs:
        if str(dig(cfg, "id")) not in weak:
            continue
        state = str(dig(cfg, "state") or "")
        targets = lst(dig(cfg, "includeTargets"))
        excluded = lst(dig(cfg, "excludeTargets"))
        if state.lower() == "enabled":
            scope = [str(val(dig(t, "id"), "?")) for t in targets]
            add("medium", "weak-method-enabled", str(dig(cfg, "id")), "state=enabled targets=" + ",".join(scope)[:60] + " excluded=" + str(len(excluded)), "a non-phishing-resistant method is available for authentication")
        if str(dig(cfg, "id")) == "TemporaryAccessPass":
            life = num(dig(cfg, "defaultLifetimeInMinutes"))
            if life is MISSING:
                life = num(dig(cfg, "codeConfiguration.defaultLifetimeInMinutes"))
            if isinstance(life, int) and life > 60:
                add("medium", "tap-long-lifetime", "TemporaryAccessPass", "defaultLifetimeInMinutes=" + str(life), "a temporary pass outlives the onboarding window")


@check("entra-idle-timeout")
def c_idle_timeout(ctx):
    rows = graph_all("policies/activityBasedTimeoutPolicies", limit=5)
    if rows is None:
        note("entra-idle-timeout", 0, denied=1)
        return
    note("entra-idle-timeout", len(rows))
    if not rows:
        add("medium", "no-idle-timeout", "tenant", "0 policies", "no idle session timeout is defined")
        return
    for p in rows:
        if dig(p, "isEnabled") is False:
            add("low", "idle-timeout-disabled", str(dig(p, "displayName")), "isEnabled=false", "the timeout policy is not enforced")
        elif not dig(p, "definition"):
            add("low", "idle-timeout-empty", str(dig(p, "displayName")), "definition empty", "policy has no timeout value")


@check("entra-consent-grant-policy")
def c_consent_policy(ctx):
    rows = graph_all("policies/permissionGrantPolicies", limit=5)
    if rows is None:
        note("entra-consent-grant-policy", 0, denied=1)
        return
    note("entra-consent-grant-policy", len(rows))
    if not rows:
        authz = graph("policies/authorizationPolicy")
        default = str(val(dig(authz, "defaultUserRolePermissions.permissionGrantPoliciesAssigned"), ""))
        if authz is None:
            denied_now("entra-consent-grant-policy")
            add("low", "consent-policy-unreadable", "tenant", "0 grant policies and authorizationPolicy unreadable", "user consent restriction cannot be assessed")
        elif not default or "managepermissiongrants" in default.lower():
            add("high", "no-consent-grant-policy", "tenant", "grantPolicies=0 defaultUserRolePermissions=" + (default or "unset"), "users can consent to any application permission")
        else:
            add("info", "consent-restricted-by-default", "tenant", "defaultUserRolePermissions.permissionGrantPoliciesAssigned=" + default, "the built-in default restricts user consent")
        return
    for p in rows:
        rules = lst(dig(p, "includes"))
        for rule in rules:
            perms = lst(dig(rule, "permissions"))
            write = [x for x in perms if write_scope(x)]
            if write:
                add("medium", "consent-policy-write-scope", str(dig(p, "displayName")), "permissions=" + ",".join(write[:3]), "users may consent to a write scope")
        add("info", "consent-policy", str(dig(p, "displayName")), "rules=" + str(len(rules)) + " id=" + str(dig(p, "id")), "consent policy inventory")


@check("entra-per-user-mfa")
def c_per_user_mfa(ctx):
    users = graph_all("users?$select=id,userPrincipalName,accountEnabled&$top=50", limit=3)
    if users is None:
        note("entra-per-user-mfa", 0, denied=1)
        return
    note("entra-per-user-mfa", len(users))
    enabled_state = 0
    unreadable = 0
    for u in users[:10]:
        doc = graph("users/" + str(dig(u, "id")) + "/authentication/requirements", beta=True)
        if doc is None:
            unreadable += 1
            continue
        per = str(dig(doc, "perUserMfaState") or "").lower()
        if per == "enabled":
            enabled_state += 1
            add("medium", "per-user-mfa-legacy", dig(u, "userPrincipalName"), "perUserMfaState=Enabled", "legacy per-user MFA is enforced, which ignores Conditional Access policy")
    if unreadable == min(len(users), 10) and unreadable:
        add("low", "per-user-mfa-unreadable", "tenant", str(unreadable) + " users unreadable", "per-user MFA state cannot be assessed")
    elif enabled_state:
        add("medium", "per-user-mfa-legacy", "tenant", "users=" + str(min(len(users), 10)) + " withPerUserMfa=" + str(enabled_state), "legacy per-user MFA is in use; it ignores conditional access")
    sample("entra-per-user-mfa", min(len(users), 10), len(users), "users")


@check("entra-license-errors")
def c_license_errors(ctx):
    rows = graph_all("users?$select=userPrincipalName,assignedLicenses,licenseAssignmentStates&$top=200", limit=5)
    if rows is None:
        note("entra-license-errors", 0, denied=1)
        return
    note("entra-license-errors", min(len(rows), 200))
    sample("entra-license-errors", min(len(rows), 200), len(rows), "users")
    for u in rows[:200]:
        for st in lst(dig(u, "licenseAssignmentStates")):
            err = str(dig(st, "error") or "")
            if err:
                add("low", "license-assignment-error", dig(u, "userPrincipalName"), "sku=" + str(dig(st, "skuId")) + " error=" + err, "group-based licensing is failing for this user")


@check("entra-custom-security-attributes")
def c_csa(ctx):
    sets = graph_all("directory/customSecurityAttributeDefinitions", limit=5, beta=True)
    if sets is None:
        note("entra-custom-security-attributes", 0, denied=1)
        return
    note("entra-custom-security-attributes", len(sets))
    if not sets:
        add("info", "no-custom-attributes", "tenant", "0 definitions", "no attribute-based access control surface")
        return
    dyn = unread(dynamic_groups(ctx), "dynamic group rules", "csa-usage-unassessed")
    if dyn is None:
        return
    rules = [rule for _name, rule, _state in dyn.values()]
    for d in sets:
        name = str(dig(d, "name"))
        used = any("customSecurityAttribute" in r or name.lower() in r.lower() for r in rules)
        add("info" if used else "low", "csa-dynamic-dependency" if used else "csa-unused", name, "attributeSet=" + str(dig(d, "attributeSet")) + " status=" + str(dig(d, "status")), "a dynamic group depends on this attribute; writing it changes membership" if used else "attribute defined but not used by any dynamic rule")


@check("entra-access-review-health")
def c_review_health(ctx):
    rows = graph_all("identityGovernance/accessReviews/definitions", limit=5, beta=True)
    if rows is None:
        note("entra-access-review-health", 0, denied=1)
        return
    note("entra-access-review-health", len(rows))
    if not rows:
        add("medium", "no-access-reviews", "tenant", "0 definitions", "no access review is configured")
        return
    for d in rows:
        sched = dig(d, "instanceEnumerationScope")
        recur = dig(d, "settings.recurrence")
        never = dig(d, "settings.recurrence.endDate")
        auto = dig(d, "settings.autoApplyDecisionsEnabled")
        add("info", "access-review-definition", str(dig(d, "displayName")), "recurrence=" + str(recur) + " endDate=" + str(never) + " autoApply=" + str(auto) + " scope=" + str(bool(sched)), "review configuration")


@check("sub-managed-hsm")
def c_hsm(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.keyvault/managedhsms' | project name, subscriptionId, publicNet=tostring(properties.publicNetworkAccess), purge=tostring(properties.securityDomainProperties.activationStatus), regions=properties.regions", ctx["subs"])
    if rows is None:
        note("sub-managed-hsm", 0, denied=1)
        return
    note("sub-managed-hsm", len(rows))
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        name = str(dig(r, "name"))
        if str(val(dig(r, "publicNet"), "")).lower() == "enabled":
            add("medium", "hsm-public-network", name, "publicNetworkAccess=Enabled", "the HSM accepts traffic from any network", s)
        sec = str(val(dig(r, "purge"), ""))
        if sec.lower() != "active":
            add("medium", "hsm-no-security-domain", name, "securityDomain=" + (sec or "none"), "no security domain means no disaster recovery for the key material", s)


@check("sub-apim-depth")
def c_apim(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.apimanagement/service' | project name, subscriptionId, sku=tostring(sku.name), vnet=tostring(properties.virtualNetworkType), publicNet=tostring(properties.publicNetworkAccess), cert=properties.hostnameConfigurations, legacy=tostring(properties.legacyPortalStatus), identity=tostring(identity.type), disableGateway=tostring(properties.disableGateway)", ctx["subs"])
    if rows is None:
        note("sub-apim-depth", 0, denied=1)
        return
    note("sub-apim-depth", len(rows))
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        name = str(dig(r, "name"))
        vnet = str(val(dig(r, "vnet"), "")).strip()
        if str(val(dig(r, "publicNet"), "Enabled")).lower() == "enabled" and vnet.lower() in ("", "none"):
            add("medium", "apim-public-no-vnet", name, "publicNetworkAccess=Enabled virtualNetworkType=" + (vnet or "none"), "the gateway is reachable from the internet without network isolation", s)
        legacy = str(val(dig(r, "legacy"), ""))
        if legacy and legacy.lower() not in ("disabled", "false"):
            add("low", "apim-legacy-portal", name, "legacyPortalStatus=" + legacy, "the deprecated developer portal is still served", s)
        hosts = lst(dig(r, "cert"))
        if any(tri(dig(h, "negotiateClientCertificate")) is True for h in hosts):
            add("info", "apim-client-cert", name, "negotiateClientCertificate=true", "client certificates are requested at the gateway", s)
        if not dig(r, "identity"):
            add("low", "apim-no-managed-identity", name, "identity.type=none", "the service cannot use managed identity for backends or named values", s)


@check("sub-firewall-premium")
def c_fw_premium(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.network/azurefirewalls' | project name, subscriptionId, sku=tostring(properties.sku.tier), idps=tostring(properties.idpsMode), tls=tostring(properties.transportSecurity.enabled), dns=tostring(properties.dnsProxyEnabled), threat=tostring(properties.threatIntelMode)", ctx["subs"])
    if rows is None:
        note("sub-firewall-premium", 0, denied=1)
        return
    note("sub-firewall-premium", len(rows))
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        name = str(dig(r, "name"))
        tier = str(val(dig(r, "sku"), "")).lower()
        if tier in ("premium",):
            if str(val(dig(r, "idps"), "")).lower() != "alertanddeny":
                add("medium", "firewall-idps-not-deny", name, "idpsMode=" + str(val(dig(r, "idps"), "unset")), "intrusion detection is not blocking", s)
            if tri(dig(r, "tls")) is not True:
                add("low", "firewall-tls-inspection-off", name, "transportSecurity.enabled=" + str(val(dig(r, "tls"), "false")), "encrypted traffic is not inspected", s)
        if str(val(dig(r, "threat"), "")).lower() in ("off", "alert"):
            add("medium", "firewall-threatintel-weak", name, "threatIntelMode=" + str(val(dig(r, "threat"), "unset")), "malicious traffic is not blocked", s)


@check("sub-frontdoor")
def c_frontdoor(ctx):
    rows = arg_rows("Resources | where type in~ ('microsoft.cdn/profiles/afdendpoints/routes','microsoft.cdn/profiles/endpoints') | project name, type, subscriptionId, redirect=tostring(properties.forwardingProtocol), httpsRedirect=tostring(properties.httpsRedirect), linkToDefaultDomain=tostring(properties.linkToDefaultDomain)", ctx["subs"])
    if rows is None:
        note("sub-frontdoor", 0, denied=1)
        return
    note("sub-frontdoor", len(rows))
    if not rows:
        add("info", "no-frontdoor", "all", "0 CDN or Front Door resources", "no edge entry point")
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        name = str(dig(r, "name"))
        redirect = str(val(dig(r, "redirect"), "")).lower()
        https_redirect = tri(dig(r, "httpsRedirect"))
        if redirect and redirect not in ("httpsonly", "matchrequest") and https_redirect is not True:
            add("medium", "frontdoor-no-https-redirect", name, "forwardingProtocol=" + redirect + " httpsRedirect=" + str(https_redirect), "plaintext is forwarded to the origin", s)
        elif redirect == "matchrequest" and https_redirect is not True:
            add("low", "frontdoor-matchrequest-no-redirect", name, "forwardingProtocol=MatchRequest httpsRedirect=false", "an HTTP request reaches the origin over HTTP", s)


@check("sub-appservice-depth")
def c_appservice_depth(ctx):
    cfg = arg_rows("Resources | where type =~ 'microsoft.web/sites/config' | where name =~ 'web' | project parent=tolower(substring(id, 0, indexof(tolower(id), '/config/'))), http20=tostring(properties.http20Enabled), minTls=tostring(properties.minTlsVersion), ftps=tostring(properties.ftpsState), cors=properties.cors.allowedOrigins, cert=tostring(properties.clientCertEnabled), remoteDebug=tostring(properties.remoteDebuggingEnabled)", ctx["subs"])
    if cfg is None:
        note("sub-appservice-depth", 0, denied=1)
        return
    note("sub-appservice-depth", len(cfg))
    for r in cfg:
        s = str(dig(r, "subscriptionId"))
        name = str(dig(r, "parent")).split("/")[-1]
        if tri(dig(r, "http20")) is False:
            add("low", "appservice-http2-off", name, "http20Enabled=false", "HTTP/2 is disabled on the app", s)
        tls = str(val(dig(r, "minTls"), ""))
        if tls in ("1.0", "1.1"):
            add("medium", "appservice-legacy-tls", name, "minTlsVersion=" + tls, "legacy TLS accepted", s)
        ftps = str(val(dig(r, "ftps"), "")).lower()
        if ftps == "allallowed":
            add("medium", "appservice-ftp-enabled", name, "ftpsState=AllAllowed", "plaintext FTP is accepted alongside FTPS", s)
        elif ftps == "ftpsonly":
            add("low", "appservice-ftps-only", name, "ftpsState=FtpsOnly", "an encrypted FTP channel exists; prefer deployment without FTP", s)
        origins = lst(dig(r, "cors"))
        if "*" in [str(o) for o in origins]:
            add("medium", "appservice-cors-wildcard", name, "allowedOrigins=*", "any browser origin can call the API", s)
        if tri(dig(r, "remoteDebug")) is True:
            add("high", "appservice-remote-debug", name, "remoteDebuggingEnabled=true", "a debug channel is exposed", s)


@check("sub-defender-plan-depth")
def c_defender_plan_detail(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.security/pricings' | project name, subscriptionId, tier=tostring(properties.pricingTier), subPlan=tostring(properties.subPlan), extensions=properties.extensions", ctx["subs"])
    if rows is None:
        note("sub-defender-plan-depth", 0, denied=1)
        return
    note("sub-defender-plan-depth", len(rows))
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        plan = str(dig(r, "name"))
        tier = str(val(dig(r, "tier"), "")).lower()
        if tier != "standard":
            continue
        exts = dig(r, "extensions")
        if isinstance(exts, dict):
            exts = [dict(v, name=k) for k, v in exts.items() if isinstance(v, dict)]
        else:
            exts = lst(exts)
        for e in exts:
            if tri(dig(e, "isEnabled")) is False:
                add("low", "defender-extension-off", plan + "/" + str(dig(e, "name")), "isEnabled=false", "a paid capability inside the plan is switched off", s)


@check("sub-security-automations")
def c_sec_automations(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.security/automations' | project name, subscriptionId, enabled=tostring(properties.isEnabled), actions=properties.actions", ctx["subs"])
    if rows is None:
        note("sub-security-automations", 0, denied=1)
        return
    note("sub-security-automations", len(rows))
    if not rows:
        add("low", "no-security-automation", "all", "0 automations", "no response workflow runs when an alert fires")
    for r in rows:
        if tri(dig(r, "enabled")) is False:
            add("low", "security-automation-disabled", str(dig(r, "name")), "isEnabled=false", "the response workflow exists but is off", str(dig(r, "subscriptionId")))


@check("sub-aks-security")
def c_aks_security(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.containerservice/managedclusters' | project name, subscriptionId, azureRbac=tostring(properties.aadProfile.enableAzureRBAC), imageCleaner=tostring(properties.securityProfile.imageCleaner.enabled), privateDns=tostring(properties.apiServerAccessProfile.privateDNSZone), defender=properties.securityProfile.defender, kv=tostring(properties.securityProfile.azureKeyVaultKms.enabled), kubelet=tostring(properties.identityProfile.kubeletidentity.objectId), localAccounts=tostring(properties.disableLocalAccounts)", ctx["subs"])
    if rows is None:
        note("sub-aks-security", 0, denied=1)
        return
    note("sub-aks-security", len(rows))
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        name = str(dig(r, "name"))
        if tri(dig(r, "azureRbac")) is not True:
            add("medium", "aks-azure-rbac-off", name, "enableAzureRBAC=false", "cluster authorization does not use Azure RBAC", s)
        local = tri(dig(r, "localAccounts"))
        if local is False:
            add("high", "aks-local-accounts-enabled", name, "disableLocalAccounts=false", "local cluster credentials exist outside Entra", s)
        elif local is None:
            add("low", "aks-local-accounts-unknown", name, "disableLocalAccounts not returned", "local accounts are enabled by default; confirm the cluster setting", s)
        defense = dig(r, "defender")
        if tri(dig(defense, "securityMonitoring.enabled")) is not True:
            add("low", "aks-defender-off", name, "defender.securityMonitoring=false", "no container runtime protection", s)
        if not dig(r, "privateDns"):
            add("low", "aks-api-public-dns", name, "privateDNSZone=none", "the API server name resolves publicly", s)
        if tri(dig(r, "imageCleaner")) is not True:
            add("low", "aks-image-cleaner-off", name, "securityProfile.imageCleaner.enabled=" + str(val(dig(r, "imageCleaner"), "unset")), "unused vulnerable images stay on the nodes", s)


@check("sub-loganalytics-depth")
def c_la_depth(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.operationalinsights/workspaces' | project name, subscriptionId, cap=tostring(properties.workspaceCapping.dailyQuotaGb), retention=tostring(properties.retentionInDays), sku=tostring(properties.sku.name), resourceOnlyPerms=tostring(properties.features.enableLogAccessUsingOnlyResourcePermissions)", ctx["subs"])
    if rows is None:
        note("sub-loganalytics-depth", 0, denied=1)
        return
    note("sub-loganalytics-depth", len(rows))
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        name = str(dig(r, "name"))
        days = num(dig(r, "retention"))
        if isinstance(days, int) and days < 90:
            add("medium", "loganalytics-short-retention", name, "retentionInDays=" + str(days), "security logs expire before an incident is closed", s)
        if tri(dig(r, "resourceOnlyPerms")) is not True:
            add("low", "loganalytics-workspace-permissions", name, "enableLogAccessUsingOnlyResourcePermissions=" + str(val(dig(r, "resourceOnlyPerms"), "unset")), "workspace-level readers can query every table", s)
        cap = flt(dig(r, "cap"))
        if isinstance(cap, float) and 0 < cap < 1:
            add("medium", "loganalytics-daily-cap", name, "dailyQuotaGb=" + str(cap), "ingestion stops once the cap is hit, leaving a blind window", s)
    parts = arg_rows("Resources | where type =~ 'microsoft.operationalinsights/workspaces/tables' | project name, subscriptionId, plan=tostring(properties.plan), retention=tostring(properties.retentionInDays)", ctx["subs"])
    if parts is not None:
        basic = [p for p in parts if str(val(dig(p, "plan"), "")).lower() == "basic"]
        if basic:
            add("medium", "loganalytics-basic-tables", "all", "tables=" + str(len(basic)), "tables on the Basic plan have no analytics and a short retention", "tenant")


@check("sub-access-reviews-rbac")
def c_reviews_rbac(ctx):
    rows = arg_rows("AuthorizationResources | where type =~ 'microsoft.authorization/accessreviewscheduledefinitions' | where subscriptionId in (" + subq(ctx["subs"]) + ") | project name, subscriptionId, scope=tostring(properties.scope), recurrence=tostring(properties.settings.recurrence), auto=tostring(properties.settings.autoApplyDecisionsEnabled)", ctx["subs"], scoped=False)
    if rows is None:
        note("sub-access-reviews-rbac", 0, denied=1)
        return
    note("sub-access-reviews-rbac", len(rows))
    if not rows:
        add("medium", "no-azure-access-review", "all", "0 schedules", "Azure RBAC assignments are never reviewed")
    for r in rows:
        if tri(dig(r, "auto")) is not True:
            add("low", "access-review-no-autoapply", str(dig(r, "name")), "autoApplyDecisionsEnabled=false", "review results do not change access", str(dig(r, "subscriptionId")))


@check("sub-publicip-sku")
def c_publicip_sku(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.network/publicipaddresses' | project name, subscriptionId, sku=tostring(sku.name), ddos=tostring(properties.ddosSettings.protectionMode), ip=tostring(properties.ipAddress)", ctx["subs"])
    if rows is None:
        note("sub-publicip-sku", 0, denied=1)
        return
    note("sub-publicip-sku", len(rows))
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        name = str(dig(r, "name"))
        if str(val(dig(r, "sku"), "")).lower() == "basic":
            add("low", "publicip-basic-sku", name, "sku=Basic", "basic SKU is retiring and has no zone or DDoS plan support", s)
        mode = str(val(dig(r, "ddos"), "")).lower()
        if mode not in ("enabled", "virtualnetwork"):
            add("low", "publicip-no-ddos", name, "ddosProtection=" + (mode or "none"), "no DDoS plan protects this address", s)


@check("sub-private-endpoint-coverage")
def c_pe_coverage(ctx):
    types = "'microsoft.keyvault/vaults','microsoft.storage/storageaccounts','microsoft.sql/servers','microsoft.containerregistry/registries','microsoft.web/sites','microsoft.appconfiguration/configurationstores','microsoft.recoveryservices/vaults'"
    q = "Resources | where type in~ (" + types + ") | project name, type, subscriptionId, id=tolower(id)"
    rows = arg_rows(q, ctx["subs"])
    if rows is None:
        note("sub-private-endpoint-coverage", 0, denied=1)
        return
    note("sub-private-endpoint-coverage", len(rows))
    pes = arg_rows("Resources | where type =~ 'microsoft.network/privateendpoints' | mv-expand c = array_concat(properties.privateLinkServiceConnections, properties.manualPrivateLinkServiceConnections) | project target=tolower(tostring(c.properties.privateLinkServiceId))", ctx["subs"])
    if pes is None:
        denied_now("sub-private-endpoint-coverage")
        return
    covered = {str(dig(p, "target")) for p in pes}
    by_type = Counter()
    for r in rows:
        t = str(dig(r, "type")).split("/")[-1]
        if str(dig(r, "id")) in covered:
            continue
        by_type[t] += 1
        add("medium", "no-private-endpoint", str(dig(r, "name")) + " " + t, "privateEndpoint=none", "the service is reachable over its public endpoint", str(dig(r, "subscriptionId")))
    if by_type:
        add("info", "private-endpoint-gap", "all", ",".join(k + "=" + str(v) for k, v in by_type.items()), "resources without a private endpoint, grouped by type")


@check("entra-sspr")
def c_sspr(ctx):
    pol = graph("policies/authenticationMethodsPolicy")
    authz = graph("policies/authorizationPolicy")
    if pol is None and authz is None:
        note("entra-sspr", 0, denied=1)
        return
    note("entra-sspr", 1)
    if pol is None:
        note("entra-sspr", 1, denied=1)
        add("info", "sspr-unassessed", "tenant", "authenticationMethodsPolicy unreadable", "reset methods were not assessed")
        return
    methods = [str(dig(c, "id")) for c in lst(dig(pol, "authenticationMethodConfigurations")) if str(dig(c, "state")).lower() == "enabled"]
    reset_methods = [m for m in methods if m in ("Email", "MobilePhone", "SecurityQuestion", "MicrosoftAuthenticator", "SoftwareOath")]
    if not reset_methods:
        add("medium", "sspr-no-method", "tenant", "enabledMethods=" + ",".join(methods)[:80], "self-service password reset has no usable verification method")
    elif len(reset_methods) < 2:
        add("low", "sspr-single-method", "tenant", "resetMethods=" + ",".join(reset_methods), "one verification method is a single point of compromise")
    else:
        add("info", "sspr-methods", "tenant", "resetMethods=" + ",".join(reset_methods), "self-service reset methods in force")
    admin_reset = dig(authz, "defaultUserRolePermissions.allowedToUseSSPR")
    if admin_reset is True:
        add("medium", "sspr-admins-allowed", "tenant", "allowedToUseSSPR=true", "administrators can reset their own password without a second administrator")


@check("entra-password-protection")
def c_password_protection(ctx):
    doc = graph("settings", beta=True)
    if doc is None:
        note("entra-password-protection", 0, denied=1)
        return
    items = lst(dig(doc, "value"))
    note("entra-password-protection", len(items))
    banned = None
    for item in items:
        if str(dig(item, "templateId")) == "5cf42378-d67d-4f36-ba46-e8b86229381d":
            banned = item
    if banned is None:
        add("medium", "password-protection-default", "tenant", "0 directory settings for password rule", "the custom banned-password list and on-premises enforcement are at platform defaults")
        return
    values = {str(dig(v, "name")): str(dig(v, "value")) for v in lst(dig(banned, "values"))}

    def setting(name):
        return values[name] if name in values else ""

    if not setting("BannedPasswordList"):
        add("low", "password-no-custom-banned-list", "tenant", "BannedPasswordList empty", "only the global banned list applies")
    if tri(setting("EnableBannedPasswordCheckOnPremises")) is not True:
        add("medium", "password-protection-not-onprem", "tenant", "EnableBannedPasswordCheckOnPremises=" + (setting("EnableBannedPasswordCheckOnPremises") or "unset"), "password changes on the on-premises path skip the banned list")
    mode = setting("BannedPasswordCheckOnPremisesMode")
    if mode and mode.lower() != "enforce":
        add("low", "password-protection-audit-mode", "tenant", "BannedPasswordCheckOnPremisesMode=" + mode, "weak passwords are logged, not rejected")


@check("entra-lifecycle-workflows")
def c_lifecycle(ctx):
    rows = graph_all("identityGovernance/lifecycleWorkflows/workflows", limit=5, beta=True)
    if rows is None:
        note("entra-lifecycle-workflows", 0, denied=1)
        return
    note("entra-lifecycle-workflows", len(rows))
    if not rows:
        add("low", "no-lifecycle-workflow", "tenant", "0 workflows", "joiner, mover and leaver steps are manual")
        return
    categories = Counter()
    for w in rows:
        cat = str(dig(w, "category") or "unknown").lower()
        categories[cat] += 1
        if dig(w, "isEnabled") is False:
            add("low", "lifecycle-workflow-disabled", dig(w, "displayName"), "category=" + cat + " isEnabled=false", "the automation exists but does not run")
    if "leaver" not in categories:
        add("medium", "no-leaver-workflow", "tenant", "categories=" + ",".join(categories), "no automated offboarding; access survives departure")


@check("entra-cross-tenant-sync")
def c_xtenant_sync(ctx):
    pol = graph("policies/crossTenantAccessPolicy/default", beta=True)
    configs = graph_all("policies/crossTenantAccessPolicy/partners", limit=5, beta=True)
    if pol is None and configs is None:
        note("entra-cross-tenant-sync", 0, denied=1)
        return
    note("entra-cross-tenant-sync", len(configs) if configs is not None else 1)
    sync = dig(pol, "crossTenantSyncPolicy")
    if sync:
        add("medium", "cross-tenant-sync-configured", "tenant", "crossTenantSyncPolicy present", "identities are provisioned into or out of another tenant automatically")
    for p in (configs if configs is not None else []):
        direct = dig(p, "b2bDirectConnectInbound")
        outward = dig(p, "b2bDirectConnectOutbound")
        for label, node in (("inbound", direct), ("outbound", outward)):
            access = str(val(dig(node, "usersAndGroups.accessType"), ""))
            if access.lower() == "allowed":
                add("medium", "b2b-direct-connect-open", str(val(dig(p, "tenantId"), "?")), "direction=" + label + " accessType=" + access, "shared channels admit users from the partner without a guest object")
    restrictions = dig(pol, "tenantRestrictions")
    if restrictions:
        add("info", "tenant-restrictions-present", "tenant", "tenantRestrictions configured", "outbound sign-in to other tenants is restricted; verify the enforcement is on the network path")


@check("entra-app-claims")
def c_app_claims(ctx):
    apps = graph_all("applications?$select=appId,displayName,groupMembershipClaims,optionalClaims,api", limit=10)
    if apps is None:
        note("entra-app-claims", 0, denied=1)
        return
    note("entra-app-claims", len(apps))
    for a in apps:
        claim = str(dig(a, "groupMembershipClaims") or "")
        if claim.lower() in ("all", "securitygroup", "directoryrole", "applicationgroup"):
            add("low", "app-group-claims", dig(a, "displayName"), "groupMembershipClaims=" + claim, "group identifiers are emitted in the token; overage moves them to a Graph call and leaks directory structure")
        optional = dig(a, "optionalClaims")
        for token_type in ("idToken", "accessToken", "saml2Token"):
            extra = lst(dig(optional, token_type))
            sensitive = [c for c in extra if str(dig(c, "name")) in ("upn", "family_name", "given_name", "onpremises_security_identifier", "ipaddr")]
            if sensitive:
                add("low", "app-optional-claim-pii", dig(a, "displayName"), "token=" + token_type + " claims=" + ",".join(str(dig(c, "name")) for c in sensitive)[:60], "personal attributes are emitted to the application")


@check("entra-token-encryption")
def c_token_encryption(ctx):
    sps = graph_all("servicePrincipals?$select=id,displayName,tokenEncryptionKeyId", limit=10)
    if sps is None:
        note("entra-token-encryption", 0, denied=1)
        return
    note("entra-token-encryption", len(sps))
    configured = [s for s in sps if dig(s, "tokenEncryptionKeyId")]
    if not configured:
        add("info", "no-token-encryption-key", "tenant", "0 service principals with tokenEncryptionKeyId", "SAML assertions are signed but not encrypted")
    for s in configured:
        add("info", "token-encryption-key", dig(s, "displayName"), "tokenEncryptionKeyId=" + str(dig(s, "tokenEncryptionKeyId")), "assertions are encrypted; the key needs a rotation owner")


@check("entra-pta-agents")
def c_pta(ctx):
    org = graph("organization?$select=id,onPremisesSyncEnabled")
    if org is None:
        note("entra-pta-agents", 0, denied=1)
        return
    synced = any(tri(dig(o, "onPremisesSyncEnabled")) is True for o in lst(dig(org, "value")))
    if not synced:
        note("entra-pta-agents", 1)
        add("info", "pta-not-applicable", "tenant", "onPremisesSyncEnabled is not true", "pass-through authentication requires a hybrid directory")
        return
    groups = graph_all("onPremisesPublishingProfiles/authentication/agentGroups", limit=3, beta=True)
    if groups is None:
        note("entra-pta-agents", 0, denied=1)
        add("info", "pta-agents-unreadable", "tenant", "agent group endpoint unavailable", "pass-through authentication agents not assessed")
        return
    items = lst(dig(groups, "value"))
    note("entra-pta-agents", len(items))
    if not items:
        add("info", "no-pta-agents", "tenant", "0 agent groups returned", "pass-through authentication appears unused, or the connector is not registered")
        return
    for g in items:
        agents = lst(dig(g, "agents"))
        name = str(val(dig(g, "agentGroup"), dig(g, "id")))
        add("info", "pta-agent-group", name, "agents=" + str(len(agents)), "each agent validates passwords against the on-premises directory")
        for a in agents:
            if str(val(dig(a, "status"), "")).lower() != "active":
                add("medium", "pta-agent-inactive", str(val(dig(a, "machineName"), dig(a, "id"))), "status=" + str(val(dig(a, "status"), "unknown")), "an authentication agent is not serving requests")


@check("entra-guest-invite-policy")
def c_guest_invites(ctx):
    pol = graph("policies/authorizationPolicy")
    if pol is None:
        note("entra-guest-invite-policy", 0, denied=1)
        return
    note("entra-guest-invite-policy", 1)
    invites = str(val(dig(pol, "allowInvitesFrom"), "unknown"))
    if invites.lower() in ("everyone", "adminsandguestinviters", "adminsguestinvitersandallmembers"):
        add("medium", "guest-invites-broad", "tenant", "allowInvitesFrom=" + invites, "non-administrators can bring external identities into the tenant")
    elif invites.lower() == "none":
        add("info", "guest-invites-disabled", "tenant", "allowInvitesFrom=None", "only administrators can invite")



@check("sub-appconfig-posture")
def c_appconfig(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.appconfiguration/configurationstores' | project name, subscriptionId, publicNet=tostring(properties.publicNetworkAccess), localAuth=tostring(properties.disableLocalAuth), purge=tostring(properties.enablePurgeProtection), softDays=toint(properties.softDeleteRetentionInDays), ident=tostring(identity.type)", ctx["subs"])
    if rows is None:
        note("sub-appconfig-posture", 0, denied=1)
        return
    note("sub-appconfig-posture", len(rows))
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        name = str(dig(r, "name"))
        if str(val(dig(r, "publicNet"), "")).lower() == "enabled":
            add("medium", "appconfig-public-network", name, "publicNetworkAccess=Enabled", "configuration and feature flags are reachable from the internet", s)
        if tri(dig(r, "localAuth")) is False:
            add("medium", "appconfig-local-auth", name, "disableLocalAuth=false", "access keys bypass identity control", s)
        if tri(dig(r, "purge")) is not True:
            add("low", "appconfig-no-purge-protection", name, "enablePurgeProtection=" + str(val(dig(r, "purge"), "unset")), "a deleted store can be purged immediately", s)


@check("sub-search-posture")
def c_search(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.search/searchservices' | project name, subscriptionId, publicNet=tostring(properties.publicNetworkAccess), localAuth=tostring(properties.disableLocalAuth), hosting=tostring(properties.hostingMode), partition=toint(properties.partitionCount)", ctx["subs"])
    if rows is None:
        note("sub-search-posture", 0, denied=1)
        return
    note("sub-search-posture", len(rows))
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        name = str(dig(r, "name"))
        if str(val(dig(r, "publicNet"), "")).lower() == "enabled":
            add("medium", "search-public-network", name, "publicNetworkAccess=Enabled", "the query and admin endpoints accept internet traffic", s)
        if tri(dig(r, "localAuth")) is False:
            add("medium", "search-admin-key-auth", name, "disableLocalAuth=false", "an admin key grants full index control", s)
        elif not dig(r, "localAuth"):
            add("low", "search-local-auth-unknown", name, "disableLocalAuth not returned", "admin keys are enabled by default; confirm the setting", s)


@check("sub-appgw-waf-policy")
def c_appgw_wafpol(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies' | project name, subscriptionId, mode=tostring(properties.policySettings.mode), state=tostring(properties.policySettings.enabledState), body=toint(properties.policySettings.requestBodyCheck)", ctx["subs"])
    if rows is None:
        note("sub-appgw-waf-policy", 0, denied=1)
        return
    note("sub-appgw-waf-policy", len(rows))
    if not rows:
        add("info", "no-appgw-waf-policy", "all", "0 Application Gateway WAF policies", "gateway protection is inline configuration only")
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        name = str(dig(r, "name"))
        if str(val(dig(r, "mode"), "")).lower() == "detection":
            add("high", "appgw-waf-policy-detection", name, "policySettings.mode=Detection", "the gateway logs attacks but does not block them", s)
        if str(val(dig(r, "state"), "")).lower() != "enabled":
            add("high", "appgw-waf-policy-disabled", name, "enabledState=" + str(val(dig(r, "state"), "unset")), "the policy is attached but inactive", s)
        if tri(dig(r, "body")) is False:
            add("low", "appgw-waf-no-body-check", name, "requestBodyCheck=false", "request bodies are not inspected", s)


@check("sub-kv-cert-contacts")
def c_kv_contacts(ctx):
    vaults = arg_rows("Resources | where type =~ 'microsoft.keyvault/vaults' | project name, subscriptionId, rg=resourceGroup", ctx["subs"])
    if vaults is None:
        note("sub-kv-cert-contacts", 0, denied=1)
        return
    note("sub-kv-cert-contacts", min(len(vaults), 10))
    sample("sub-kv-cert-contacts", min(len(vaults), 10), len(vaults), "vaults")
    for v in vaults[:10]:
        s = str(dig(v, "subscriptionId"))
        url = ARM_BASE + "/subscriptions/" + s + "/resourceGroups/" + str(dig(v, "rg")) + "/providers/Microsoft.KeyVault/vaults/" + str(dig(v, "name")) + "/certificates?api-version=2023-07-01"
        LAST_QUERY[CURRENT["check"]] = "az rest --url " + repr(url)
        doc = arm(url)
        if doc is None:
            denied_now("sub-kv-cert-contacts")
            continue
        certs = lst(dig(doc, "value"))
        for c in certs:
            policy = dig(c, "properties.policy") or dig(c, "policy")
            lifetime = lst(dig(policy, "lifetimeActions"))
            auto = any(str(dig(dig(a, "action"), "actionType")).lower() == "autorenew" for a in lifetime)
            if not auto:
                add("medium", "kv-cert-no-autorenew", str(dig(v, "name")) + "/" + str(dig(c, "id")).split("/")[-1], "lifetimeActions without AutoRenew", "the certificate expires without renewal", s)


@check("sub-defender-plan-coverage")
def c_defender_coverage(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.security/pricings' | project name, subscriptionId, tier=tostring(properties.pricingTier)", ctx["subs"])
    if rows is None:
        note("sub-defender-plan-coverage", 0, denied=1)
        return
    note("sub-defender-plan-coverage", len(rows))
    expected = ("VirtualMachines", "StorageAccounts", "SqlServers", "AppServices", "KeyVaults", "Arm", "Dns", "Containers", "OpenSourceRelationalDatabases", "CosmosDbs")
    by_sub = defaultdict(dict)
    for r in rows:
        by_sub[str(dig(r, "subscriptionId"))][str(dig(r, "name"))] = str(val(dig(r, "tier"), ""))
    for s, plans in by_sub.items():
        missing = [p for p in expected if p not in plans]
        free = [p for p, t in plans.items() if t.lower() == "free"]
        if missing:
            add("low", "defender-plan-absent", s, "missing=" + ",".join(missing)[:100], "no Defender plan exists for these resource types", s)
        if free:
            add("medium", "defender-plan-free", s, "freeTier=" + ",".join(free)[:100], "these workloads have no threat protection", s)


@check("sub-security-contacts")
def c_security_contacts(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.security/securitycontacts' | project name, subscriptionId, email=tostring(properties.email), phone=tostring(properties.phone), roles=tostring(properties.alertNotifications.state), admins=tostring(properties.alertsToAdmins)", ctx["subs"])
    if rows is None:
        note("sub-security-contacts", 0, denied=1)
        return
    note("sub-security-contacts", len(rows))
    if not rows:
        add("medium", "no-security-contact", "all", "0 security contacts across every subscription", "Defender alerts reach nobody")
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        email = str(val(dig(r, "email"), ""))
        if not email or "@" not in email:
            add("medium", "security-contact-invalid", "subscription", "email=" + (email or "empty"), "the alert recipient is not a usable address", s, "/subscriptions/" + s)
        elif email.lower().endswith((".onmicrosoft.com",)) is False and ";" not in email and "," not in email:
            add("low", "security-contact-single-person", str(dig(r, "name")), "email=" + email, "alerts go to one mailbox; use a monitored distribution list", s)
        roles = dig(r, "roles")
        state = None
        if isinstance(roles, dict):
            state = tri(dig(roles, "state"))
        elif roles is not MISSING:
            state = tri(roles)
        if state is False:
            add("low", "security-contact-roles-off", str(dig(r, "name")), "alertNotifications.state=Off", "role-based notification is disabled", s)
        elif state is None:
            add("low", "security-contact-roles-unknown", str(dig(r, "name")), "alertNotifications not returned", "role notification cannot be confirmed", s)


@check("sub-udr-default-route")
def c_udr_split(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.network/routetables' | mv-expand r = properties.routes | project name, subscriptionId, id=tolower(id), route=tostring(r.name), prefix=tostring(r.properties.addressPrefix), hop=tostring(r.properties.nextHopType), ip=tostring(r.properties.nextHopIpAddress)", ctx["subs"])
    if rows is None:
        note("sub-udr-default-route", 0, denied=1)
        return
    note("sub-udr-default-route", len(rows))
    by_table = defaultdict(list)
    for r in rows:
        by_table[(str(dig(r, "subscriptionId")), str(dig(r, "id")) or str(dig(r, "name")))].append(r)
    for (s, table), rules in by_table.items():
        prefixes = {str(dig(r, "prefix")) for r in rules}
        if "0.0.0.0/1" in prefixes and "128.0.0.0/1" in prefixes:
            add("medium", "udr-default-route-split", table, "prefixes=0.0.0.0/1,128.0.0.0/1", "two halves replace the default route and override a forced tunnel", s)
        for r in rules:
            if str(dig(r, "hop")).lower() == "internet" and str(dig(r, "prefix")) in ("0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1"):
                add("high", "udr-internet-default", table, "route=" + str(dig(r, "route")) + " prefix=" + str(dig(r, "prefix")) + " nextHop=Internet", "traffic bypasses the inspection path", s)


@check("sub-sql-firewall-width")
def c_sql_fw_width(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.sql/servers/firewallrules' | project server=split(id, '/')[8], name, subscriptionId, start=tostring(properties.startIpAddress), end=tostring(properties.endIpAddress)", ctx["subs"])
    if rows is None:
        note("sub-sql-firewall-width", 0, denied=1)
        return
    note("sub-sql-firewall-width", len(rows))
    def _int(ip):
        parts = str(ip).split(".")
        if len(parts) != 4 or not all(p.isdigit() for p in parts):
            return -1
        total = 0
        for p in parts:
            total = total * 256 + int(p)
        return total
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        label = str(dig(r, "server")) + "/" + str(dig(r, "name"))
        start, end = _int(dig(r, "start")), _int(dig(r, "end"))
        if start < 0 or end < 0:
            continue
        if start == 0 and end == 0:
            add("info", "sql-firewall-azure-services", label, "0.0.0.0-0.0.0.0", "the Allow Azure services sentinel; any Azure tenant can reach the server", s)
            continue
        if start == 0:
            add("high", "sql-firewall-from-zero", label, "range=" + str(dig(r, "start")) + "-" + str(dig(r, "end")), "the range starts at 0.0.0.0 and is not the Azure-services sentinel; it admits addresses across the internet", s)
            continue
        width = end - start + 1
        if width > 65536:
            add("high", "sql-firewall-very-wide", label, "range=" + str(dig(r, "start")) + "-" + str(dig(r, "end")) + " addresses=" + str(width), "the rule admits more than a /16 of the internet", s)
        elif width > 256:
            add("medium", "sql-firewall-wide", label, "range=" + str(dig(r, "start")) + "-" + str(dig(r, "end")) + " addresses=" + str(width), "the rule admits more than a /24", s)


@check("entra-seamless-sso")
def c_seamless_sso(ctx):
    org = graph("organization?$select=id,onPremisesSyncEnabled,onPremisesLastSyncDateTime,dirSyncEnabled")
    if org is None:
        note("entra-seamless-sso", 0, denied=1)
        return
    items = lst(dig(org, "value"))
    note("entra-seamless-sso", len(items))
    synced = False
    for o in items:
        state = tri(dig(o, "onPremisesSyncEnabled"))
        if state is True:
            synced = True
            add("info", "directory-sync-enabled", "tenant", "lastSync=" + str(val(dig(o, "onPremisesLastSyncDateTime"), "unknown")), "identities and password hashes originate on premises")
        else:
            add("info", "no-directory-sync", "tenant", "onPremisesSyncEnabled=" + str(state), "the tenant is cloud-only")
    if not synced:
        add("info", "seamless-sso-not-applicable", "tenant", "onPremisesSyncEnabled is not true", "Seamless SSO needs a hybrid directory; there is no AZUREADSSOACC object to assess")
        return
    agents = graph_all("onPremisesPublishingProfiles/authentication/agentGroups", limit=3, beta=True)
    if agents is not None:
        groups = lst(dig(agents, "value"))
        active = [g for g in groups if str(val(dig(g, "agentGroup"), "")).lower() or lst(dig(g, "agents"))]
        add("info", "seamless-sso-agent-groups", "tenant", "groups=" + str(len(groups)) + " withAgents=" + str(len(active)), "hybrid authentication agents registered in this tenant")
    add("low", "seamless-sso-key-rotation-unverifiable", "tenant", "AZUREADSSOACC is an on-premises AD computer object", "Entra exposes no view of this object; confirm its Kerberos decryption key rotation on the domain controller")


@check("entra-password-writeback")
def c_writeback(ctx):
    org = graph("organization?$select=id,onPremisesSyncEnabled")
    settings = graph_all("groupSettings", limit=5)
    if org is None:
        note("entra-password-writeback", 0, denied=1)
        return
    note("entra-password-writeback", 1)
    synced = any(tri(dig(o, "onPremisesSyncEnabled")) is True for o in lst(dig(org, "value")))
    if not synced:
        add("info", "writeback-not-applicable", "tenant", "onPremisesSyncEnabled=false", "no on-premises directory to write back to")
        return
    add("low", "writeback-state-unreadable", "tenant", "onPremisesSyncEnabled=true settings=" + str(len(settings) if settings is not None else 0), "password writeback is configured in AAD Connect, not in the directory; a cloud reset may not reach the on-premises password")


@check("entra-pim-activation-rules")
def c_pim_activation(ctx):
    pols = graph_all("policies/roleManagementPolicies?$expand=rules", limit=5, beta=True)
    if pols is None:
        note("entra-pim-activation-rules", 0, denied=1)
        return
    note("entra-pim-activation-rules", min(len(pols), 10))
    sample("entra-pim-activation-rules", min(len(pols), 10), len(pols), "role management policies")
    for p in pols[:10]:
        rules = lst(dig(p, "rules"))
        enabled = set()
        ticketing = False
        max_duration = ""
        for rule in rules:
            for item in lst(dig(rule, "enabledRules")):
                enabled.add(str(item))
            rtype = str(dig(rule, "@odata.type")).lower()
            if rtype.endswith("ticketingrule"):
                ticketing = bool(dig(rule, "ticketSystem"))
            if rtype.endswith("expirationrule") or rtype.endswith("expirationendrule"):
                max_duration = str(val(dig(rule, "maximumDuration"), ""))
        name = str(val(dig(p, "displayName"), dig(p, "id")))
        if "Justification" not in enabled:
            add("medium", "pim-no-justification", name, "enabledRules=" + ",".join(sorted(enabled))[:80], "activation records no reason")
        if not ticketing:
            add("low", "pim-no-ticketing", name, "ticketSystem unset", "activation is not tied to a change record")
        hours = 0
        hour_match = re.match(r"^PT(\d+)H", max_duration)
        day_match = re.match(r"^P(\d+)D", max_duration)
        if hour_match:
            hours = int(hour_match.group(1))
        elif day_match:
            hours = 24 * int(day_match.group(1))
        if hours > 8:
            add("medium", "pim-long-activation", name, "maximumDuration=" + max_duration, "an activation lasts longer than a working day")
        add("info", "pim-activation-rule", name, "enabledRules=" + ",".join(sorted(enabled))[:80] + " maxDuration=" + (max_duration or "unset"), "activation requirements")


@check("entra-federation-posture")
def c_federation_posture(ctx):
    domains = graph_all("domains?$select=id,authenticationType,isVerified", limit=3)
    if domains is None:
        note("entra-federation-posture", 0, denied=1)
        return
    note("entra-federation-posture", len(domains))
    for d in domains:
        name = str(dig(d, "id"))
        auth = str(val(dig(d, "authenticationType"), "unknown"))
        if auth.lower() == "federated":
            add("medium", "domain-federated", name, "authenticationType=Federated", "password validation happens outside Entra; the identity provider is the trust anchor")
            fed = graph("domains/" + name + "/federationConfiguration", beta=True)
            if fed is None:
                denied_now("entra-federation-posture")
                continue
            for cfg in lst(dig(fed, "value")):
                stamped = []
                for label, node in (("primary", dig(cfg, "signingCertificate")), ("next", dig(cfg, "nextSigningCertificate"))):
                    if node in (MISSING, None):
                        continue
                    text = str(val(dig(node, "endDateTime"), "")) or str(node)
                    if text:
                        stamped.append((label, text))
                if not stamped:
                    add("low", "federation-certs-unreadable", name, "signingCertificate not returned", "signing certificate lifetime cannot be assessed")
                for label, end in stamped:
                    if _expired(end) is None:
                        add("low", "federation-cert-expiry-unreadable", name, "certificate=" + label + " end=" + end, "the certificate end date could not be parsed; expiry is unknown")
                    elif _expired(end):
                        add("high", "federation-cert-expired", name, "certificate=" + label + " end=" + end, "the federation trust anchor is expired")
                    else:
                        add("info", "federation-cert-lifetime", name, "certificate=" + label + " end=" + end, "signing certificate lifetime; plan the rollover")
        elif auth.lower() == "managed":
            add("info", "domain-managed", name, "authenticationType=Managed", "password hash or pass-through authentication; confirm which in AAD Connect")


@check("entra-guest-sponsors")
def c_guest_sponsors(ctx):
    guests = graph_all("users?$filter=userType eq 'Guest'&$select=id,userPrincipalName&$top=100", limit=3)
    if guests is None:
        note("entra-guest-sponsors", 0, denied=1)
        return
    note("entra-guest-sponsors", min(len(guests), 15))
    sample("entra-guest-sponsors", min(len(guests), 15), len(guests), "guests")
    unsponsored = 0
    for g in guests[:15]:
        doc = graph("users/" + str(dig(g, "id")) + "/sponsors", beta=True)
        if doc is None:
            denied_now("entra-guest-sponsors")
            continue
        sponsors = lst(dig(doc, "value"))
        if not sponsors:
            unsponsored += 1
            add("low", "guest-no-sponsor", dig(g, "userPrincipalName"), "sponsors=0", "no internal identity is accountable for this guest")
    if unsponsored:
        add("medium", "guest-sponsorship-gap", "tenant", "unsponsored=" + str(unsponsored) + " sampled=" + str(min(len(guests), 15)), "guest lifecycle has no owner")


@check("sub-redis-auth")
def c_redis_auth(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.cache/redis' | project name, subscriptionId, rg=resourceGroup, nonSsl=tostring(properties.enableNonSslPort), publicNet=tostring(properties.publicNetworkAccess), tls=tostring(properties.minimumTlsVersion), aad=tostring(properties.redisConfiguration.aad-enabled), accessKeys=tostring(properties.accessKeys)", ctx["subs"])
    if rows is None:
        note("sub-redis-auth", 0, denied=1)
        return
    note("sub-redis-auth", len(rows))
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        name = str(dig(r, "name"))
        if tri(dig(r, "aad")) is not True:
            add("medium", "redis-no-entra-auth", name, "redisConfiguration.aad-enabled=" + str(val(dig(r, "aad"), "unset")), "clients authenticate with a shared access key", s)
    rules = arg_rows("Resources | where type =~ 'microsoft.cache/redis/firewallrules' | project name, subscriptionId, cache=split(id, '/')[8]", ctx["subs"])
    if rules is None:
        denied_now("sub-redis-auth")
        return
    with_rules = {str(dig(x, "cache")) for x in rules}
    for r in rows:
        if str(dig(r, "name")) not in with_rules:
            add("low", "redis-no-firewall-rule", str(dig(r, "name")), "0 firewall rules", "the cache accepts any source address the network path allows", str(dig(r, "subscriptionId")))


@check("sub-messaging-sas-rights")
def c_sas_rights(ctx):
    rows = arg_rows("Resources | where type in~ ('microsoft.servicebus/namespaces/authorizationrules','microsoft.eventhub/namespaces/authorizationrules') | project name, type, subscriptionId, ns=split(id, '/')[8], rights=properties.rights", ctx["subs"])
    if rows is None:
        note("sub-messaging-sas-rights", 0, denied=1)
        return
    note("sub-messaging-sas-rights", len(rows))
    if not rows:
        add("info", "messaging-sas-not-indexed", "all", "0 namespace authorization rules", "shared access policy rights cannot be assessed")
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        label = str(dig(r, "ns")) + "/" + str(dig(r, "name"))
        rights = [str(x).lower() for x in lst(dig(r, "rights"))]
        if "manage" in rights:
            add("high", "messaging-sas-manage-right", label, "rights=" + ",".join(rights), "the key can create and delete entities and read every message", s)
        elif "listen" in rights and "send" in rights:
            add("medium", "messaging-sas-send-listen", label, "rights=" + ",".join(rights), "one key both publishes and consumes", s)


@check("sub-nsg-precedence")
def c_nsg_precedence(ctx):
    subnets = arg_rows("Resources | where type =~ 'microsoft.network/virtualnetworks' | mv-expand s = properties.subnets | project vnet=name, subscriptionId, subnet=tostring(s.name), nsg=tolower(tostring(s.properties.networkSecurityGroup.id))", ctx["subs"])
    if subnets is None:
        note("sub-nsg-precedence", 0, denied=1)
        return
    note("sub-nsg-precedence", len(subnets))
    nics = arg_rows("Resources | where type =~ 'microsoft.network/networkinterfaces' | project name, subscriptionId, subnet=tolower(tostring(properties.ipConfigurations[0].properties.subnet.id)), nsg=tolower(tostring(properties.networkSecurityGroup.id))", ctx["subs"])
    if nics is None:
        denied_now("sub-nsg-precedence")
        return
    subnet_nsg = {(str(dig(s, "subscriptionId")) + "|" + str(dig(s, "vnet")).lower() + "/" + str(dig(s, "subnet")).lower()): str(dig(s, "nsg")) for s in subnets}
    for n in nics:
        nic_nsg = str(dig(n, "nsg"))
        subnet_id = str(dig(n, "subnet"))
        parts = subnet_id.split("/")
        key = (str(dig(n, "subscriptionId")) + "|" + parts[8] + "/" + parts[-1]).lower() if len(parts) > 9 else ""
        parent = subnet_nsg.get(key, "")
        s = str(dig(n, "subscriptionId"))
        if nic_nsg and parent and nic_nsg != parent:
            add("medium", "nsg-two-layer-divergent", str(dig(n, "name")), "nicNsg=" + nic_nsg.split("/")[-1] + " subnetNsg=" + parent.split("/")[-1], "inbound traffic must pass the NIC group first; a subnet deny can be shadowed by a NIC allow only in the reverse order, so review both", s)
        elif nic_nsg and not parent:
            add("low", "nsg-nic-only", str(dig(n, "name")), "subnetNsg=none nicNsg=" + nic_nsg.split("/")[-1], "protection depends on one interface-level group", s)
        elif parent and not nic_nsg:
            add("info", "nsg-subnet-only", str(dig(n, "name")), "subnetNsg=" + parent.split("/")[-1], "the subnet group is the only filter", s)


@check("sub-policy-parameter-effect")
def c_policy_params(ctx):
    rows = arg_rows("PolicyResources | where type =~ 'microsoft.authorization/policyassignments' | where subscriptionId in (" + subq(ctx["subs"]) + ") | project name, subscriptionId, effect=tostring(properties.parameters.effect.value), enforcement=tostring(properties.enforcementMode), notScopes=properties.notScopes", ctx["subs"], scoped=False)
    if rows is None:
        note("sub-policy-parameter-effect", 0, denied=1)
        return
    note("sub-policy-parameter-effect", len(rows))
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        effect = str(val(dig(r, "effect"), "")).lower()
        if effect in ("audit", "auditifnotexists", "disabled"):
            add("medium", "policy-parameter-weak-effect", dig(r, "name"), "parameters.effect=" + effect, "the assignment reports but does not prevent the condition", s)


@check("sub-storage-encryption-scopes")
def c_encryption_scopes(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.storage/storageaccounts/encryptionscopes' | project account=split(id, '/')[8], name, subscriptionId, source=tostring(properties.keySource), state=tostring(properties.state)", ctx["subs"])
    if rows is None:
        note("sub-storage-encryption-scopes", 0, denied=1)
        return
    note("sub-storage-encryption-scopes", len(rows))
    if not rows:
        add("info", "no-encryption-scope", "all", "0 encryption scopes", "all containers share the account key")
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        label = str(dig(r, "account")) + "/" + str(dig(r, "name"))
        if str(val(dig(r, "source"), "")).lower() != "microsoft.keyvault":
            add("low", "encryption-scope-platform-key", label, "keySource=" + str(val(dig(r, "source"), "unset")), "the scope uses a platform key, so it adds no key separation", s)
        if str(val(dig(r, "state"), "")).lower() == "disabled":
            add("low", "encryption-scope-disabled", label, "state=Disabled", "the scope exists but is not usable", s)


@check("sub-aks-pod-security")
def c_aks_podsec(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.containerservice/managedclusters' | project name, subscriptionId, policy=tostring(properties.addonProfiles.azurepolicy.enabled), pss=tostring(properties.podSecurityPolicyName), workloadIdentity=tostring(properties.securityProfile.workloadIdentity.enabled), oidc=tostring(properties.oidcIssuerProfile.enabled)", ctx["subs"])
    if rows is None:
        note("sub-aks-pod-security", 0, denied=1)
        return
    note("sub-aks-pod-security", len(rows))
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        name = str(dig(r, "name"))
        if tri(dig(r, "policy")) is not True:
            add("medium", "aks-no-azure-policy", name, "addonProfiles.azurepolicy.enabled=" + str(val(dig(r, "policy"), "unset")), "no admission control enforces pod security standards", s)
        if tri(dig(r, "workloadIdentity")) is not True or tri(dig(r, "oidc")) is not True:
            add("low", "aks-workload-identity-off", name, "workloadIdentity=" + str(val(dig(r, "workloadIdentity"), "unset")) + " oidcIssuer=" + str(val(dig(r, "oidc"), "unset")), "pods cannot federate to Entra and must use shared secrets", s)


@check("sub-apim-auth")
def c_apim_auth(ctx):
    named = arg_rows("Resources | where type =~ 'microsoft.apimanagement/service/namedvalues' | project service=split(id, '/')[8], name, subscriptionId, secret=tostring(properties.secret), kv=tostring(properties.keyVault.secretIdentifier), value=tostring(properties.value)", ctx["subs"])
    if named is None:
        note("sub-apim-auth", 0, denied=1)
        return
    note("sub-apim-auth", len(named))
    for n in named:
        s = str(dig(n, "subscriptionId"))
        label = str(dig(n, "service")) + "/" + str(dig(n, "name"))
        if tri(dig(n, "secret")) is True and not dig(n, "kv"):
            add("high", "apim-named-value-plaintext", label, "secret=true keyVault unset", "a secret named value is stored in the service instead of Key Vault", s)
        elif not dig(n, "kv") and dig(n, "value") and SECRET_PAT.search(str(dig(n, "name"))):
            add("medium", "apim-named-value-credential-name", label, "name suggests a credential, keyVault unset", "confirm the value is not a credential", s)
    svcs = arg_rows("Resources | where type =~ 'microsoft.apimanagement/service' | project name, subscriptionId, rg=resourceGroup, portal=tostring(properties.developerPortalStatus)", ctx["subs"])
    if svcs is None:
        denied_now("sub-apim-auth")
        return
    for v in svcs:
        s = str(dig(v, "subscriptionId"))
        if str(val(dig(v, "portal"), "")).lower() == "enabled":
            add("low", "apim-developer-portal-enabled", dig(v, "name"), "developerPortalStatus=Enabled", "self-service signup and API discovery are exposed", s)


@check("sub-automation-assets")
def c_automation_assets(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.automation/automationaccounts' | project name, subscriptionId, rg=resourceGroup", ctx["subs"])
    if rows is None:
        note("sub-automation-assets", 0, denied=1)
        return
    note("sub-automation-assets", min(len(rows), 10))
    sample("sub-automation-assets", min(len(rows), 10), len(rows), "automation accounts")
    for r in rows[:10]:
        s = str(dig(r, "subscriptionId"))
        base = ARM_BASE + "/subscriptions/" + s + "/resourceGroups/" + str(dig(r, "rg")) + "/providers/Microsoft.Automation/automationAccounts/" + str(dig(r, "name"))
        url = base + "/credentials?api-version=2023-11-01"
        LAST_QUERY[CURRENT["check"]] = "az rest --url " + repr(url)
        creds = arm(url)
        if creds is None:
            denied_now("sub-automation-assets")
        else:
            items = lst(dig(creds, "value"))
            if items:
                add("medium", "automation-credential-asset", str(dig(r, "name")), "credentialAssets=" + str(len(items)), "runbooks authenticate with a stored username and password", s)
        curl = base + "/certificates?api-version=2023-11-01"
        certs = arm(curl)
        if certs is not None and lst(dig(certs, "value")):
            add("medium", "automation-certificate-asset", str(dig(r, "name")), "certificateAssets=" + str(len(lst(dig(certs, "value")))), "a certificate with a private key is stored in the account", s)


@check("sub-logicapp-trigger")
def c_logicapp_trigger(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.logic/workflows' | project name, subscriptionId, rg=resourceGroup, state=tostring(properties.state), access=tostring(properties.accessControl.triggers.allowedCallerIpAddresses)", ctx["subs"])
    if rows is None:
        note("sub-logicapp-trigger", 0, denied=1)
        return
    note("sub-logicapp-trigger", len(rows))
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        name = str(dig(r, "name"))
        if str(val(dig(r, "state"), "")).lower() == "disabled":
            add("info", "logicapp-disabled", name, "state=Disabled", "the workflow does not run", s)
            continue
        base = ARM_BASE + "/subscriptions/" + s + "/resourceGroups/" + str(dig(r, "rg")) + "/providers/Microsoft.Logic/workflows/" + name
        url = base + "/triggers?api-version=2019-05-01"
        LAST_QUERY[CURRENT["check"]] = "az rest --url " + repr(url)
        doc = arm(url)
        if doc is None:
            denied_now("sub-logicapp-trigger")
            continue
        for t in lst(dig(doc, "value")):
            kind = str(val(dig(t, "properties.definition.kind"), ""))
            if kind.lower() == "request":
                add("medium", "logicapp-http-trigger", name, "trigger=" + str(dig(t, "name")) + " kind=Request", "the workflow starts from a bearer URL; anyone holding the SAS callback runs it", s)


@check("sub-mg-default-membership")
def c_mg_default(ctx):
    rows = arg_rows("ResourceContainers | where type =~ 'microsoft.resources/subscriptions' | where subscriptionId in (" + subq(ctx["subs"]) + ") | project name, id=tolower(id), chain=properties.managementGroupAncestorsChain", ctx["subs"], scoped=False)
    if rows is None:
        note("sub-mg-default-membership", 0, denied=1)
        return
    note("sub-mg-default-membership", len(rows))
    for r in rows:
        chain = lst(dig(r, "chain"))
        names = [str(dig(c, "name")) for c in chain]
        if len(names) <= 1:
            parts = str(dig(r, "id")).split("/")
            sub_id = parts[2] if len(parts) > 2 else "unknown"
            add("medium", "subscription-at-tenant-root", dig(r, "name"), "managementGroupChain=" + ",".join(names), "the subscription sits directly under the root group, so a root-scope grant reaches it", sub_id)


@check("sub-diag-destination")
def c_diag_destination(ctx):
    settings = arg_rows("Resources | where type =~ 'microsoft.insights/diagnosticsettings' | project name, subscriptionId, storage=tolower(tostring(properties.storageAccountId)), workspace=tostring(properties.workspaceId)", ctx["subs"])
    if settings is None:
        note("sub-diag-destination", 0, denied=1)
        return
    note("sub-diag-destination", len(settings))
    targets = {str(dig(s, "storage")) for s in settings if dig(s, "storage")}
    if not targets:
        add("info", "diag-no-storage-target", "all", "0 storage destinations", "logs go to a workspace or event hub")
        return
    accounts = arg_rows("Resources | where type =~ 'microsoft.storage/storageaccounts' | project id=tolower(id), name, subscriptionId, publicNet=tostring(properties.publicNetworkAccess), blobPublic=tostring(properties.allowBlobPublicAccess), https=tostring(properties.supportsHttpsTrafficOnly)", ctx["subs"])
    if accounts is None:
        denied_now("sub-diag-destination")
        return
    for a in accounts:
        if str(dig(a, "id")) not in targets:
            continue
        s = str(dig(a, "subscriptionId"))
        name = str(dig(a, "name"))
        if str(val(dig(a, "publicNet"), "")).lower() == "enabled":
            add("medium", "diag-storage-public", name, "publicNetworkAccess=Enabled", "the log archive is reachable from the internet", s)
        if tri(dig(a, "blobPublic")) is True:
            add("high", "diag-storage-anonymous-allowed", name, "allowBlobPublicAccess=true", "a container holding audit logs can be made anonymous", s)
        if tri(dig(a, "https")) is False:
            add("high", "diag-storage-plaintext", name, "supportsHttpsTrafficOnly=false", "log traffic can be read in transit", s)


@check("entra-pim-standing-roles")
def c_pim_standing(ctx):
    defs = graph_all("roleManagement/directory/roleDefinitions", limit=5)
    active = graph_all("roleManagement/directory/roleAssignmentScheduleInstances", limit=5, beta=True)
    eligible = graph_all("roleManagement/directory/roleEligibilityScheduleInstances", limit=5, beta=True)
    if defs is None or active is None:
        note("entra-pim-standing-roles", 0, denied=1)
        return
    privileged = {str(dig(d, "id")): d for d in defs if is_escalation(d)}
    note("entra-pim-standing-roles", len(active))
    eligible_pairs = set()
    eligible_ok = eligible is not None
    if not eligible_ok:
        denied_now("entra-pim-standing-roles")
        add("low", "pim-eligibility-unreadable", "tenant", "roleEligibilityScheduleInstances unavailable", "permanent and eligible grants cannot be distinguished")
    else:
        eligible_pairs = {(str(dig(e, "principalId")), str(dig(e, "roleDefinitionId"))) for e in eligible}
    counts = Counter()
    for a in active:
        rid = str(dig(a, "roleDefinitionId"))
        if rid not in privileged:
            continue
        pid = str(dig(a, "principalId"))
        kind = str(val(dig(a, "assignmentType"), "unknown")).lower()
        counts[rid] += 1
        if kind == "assigned" and eligible_ok and (pid, rid) not in eligible_pairs:
            role = privileged[rid]
            add("high", "standing-privileged-role", str(val(dig(role, "displayName"), rid)), "principal=" + pid + " assignmentType=Assigned noEligibility", "the role is held permanently with no activation path")
    for rid, role in privileged.items():
        if not counts.get(rid):
            add("info", "privileged-role-unheld", str(val(dig(role, "displayName"), rid)), "activeAssignments=0", "no standing holder for this role")


@check("entra-access-review-guest-scope")
def c_review_guests(ctx):
    rows = graph_all("identityGovernance/accessReviews/definitions", limit=5, beta=True)
    if rows is None:
        note("entra-access-review-guest-scope", 0, denied=1)
        return
    note("entra-access-review-guest-scope", len(rows))
    guest_scoped = []
    for d in rows:
        scope = str(dig(d, "scope"))
        query_type = str(val(dig(d, "instanceEnumerationScope.query"), ""))
        blob = (scope + " " + query_type).lower()
        if "usertype eq 'guest'" in blob or "guest" in blob:
            guest_scoped.append(str(dig(d, "displayName")))
    if guest_scoped:
        add("info", "access-review-guest-scoped", "tenant", "reviews=" + ",".join(guest_scoped)[:80], "guest access is reviewed explicitly")
    else:
        add("medium", "access-review-no-guest-scope", "tenant", "definitions=" + str(len(rows)) + " guestScoped=0", "no review targets external identities; guest access accumulates")


@check("entra-app-instance-lock")
def c_instance_lock(ctx):
    apps = graph_all("applications?$select=appId,displayName,servicePrincipalLockConfiguration", limit=10, beta=True)
    if apps is None:
        note("entra-app-instance-lock", 0, denied=1)
        return
    note("entra-app-instance-lock", len(apps))
    locked = 0
    for a in apps:
        lock = dig(a, "servicePrincipalLockConfiguration")
        if lock is MISSING or not lock:
            continue
        locked += 1
        if tri(dig(lock, "isEnabled")) is not True:
            add("medium", "app-instance-lock-off", dig(a, "displayName"), "servicePrincipalLockConfiguration.isEnabled=false", "sensitive instance properties can be changed by a service principal owner")
        else:
            add("info", "app-instance-lock-on", dig(a, "displayName"), "allProperties=" + str(dig(lock, "allProperties")) + " credentialsWithUsageVerify=" + str(dig(lock, "credentialsWithUsageVerify")), "instance properties are protected from owner edits")
    if not locked:
        add("low", "app-instance-lock-unset", "tenant", "applicationsWithLock=0", "no application protects its instance properties; owner edits reach credentials and identifier URIs")


@check("sub-apim-api-subscription")
def c_apim_api_sub(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.apimanagement/service/apis' | project service=split(id, '/')[8], name, subscriptionId, required=tostring(properties.subscriptionRequired), protocols=properties.protocols, path=tostring(properties.path)", ctx["subs"])
    if rows is None:
        note("sub-apim-api-subscription", 0, denied=1)
        return
    note("sub-apim-api-subscription", len(rows))
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        label = str(dig(r, "service")) + "/" + str(dig(r, "name"))
        if tri(dig(r, "required")) is False:
            add("medium", "apim-api-no-subscription-key", label, "subscriptionRequired=false", "the API is callable without a subscription key", s)
        protocols = [str(p).lower() for p in lst(dig(r, "protocols"))]
        if protocols and "https" not in protocols:
            add("high", "apim-api-plaintext", label, "protocols=" + ",".join(protocols), "the API accepts plaintext HTTP", s)


@check("sub-automation-runbook-content")
def c_runbook_content(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.automation/automationaccounts/runbooks' | project account=split(id, '/')[8], name, subscriptionId, rg=resourceGroup, kind=tostring(properties.runbookType)", ctx["subs"])
    if rows is None:
        note("sub-automation-runbook-content", 0, denied=1)
        return
    note("sub-automation-runbook-content", min(len(rows), 10))
    sample("sub-automation-runbook-content", min(len(rows), 10), len(rows), "runbooks")
    for r in rows[:10]:
        s = str(dig(r, "subscriptionId"))
        label = str(dig(r, "account")) + "/" + str(dig(r, "name"))
        url = ARM_BASE + "/subscriptions/" + s + "/resourceGroups/" + str(dig(r, "rg")) + "/providers/Microsoft.Automation/automationAccounts/" + str(dig(r, "account")) + "/runbooks/" + str(dig(r, "name")) + "/draft/content?api-version=2023-11-01"
        LAST_QUERY[CURRENT["check"]] = "az rest --url " + repr(url)
        doc = arm(url)
        if doc is None:
            denied_now("sub-automation-runbook-content")
            continue
        text_body = str(val(dig(doc, "properties.script"), "")) or (doc if isinstance(doc, str) else str(doc))
        if not text_body or len(text_body) < 20:
            add("low", "runbook-content-unreadable", label, "draft content empty or not returned", "the runbook body cannot be scanned", s)
            continue
        hits = []
        for pattern in ("ConvertTo-SecureString", "-Password ", "AccountKey=", "SharedAccessKey=", "ClientSecret", "password="):
            if pattern.lower() in text_body.lower():
                hits.append(pattern.strip())
        if hits:
            add("high", "runbook-inline-credential", label, "patterns=" + ",".join(hits[:4]), "the runbook body carries credential material", s)


@check("entra-tenant-relationships")
def c_tenant_relationships(ctx):
    partners = graph_all("policies/crossTenantAccessPolicy/partners", limit=5, beta=True)
    sps = graph_all("servicePrincipals?$select=id,appId,displayName,appOwnerOrganizationId,servicePrincipalType", limit=10)
    if partners is None and sps is None:
        note("entra-tenant-relationships", 0, denied=1)
        return
    note("entra-tenant-relationships", len(lst(partners)) + len(lst(sps)))
    for p in lst(partners):
        tid = str(val(dig(p, "tenantId"), ""))
        label = tenant_name(tid)
        inbound = str(val(dig(p, "b2bCollaborationInbound.usersAndGroups.accessType"), "unset"))
        outbound = str(val(dig(p, "b2bCollaborationOutbound.usersAndGroups.accessType"), "unset"))
        trusted = any(tri(dig(p, key)) is True for key in ("inboundTrust.isMfaAccepted", "inboundTrust.isCompliantDeviceAccepted", "inboundTrust.isHybridAzureADJoinedDeviceAccepted"))
        add("info", "tenant-partner", label or tid, "inbound=" + inbound + " outbound=" + outbound + " deviceOrMfaTrust=" + str(trusted), "explicit cross-tenant relationship")
        if not label:
            add("low", "tenant-partner-unresolved", tid, "findTenantInformationByTenantId returned nothing", "the partner tenant cannot be named; verify the id manually")
    publishers = Counter()
    unknown_owner = 0
    for s in lst(sps):
        owner = str(val(dig(s, "appOwnerOrganizationId"), "")).lower()
        if not owner or owner in MS_TENANTS:
            continue
        rel = tenant_rel(owner)
        if rel == "home":
            continue
        if rel == "unknown":
            unknown_owner += 1
            continue
        publishers[(owner, str(val(dig(s, "displayName"), "")))] += 1
    if unknown_owner:
        undecided("app-owner-tenant-unknown", "servicePrincipals=" + str(unknown_owner), "the home tenant was not read, so foreign ownership cannot be confirmed")
    for (owner, app), count in publishers.most_common(10):
        label = tenant_name(owner)
        add("medium", "app-owned-by-foreign-tenant", app, "ownerTenant=" + (label or owner) + " servicePrincipals=" + str(count), "an application registered in another tenant is present here; its publisher controls the code and the credentials")
    if not publishers and sps is None:
        note("entra-tenant-relationships", len(lst(partners)), denied=1)
        add("info", "foreign-publishers-unassessed", "tenant", "servicePrincipals unreadable", "application ownership was not assessed")
    elif not publishers:
        add("info", "no-foreign-app-publishers", "tenant", "0 service principals owned outside this tenant", "every application present is first-party")


@check("entra-cross-tenant-escalation")
def c_xtenant_escalation(ctx):
    defs = graph_all("roleManagement/directory/roleDefinitions", limit=5)
    asg = graph_all("roleManagement/directory/roleAssignments", limit=5)
    partners = graph_all("policies/crossTenantAccessPolicy/partners", limit=5, beta=True)
    gdap = graph_all("directory/delegatedAdminRelationships", limit=5, beta=True)
    if defs is None or asg is None:
        note("entra-cross-tenant-escalation", 0, denied=1)
        return
    partners = unread(partners, "cross-tenant access partners", "cross-tenant-partners-unreadable")
    gdap = unread(gdap, "delegated admin relationships", "cross-tenant-gdap-unreadable")
    guests = unread(scan_guests(ctx), "guest accounts", "cross-tenant-guests-unreadable")
    blind = partners is None or gdap is None or guests is None
    privileged = {str(dig(d, "id")): d for d in defs if is_escalation(d)}
    edges = 0
    note("entra-cross-tenant-escalation", len(asg) + len(lst(partners)) + len(lst(gdap)))
    guest_roles = []
    for a in asg:
        pid = str(dig(a, "principalId"))
        rid = str(dig(a, "roleDefinitionId"))
        if guests is not None and pid in guests and rid in privileged:
            guest_roles.append((pid, str(val(dig(privileged[rid], "displayName"), rid))))
    for pid, role in guest_roles:
        name = ctx["idx"].resolve(pid) or pid
        domain = name.split("@")[-1] if "@" in name else "unknown"
        edges += 1
        add("critical", "cross-tenant-guest-privileged-role", name, "role=" + role + " sourceDomain=" + domain, "an identity that another tenant controls holds a directory role here")
        chain("external-identity-to-directory-role", domain + " -> guest " + name + " -> " + role, "critical", "the far tenant decides who sits in this role")
    trusted = []
    for p in lst(partners):
        tid = str(val(dig(p, "tenantId"), ""))
        inbound = str(val(dig(p, "b2bCollaborationInbound.usersAndGroups.accessType"), "")).lower()
        mfa = tri(dig(p, "inboundTrust.isMfaAccepted")) is True
        device = tri(dig(p, "inboundTrust.isCompliantDeviceAccepted")) is True or tri(dig(p, "inboundTrust.isHybridAzureADJoinedDeviceAccepted")) is True
        if (mfa or device) and inbound != "blocked":
            trusted.append((tid, mfa, device))
    for tid, mfa, device in trusted:
        label = tenant_name(tid) or tid
        satisfied = ",".join([t for t, on in (("MFA", mfa), ("compliantOrHybridDevice", device)) if on])
        edges += 1
        add("high", "cross-tenant-trust-bypass", label, "inboundTrust=" + satisfied, "accounts in that tenant satisfy your conditional access without a factor this tenant controls")
        chain("external-tenant-satisfies-ca", "tenant " + label + " -> " + satisfied + " -> any resource it can reach", "high", "trust is delegated to an anchor outside this tenant")
    sync = unread(graph("policies/crossTenantAccessPolicy/default", beta=True),
                  "cross-tenant default policy", "cross-tenant-default-policy-unreadable")
    blind = blind or sync is None
    if sync is not None and dig(sync, "crossTenantSyncPolicy"):
        edges += 1
        add("high", "cross-tenant-sync-identity-source", "tenant", "crossTenantSyncPolicy present", "identities are provisioned from another directory; their attributes and lifecycle are decided there")
        chain("provisioned-identity-path", "other tenant -> cross-tenant sync -> local object -> inherited access", "high", "a foreign provisioning job decides who exists here")
    outbound = 0
    for r in lst(gdap):
        roles = lst(dig(r, "accessDetails.unifiedRoles"))
        if str(val(dig(r, "status"), "")).lower() != "active":
            continue
        outbound += 1
        label = tenant_name(str(val(dig(r, "customer.tenantId"), ""))) or str(val(dig(r, "customer.displayName"), "customer"))
        edges += 1
        add("high", "cross-tenant-outbound-admin", label, "roles=" + str(len(roles)) + " relationship=" + str(val(dig(r, "displayName"), "")), "principals in this tenant administer another tenant; the same credentials act on both sides")
        chain("local-admin-to-customer-tenant", "this tenant -> GDAP -> " + label, "high", "blast radius includes the customer tenant")
    if ctx["subs"]:
        lh = arg_rows("Resources | where type =~ 'microsoft.managedservices/registrationdefinitions' | project name, subscriptionId, props=properties", ctx["subs"])
        lap = arg_rows("AuthorizationResources | where type =~ 'microsoft.authorization/roleassignments' | where subscriptionId in (" + subq(ctx["subs"]) + ") | where tostring(properties.principalType) == 'ForeignGroup' | project name, subscriptionId, principalId=tostring(properties.principalId), roleId=tostring(properties.roleDefinitionId), scope=tostring(properties.scope)", ctx["subs"], scoped=False)
        lh = unread(lh, "Lighthouse registrations", "cross-tenant-lighthouse-unreadable")
        lap = unread(lap, "foreign-principal Azure RBAC", "cross-tenant-rbac-unreadable")
        blind = blind or lh is None or lap is None
        for r in lst(lh):
            manager = str(val(dig(r, "props.managedByTenantId"), "")) or str(val(dig(r, "props.registrationDefinitionProperties.managedByTenantId"), ""))
            rel = tenant_rel(manager)
            if not manager or rel == "home":
                continue
            if rel == "unknown":
                undecided("cross-tenant-delegation-unknown", "registration=" + str(dig(r, "name")), "the home tenant was not read, so delegated control cannot be attributed to another directory")
                continue
            auth = lst(dig(r, "props.authorizations")) or lst(dig(r, "props.registrationDefinitionProperties.authorizations"))
            roles = [str(dig(a2, "roleDefinitionId")) for a2 in auth]
            edges += 1
            add("critical", "cross-tenant-control-plane-access", dig(r, "name"), "managedByTenantId=" + (tenant_name(manager) or manager) + " principals=" + str(len(auth)), "another tenant holds delegated control over this subscription", str(dig(r, "subscriptionId")))
            chain("external-tenant-to-subscription", "tenant " + (tenant_name(manager) or manager) + " -> Lighthouse subscription " + str(dig(r, "subscriptionId")) + " roles=" + str(len(roles)), "critical", "control-plane access is held outside this directory")
        for r in lst(lap):
            edges += 1
            add("high", "cross-tenant-azure-rbac", dig(r, "principalId"), "scope=" + str(dig(r, "scope")) + " role=" + str(dig(r, "roleId")).split("/")[-1], "a principal from another tenant holds Azure RBAC here", str(dig(r, "subscriptionId")))
    if outbound:
        add("info", "cross-tenant-outbound-count", "tenant", "activeRelationships=" + str(outbound), "principals here administer other tenants")
    if not edges and not blind:
        add("info", "no-cross-tenant-escalation-edge", "tenant", "partners=" + str(len(lst(partners))) + " gdap=" + str(len(lst(gdap))) + " privilegedGuests=" + str(len(guest_roles)), "no trust edge from another tenant reaches a privileged object here")
    if guest_roles or trusted:
        add("info", "cross-tenant-scope-limit", "tenant", "edges=" + str(edges), "the far side of each edge is outside this assessment; partner-side role assignments, consent and conditional access are not readable with these credentials")


@check("entra-guest-domain-inventory")
def c_guest_domains(ctx):
    guests = graph_all("users?$filter=userType eq 'Guest'&$select=id,userPrincipalName,mail,createdDateTime&$top=999", limit=10)
    if guests is None:
        note("entra-guest-domain-inventory", 0, denied=1)
        return
    note("entra-guest-domain-inventory", len(guests))
    consumer = ("gmail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "icloud.com", "protonmail.com", "gmx.de", "web.de", "mail.ru", "qq.com")
    domains = Counter()
    personal = 0
    for g in guests:
        address = upn_canonical(str(val(dig(g, "mail"), "")) or str(val(dig(g, "userPrincipalName"), "")))
        domain = address.split("@")[-1].lower() if "@" in address else "unknown"
        domains[domain] += 1
        if domain in consumer:
            personal += 1
            add("medium", "guest-personal-identity", dig(g, "userPrincipalName"), "domain=" + domain, "the external identity is a consumer account; its recovery mailbox is outside any corporate control")
    for domain, count in domains.most_common(12):
        add("info", "guest-domain", domain, "accounts=" + str(count), "external identity source domain")
    if personal:
        add("medium", "guest-consumer-identity-share", "tenant", "consumerAccounts=" + str(personal) + " guests=" + str(len(guests)), "consumer identities widen the trust boundary beyond partner organisations")


def with_tenant(tenant_id, fn):
    keep = {"tenant": CFG.get("tenant", ""), "home": HOME_TENANT["id"], "name": HOME_TENANT["name"]}
    saved_cache = dict(CACHE)
    saved_ca = dict(CA_CACHE)
    saved_kv = dict(KV_CACHE)
    saved_url = dict(CACHE_URL)
    saved_sp = dict(SP_FALLBACK)
    saved_names = dict(TENANT_NAMES)
    saved_failed = set(TENANT_FAILED)
    saved_trunc = set(TRUNC_KEYS)
    saved_scopes = dict(SCOPE_NAMES)
    saved_paths = list(TRUNCATED)
    TRUNCATED.clear()
    CFG["tenant"] = str(tenant_id)
    HOME_TENANT["id"] = str(tenant_id).lower()
    HOME_TENANT["name"] = tenant_name(tenant_id)
    CACHE.clear()
    CA_CACHE.clear()
    KV_CACHE.clear()
    CACHE_URL.clear()
    SP_FALLBACK.clear()
    try:
        with audit_scope():
            return fn()
    finally:
        CFG["tenant"] = keep["tenant"]
        HOME_TENANT["id"] = keep["home"]
        HOME_TENANT["name"] = keep["name"]
        TENANT_NAMES.clear()
        TENANT_NAMES.update(saved_names)
        TENANT_FAILED.clear()
        TENANT_FAILED.update(saved_failed)
        TRUNC_KEYS.clear()
        TRUNC_KEYS.update(saved_trunc)
        SCOPE_NAMES.clear()
        SCOPE_NAMES.update(saved_scopes)
        peer_paths = ["tenant " + str(tenant_id) + ": " + str(p) for p in TRUNCATED]
        TRUNCATED[:] = saved_paths + [p for p in peer_paths if p not in saved_paths]
        CACHE.clear()
        CACHE.update(saved_cache)
        CA_CACHE.clear()
        CA_CACHE.update(saved_ca)
        KV_CACHE.clear()
        KV_CACHE.update(saved_kv)
        CACHE_URL.clear()
        CACHE_URL.update(saved_url)
        SP_FALLBACK.clear()
        SP_FALLBACK.update(saved_sp)


def peer_privilege(tenant_id):
    """Return (privileged holders, guests with roles) for another tenant."""
    result = {"privileged": [], "guestRoles": [], "error": ""}

    def collect():
        defs = graph_all("roleManagement/directory/roleDefinitions", limit=5)
        asg = graph_all("roleManagement/directory/roleAssignments", limit=5)
        if defs is None or asg is None:
            result["error"] = "no read access to " + str(tenant_id)
            return
        privileged = {str(dig(d, "id")): d for d in defs if is_escalation(d)}
        users = graph_all("users?$select=id,userPrincipalName,userType&$top=999", limit=5)
        if users is None:
            result["error"] = "user list unreadable in " + str(tenant_id)
            return
        groups = graph_all("groups?$select=id,displayName&$top=999", limit=5)
        sps = graph_all("servicePrincipals?$select=id,displayName,servicePrincipalType&$top=999", limit=5)
        kinds = {}
        for u in users:
            kinds[str(dig(u, "id"))] = (str(dig(u, "userPrincipalName")), str(dig(u, "userType")) or "User")
        for g in lst(groups):
            kinds[str(dig(g, "id"))] = ("", "Group")
        for s in lst(sps):
            if str(dig(s, "id")):
                kinds[str(dig(s, "id"))] = (str(dig(s, "displayName")), str(dig(s, "servicePrincipalType")) or "ServicePrincipal")
        for a in asg:
            rid = str(dig(a, "roleDefinitionId"))
            if rid not in privileged:
                continue
            pid = str(dig(a, "principalId"))
            upn, kind = kinds.get(pid, ("", "Unknown"))
            role = str(val(dig(privileged[rid], "displayName"), rid))
            result["privileged"].append((pid, upn, role, kind))
            if kind.lower() == "guest":
                result["guestRoles"].append((upn, role))

    with_tenant(tenant_id, collect)
    return result

@check("entra-peer-tenant-privilege")
def c_peer_privilege(ctx):
    named = CFG["peers"] if "peers" in CFG else ""
    peers = [t.strip().lower() for t in str(named).split(",") if t.strip()]
    if not peers:
        note("entra-peer-tenant-privilege", 0)
        add("info", "peer-tenant-not-configured", "tenant", "0 peer tenants named", "pass --peer-tenant to compare privileged access across directories this login can read")
        return
    note("entra-peer-tenant-privilege", len(peers))
    reviewed = 0
    for tid in peers:
        rel_peer = tenant_rel(tid)
        if rel_peer == "home":
            add("info", "peer-tenant-is-home", tid, "same as the audited tenant", "peer entry ignored")
            continue
        if rel_peer == "unknown":
            undecided("peer-tenant-home-unknown", "peer=" + tid, "the home tenant was not read, so this peer cannot be distinguished from it")
            continue
        info = peer_privilege(tid)
        label = tenant_name(tid) or tid
        if info["error"]:
            add("low", "peer-tenant-unreadable", label, info["error"], "privileged access in that directory was not assessed")
            continue
        reviewed += 1
        holders = info["privileged"]
        add("info", "peer-tenant-privileged", label, "privilegedAssignments=" + str(len(holders)), "privileged access in a directory this login can read")
        home_users = graph_all("users?$select=id,userPrincipalName&$top=999", limit=5)
        home_addresses = {upn_canonical(dig(u, "userPrincipalName")) for u in lst(home_users)}
        home_addresses = {a for a in home_addresses if a}
        if home_users is None:
            add("low", "peer-overlap-unassessed", label, "this tenant's user list unreadable", "the same-identity comparison across directories was not performed")
        unresolved = [h for h in holders if h[3] in ("Group", "Unknown")]
        if unresolved:
            add("info", "peer-principal-type-unaligned", label, "groupHolders=" + str(sum(1 for h in unresolved if h[3] == "Group")) + " unknownHolders=" + str(sum(1 for h in unresolved if h[3] == "Unknown")), "a group or unresolved principal holds privilege in that directory; name matching cannot follow group membership")
        same_upn = [h for h in holders if h[1] and upn_canonical(h[1]) in home_addresses]
        for _pid, upn, role, _kind in same_upn:
            add("critical", "identity-privileged-in-both-tenants", upn, "role=" + role + " peer=" + label, "one principal name is privileged in both directories")
            chain("dual-tenant-privilege", str(upn) + " -> " + role + " in " + label, "critical", "one compromised account reaches two directories")
        for upn, role in info["guestRoles"]:
            add("high", "peer-guest-holds-role", upn or "unknown", "role=" + role + " peer=" + label, "an external identity holds a privileged role in that directory; if it comes from here, this tenant's compromise reaches it")
            chain("guest-to-peer-role", str(upn) + " (guest) -> " + role + " in " + label, "high", "guest privilege granted in the peer directory")

    if not reviewed:
        add("low", "peer-tenant-none-readable", "tenant", "peers=" + str(len(peers)) + " readable=0", "the login could not read any peer directory")


@check("entra-ca-signin-frequency")
def c_signin_frequency(ctx):
    pols = ca_all("policies", limit=5)
    if pols is None:
        note("entra-ca-signin-frequency", 0, denied=1)
        return
    enabled = [p for p in pols if str(dig(p, "state")) == "enabled"]
    note("entra-ca-signin-frequency", len(enabled))
    forced = []
    for p in enabled:
        freq = dig(p, "sessionControls.signInFrequency")
        if tri(dig(freq, "isEnabled")) is True:
            forced.append(str(dig(p, "displayName")) + "(" + str(val(dig(freq, "value"), "?")) + str(val(dig(freq, "type"), "")) + ")")
    if not forced:
        add("medium", "no-signin-frequency", "tenant", "enabledPolicies=" + str(len(enabled)) + " withSignInFrequency=0", "sessions are not re-evaluated on a schedule; a stolen session survives until the token expires")
    else:
        add("info", "signin-frequency", "tenant", "policies=" + ",".join(forced)[:100], "periodic re-authentication is enforced")


@check("entra-global-admin-count")
def c_ga_count(ctx):
    defs = graph_all("roleManagement/directory/roleDefinitions", limit=5)
    asg = graph_all("roleManagement/directory/roleAssignments", limit=5)
    if defs is None or asg is None:
        note("entra-global-admin-count", 0, denied=1)
        return
    ga = {str(dig(d, "id")) for d in defs if str(val(dig(d, "templateId"), "")).lower() == "62e90394-69f5-4237-9190-012177145e10"}
    holders = [str(dig(a, "principalId")) for a in asg if str(dig(a, "roleDefinitionId")) in ga]
    note("entra-global-admin-count", len(holders))
    if not holders:
        add("medium", "no-global-administrator", "tenant", "0 assignments", "no verified administrative path")
    elif len(holders) > 5:
        add("medium", "global-administrator-count", "tenant", "holders=" + str(len(holders)), "more than five standing Global Administrators widens the credential attack surface")
    elif len(holders) < 2:
        add("low", "single-global-administrator", "tenant", "holders=" + str(len(holders)), "one administrator is a single point of failure for recovery")
    else:
        add("info", "global-administrator-count-ok", "tenant", "holders=" + str(len(holders)), "within the recommended band")


@check("entra-multitenant-apps")
def c_multitenant(ctx):
    apps = graph_all("applications?$select=appId,displayName,signInAudience,verifiedPublisher,publisherDomain", limit=10)
    if apps is None:
        note("entra-multitenant-apps", 0, denied=1)
        return
    note("entra-multitenant-apps", len(apps))
    multi = []
    for a in apps:
        audience = str(val(dig(a, "signInAudience"), ""))
        if audience in ("AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount", "PersonalMicrosoftAccount"):
            multi.append((str(dig(a, "displayName")), audience, str(val(dig(a, "verifiedPublisher.displayName"), ""))))
    for name, audience, publisher in multi:
        sev = "medium" if publisher else "low"
        add(sev, "multitenant-application", name, "signInAudience=" + audience + " verifiedPublisher=" + (publisher or "none"), "the application accepts identities from other tenants" + ("" if publisher else "; the consent screen shows no verified publisher"))
    if not multi:
        add("info", "no-multitenant-apps", "tenant", "applications=" + str(len(apps)), "every application is single-tenant")


@check("entra-app-overscope")
def c_overscope(ctx):
    grants = graph_all("oauth2PermissionGrants", limit=10)
    apps = graph_all("applications?$select=appId,displayName,requiredResourceAccess", limit=10)
    if grants is None or apps is None:
        note("entra-app-overscope", 0, denied=1)
        return
    note("entra-app-overscope", len(grants) + len(apps))
    by_app = {}
    for a in apps:
        wanted = defaultdict(set)
        for res in lst(dig(a, "requiredResourceAccess")):
            resource = str(val(dig(res, "resourceAppId"), ""))
            for perm in lst(dig(res, "resourceAccess")):
                wanted[resource].add(str(dig(perm, "id")))
        by_app[str(dig(a, "appId"))] = (str(val(dig(a, "displayName"), "unnamed")), dict(wanted))
    sps = graph_all("servicePrincipals?$select=id,appId,displayName", limit=10)
    if sps is None:
        denied_now("entra-app-overscope")
    sp_app = {}
    declared = dict(by_app)
    for s in lst(sps):
        label, wanted = by_app.get(str(dig(s, "appId")), (str(val(dig(s, "displayName"), "")), {}))
        sid = str(dig(s, "id"))
        sp_app[sid] = str(val(dig(s, "appId"), ""))
        declared[sid] = (label, wanted)
    for g in grants:
        entry = declared.get(str(dig(g, "clientId")))
        if entry is None:
            continue
        name, wanted = entry
        if not name:
            continue
        granted = {s.strip().lower() for s in str(val(dig(g, "scope"), "")).split() if s.strip()}
        resource = str(val(dig(g, "resourceId"), ""))
        resource_app = sp_app.get(resource, GRAPH_APP_ID)
        wanted_ids = set(wanted.get(resource_app, set()))
        if granted and not wanted_ids:
            add("medium", "grant-without-manifest-scope", name, "granted=" + ",".join(sorted(granted)[:4]) + " resource=" + (resource_app or "unknown") + " manifestDeclares=0", "a delegated grant exists but the application declares no required permission for that resource")
        elif granted:
            names = declared_names(wanted_ids, resource_app)
            if names is None:
                deny("entra-app-overscope")
                add("low", "grant-scope-names-unresolved", name, "granted=" + ",".join(sorted(granted)[:4]), "the permission list of the target resource is unreadable, so the grant was not compared with the manifest")
                continue
            extra = sorted(granted - names)
            if names and extra:
                add("low", "grant-not-in-manifest", name, "grantedNotDeclared=" + ",".join(extra[:4]), "granted scopes are absent from the manifest; requiredResourceAccess understates what the app uses")
            elif names:
                add("info", "grant-declared", name, "granted=" + ",".join(sorted(granted)[:4]) + " declared=" + str(len(names)), "granted scopes are present in the manifest")


@check("sub-advisor-security")
def c_advisor(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.advisor/recommendations' | where tostring(properties.category) == 'Security' | project name, subscriptionId, impact=tostring(properties.impact), state=tostring(properties.recommendationStatus), problem=tostring(properties.shortDescription.problem)", ctx["subs"])
    if rows is None:
        note("sub-advisor-security", 0, denied=1)
        return
    note("sub-advisor-security", len(rows))
    open_rows = [r for r in rows if str(val(dig(r, "state"), "Active")) not in ("Dismissed", "Postponed", "Resolved")]
    sample("sub-advisor-security", min(len(open_rows), 25), len(open_rows), "open recommendations")
    for r in open_rows[:25]:
        sev = "medium" if str(val(dig(r, "impact"), "")).lower() == "high" else "low"
        add(sev, "advisor-security-recommendation", str(val(dig(r, "problem"), "unnamed recommendation"))[:70], "impact=" + str(val(dig(r, "impact"), "unknown")) + " state=" + str(val(dig(r, "state"), "Active")), "Azure Advisor reports a security recommendation", str(dig(r, "subscriptionId")))
    if not rows:
        add("info", "advisor-no-security-recommendations", "all", "0 security recommendations", "Advisor returned no security advice; confirm the subscription is assessed")


@check("sub-pe-dns-zone")
def c_pe_dns(ctx):
    pes = arg_rows("Resources | where type =~ 'microsoft.network/privateendpoints' | project name, subscriptionId, id=tolower(id), subnet=tostring(properties.subnet.id)", ctx["subs"])
    if pes is None:
        note("sub-pe-dns-zone", 0, denied=1)
        return
    note("sub-pe-dns-zone", len(pes))
    groups = arg_rows("Resources | where type =~ 'microsoft.network/privateendpoints/privatednszonegroups' | project pe=tolower(substring(id, 0, indexof(tolower(id), '/privatednszonegroups')))", ctx["subs"])
    if groups is None:
        denied_now("sub-pe-dns-zone")
        return
    covered = {str(dig(g, "pe")) for g in groups}
    for p in pes:
        if str(dig(p, "id")) not in covered:
            add("low", "private-endpoint-no-dns-zone", dig(p, "name"), "no privateDnsZoneGroup child", "name resolution falls back to public DNS for this endpoint", str(dig(p, "subscriptionId")))


@check("sub-aks-endpoint-exposure")
def c_aks_exposure(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.containerservice/managedclusters' | project name, subscriptionId, privateCluster=tostring(properties.apiServerAccessProfile.enablePrivateCluster), ranges=properties.apiServerAccessProfile.authorizedIpRanges, netpol=tostring(properties.networkProfile.networkPolicy), outbound=tostring(properties.apiServerAccessProfile.enablePrivateClusterPublicFqdn)", ctx["subs"])
    if rows is None:
        note("sub-aks-endpoint-exposure", 0, denied=1)
        return
    note("sub-aks-endpoint-exposure", len(rows))
    for r in rows:
        s = str(dig(r, "subscriptionId"))
        name = str(dig(r, "name"))
        private = tri(dig(r, "privateCluster"))
        ranges = lst(dig(r, "ranges"))
        if private is not True and not ranges:
            add("medium", "aks-api-public-unrestricted", name, "privateCluster=false authorizedIpRanges=0", "the Kubernetes API server accepts connections from any address", s)
        elif private is not True:
            add("low", "aks-api-public-restricted", name, "authorizedIpRanges=" + str(len(ranges)), "the API server is public but limited to listed ranges", s)
        if str(val(dig(r, "netpol"), "")).lower() in ("", "none"):
            add("medium", "aks-no-network-policy", name, "networkPolicy=" + str(val(dig(r, "netpol"), "none")), "pod-to-pod traffic is unrestricted inside the cluster", s)


@check("sub-vnet-ddos")
def c_vnet_ddos(ctx):
    rows = arg_rows("Resources | where type =~ 'microsoft.network/virtualnetworks' | project name, subscriptionId, ddos=tostring(properties.enableDdosProtection), plan=tostring(properties.ddosProtectionPlan.id)", ctx["subs"])
    plans = arg_rows("Resources | where type =~ 'microsoft.network/ddosprotectionplans' | project name, subscriptionId", ctx["subs"])
    if rows is None or plans is None:
        note("sub-vnet-ddos", 0, denied=1)
        return
    note("sub-vnet-ddos", len(rows))
    if not plans:
        add("low", "no-ddos-plan", "all", "0 DDoS protection plans", "public endpoints rely on platform protection only", "tenant")
        return
    for r in rows:
        if tri(dig(r, "ddos")) is not True and not dig(r, "plan"):
            add("low", "vnet-no-ddos-plan", dig(r, "name"), "enableDdosProtection=false ddosProtectionPlan=none", "the VNet is not attached to a DDoS plan", str(dig(r, "subscriptionId")))


@check("entra-risk-based-ca")
def c_risk_ca(ctx):
    pols = ca_all("policies", limit=5)
    if pols is None:
        note("entra-risk-based-ca", 0, denied=1)
        return
    enabled = [p for p in pols if str(dig(p, "state")) == "enabled"]
    note("entra-risk-based-ca", len(enabled))
    user_risk = []
    signin_risk = []
    for p in enabled:
        levels = [str(x).lower() for x in lst(dig(dig(p, "conditions"), "userRiskLevels"))]
        scores = [str(x).lower() for x in lst(dig(dig(p, "conditions"), "signInRiskLevels"))]
        if levels:
            user_risk.append(str(dig(p, "displayName")) + "(" + ",".join(levels) + ")")
        if scores:
            signin_risk.append(str(dig(p, "displayName")) + "(" + ",".join(scores) + ")")
    if not user_risk:
        add("medium", "no-user-risk-policy", "tenant", "enabledPolicies=" + str(len(enabled)), "no policy reacts to a user flagged as risky; leaked credentials stay valid")
    else:
        add("info", "user-risk-policy", "tenant", "policies=" + ",".join(user_risk)[:100], "user risk drives an enforced policy")
    if not signin_risk:
        add("medium", "no-signin-risk-policy", "tenant", "enabledPolicies=" + str(len(enabled)), "no policy reacts to a risky sign-in; impossible-travel and token-anomaly signals are ignored")
    else:
        add("info", "signin-risk-policy", "tenant", "policies=" + ",".join(signin_risk)[:100], "sign-in risk drives an enforced policy")


@check("entra-breakglass-hardening")
def c_breakglass_hardening(ctx):
    defs = graph_all("roleManagement/directory/roleDefinitions", limit=5)
    asg = graph_all("roleManagement/directory/roleAssignments", limit=5)
    pols = ca_all("policies", limit=5)
    if defs is None or asg is None:
        note("entra-breakglass-hardening", 0, denied=1)
        return
    ga = {str(dig(d, "id")) for d in defs if str(val(dig(d, "templateId"), "")).lower() == "62e90394-69f5-4237-9190-012177145e10"}
    holders = [str(dig(a, "principalId")) for a in asg if str(dig(a, "roleDefinitionId")) in ga]
    note("entra-breakglass-hardening", min(len(holders), 10))
    sample("entra-breakglass-hardening", min(len(holders), 10), len(holders), "global administrator holders read")
    exclude_counts = Counter()
    enabled_policies = 0
    for p in lst(pols):
        if str(dig(p, "state")) == "enabled":
            enabled_policies += 1
            for uid in lst(dig(p, "conditions.users.excludeUsers")):
                exclude_counts[str(uid)] += 1
    evaluated = 0
    for pid in holders[:10]:
        doc = graph("users/" + pid + "?$select=displayName,userPrincipalName,accountEnabled,onPremisesImmutableId,assignedLicenses")
        if doc is None:
            denied_now("entra-breakglass-hardening")
            continue
        evaluated += 1
        name = str(val(dig(doc, "userPrincipalName"), pid))
        label = str(val(dig(doc, "displayName"), pid))
        excluded_by = exclude_counts.get(pid, 0)
        if excluded_by and excluded_by == enabled_policies:
            add("info", "breakglass-excluded", name, "excludedFromAtLeastOneEnabledPolicy=true excludedFrom=" + str(excluded_by) + "/" + str(enabled_policies), "this administrator bypasses every enforced policy")
        elif excluded_by:
            add("medium", "breakglass-excluded-from-some-policies", name, "excludedFrom=" + str(excluded_by) + "/" + str(enabled_policies), "the emergency account still meets the remaining policies; a lost factor can lock it out")
        else:
            add("high", "breakglass-not-excluded", name, "excludedFromAtLeastOneEnabledPolicy=false policies=" + str(enabled_policies), "no emergency path: a broken policy or a lost factor locks this administrator out")
        if dig(doc, "onPremisesImmutableId"):
            add("medium", "breakglass-synced", name, "onPremisesImmutableId=" + str(dig(doc, "onPremisesImmutableId")), "the emergency account depends on the on-premises directory it is meant to survive")
        if lst(dig(doc, "assignedLicenses")):
            add("low", "breakglass-licensed", name, "assignedLicenses=" + str(len(lst(dig(doc, "assignedLicenses")))), "a licensed mailbox gives the break-glass account an extra credential path")
        methods = graph("users/" + pid + "/authentication/methods")
        if methods is None:
            denied_now("entra-breakglass-hardening")
            continue
        kinds = [str(dig(m, "@odata.type") or "").split(".")[-1] for m in lst(dig(methods, "value"))]
        strong = [k for k in kinds if k in ("fido2AuthenticationMethod", "windowsHelloForBusinessAuthenticationMethod", "x509CertificateAuthenticationMethod")]
        if not strong:
            add("high", "breakglass-no-strong-method", label, "methods=" + (",".join(kinds)[:70] or "none"), "the emergency path has no phishing-resistant factor")
    if not holders:
        add("medium", "breakglass-no-holder", "tenant", "0 Global Administrator assignments", "there is no emergency administrative path to harden")
    add("info", "breakglass-alert-not-visible", "tenant", "holders=" + str(len(holders)) + " evaluated=" + str(evaluated), "sign-in alerting on these accounts is configured in Azure Monitor, not in the directory; enable a subscription run to assess it")


@check("sub-tag-ownership")
def c_tags(ctx):
    rows = arg_rows("Resources | project name, type, subscriptionId, tags", ctx["subs"])
    if rows is None:
        note("sub-tag-ownership", 0, denied=1)
        return
    note("sub-tag-ownership", len(rows))
    missing = Counter()
    for r in rows:
        tags = dig(r, "tags")
        owner = ""
        if isinstance(tags, dict):
            for key in ("owner", "Owner", "OWNER", "ownerEmail", "businessOwner", "technicalOwner"):
                if key in tags:
                    owner = str(tags[key])
                    break
        if not owner.strip():
            missing[str(dig(r, "type")).split("/")[-1]] += 1
    total_missing = sum(missing.values())
    if not rows:
        return
    if total_missing:
        for prefix, count in missing.most_common(8):
            add("low", "resource-without-owner-tag", prefix, "resources=" + str(count), "no accountable owner is recorded on these resources", "tenant")
        add("info", "tag-coverage", "all", "resources=" + str(len(rows)) + " withoutOwner=" + str(total_missing), "ownership metadata is the basis for every other finding's remediation")
    else:
        add("info", "tag-coverage", "all", "resources=" + str(len(rows)) + " withoutOwner=0", "every resource records an owner")


def run(subs, idx, opts):
    ctx = {"subs": subs, "idx": idx, "dynamic": set(), "guests": set(), "dyn_done": False,
           "guests_done": False, "include_vms": bool(opts.get("include_vms")), "selected": opts["checks"]}
    try:
        for u in idx.users():
            if str(idx.props(u).get("userType") or "").lower() == "guest":
                ctx["guests"].add(u.get("id"))
    except DatasetUnavailable as exc:
        ctx["dataset_gap"] = str(exc)
    selected = opts["checks"]
    for name, fn in REGISTRY:
        if selected and name not in selected:
            COVERAGE[name] = {"examined": 0, "denied": 0, "status": "skipped", "detail": "--check: not selected"}
            continue
        if opts["no_az"] and name not in OFFLINE_CHECKS:
            COVERAGE[name] = {"examined": 0, "denied": 0, "status": "skipped", "detail": "--no-az: control-plane calls skipped"}
            continue
        if opts["no_entra"] and (name.startswith("entra-") or name in GRAPH_SUB_CHECKS):
            COVERAGE[name] = {"examined": 0, "denied": 0, "status": "skipped", "detail": "--no-entra: identity checks skipped"}
            continue
        if opts["no_subs"] and (name.startswith("sub-") or name in GRAPH_SUB_CHECKS):
            COVERAGE[name] = {"examined": 0, "denied": 0, "status": "skipped", "detail": "--no-subs: no subscription in scope"}
            continue
        CURRENT["check"] = name
        CURRENT["suppress"] = False
        CHECK_ERR.pop(name, None)
        idx.reset_budget()
        try:
            fn(ctx)
        except DatasetUnavailable as exc:
            c = COVERAGE.setdefault(name, {"examined": 0, "denied": 0, "status": "ok"})
            c["status"] = "partial" if c["examined"] else "absent"
            c["detail"] = str(exc)[:120]
            DATASET_GAPS.append(name)
        except Exception as exc:
            note(name, 0)
            COVERAGE.setdefault(name, {"examined": 0, "denied": 0, "status": "failed"})["status"] = "failed"
            add("medium", "check-error", name, repr(exc)[:120], "check aborted; its area is not assessed")
    return ctx


def baseline_key(f):
    return "|".join([str(f["severity"]), str(f["check"]), str(f["subject"]), str(f["subscription"]), str(f["scope"])])


def key_body(key):
    """The identity part of a baseline key: everything after the severity."""
    return key.split("|", 1)[1] if "|" in key else key


def _tee_restore(tee):
    if sys.stdout is tee:
        sys.stdout = tee.orig
    try:
        tee.close()
    except Exception:
        pass


class Tee:
    def __init__(self, path):
        self.orig = sys.stdout
        self.fh = open(path, "w", encoding="utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        sys.stdout = self.orig
        self.fh.close()
        return False

    def write(self, data):
        self.orig.write(data)
        self.fh.write(data)
        return len(data)

    def flush(self):
        self.orig.flush()
        self.fh.flush()

    def close(self):
        self.fh.close()


def _dot_label(text):
    """A graphviz-safe single-line label, truncated to keep the graph readable."""
    raw = str(text).strip()
    for old, new in (("\\", "\\\\"), ('"', "'"), ("{", "("), ("}", ")"), ("[", "("), ("]", ")"), ("\n", " ")):
        raw = raw.replace(old, new)
    return raw[:120]


def dot(path, rows=None):
    """Graphviz of the attack chains, one node per chain id and one per entity.

    Equal entity labels are one node, so paths that share an entity join. Chain
    authors keep middle labels specific to one entity; a generic middle label would
    join unrelated paths. Each chain has its own node, so the graph names the chain
    rather than only its path.
    """
    if rows is None:
        rows = [{"id": "CH-" + str(i + 1).zfill(2), "chain": c} for i, c in enumerate(CHAINS)]
    items = rows
    ids = {}
    chain_nodes = set()
    hot = set()
    edges = {}
    for row in items:
        c = row["chain"]
        cid = "c" + str(row["id"]).replace("-", "")
        chain_nodes.add(cid)
        ids[_dot_label(str(row["id"]) + " " + str(c["chain"]))] = cid
        if c["severity"] in ("critical", "high"):
            hot.add(cid)
        prev = None
        first = None
        for part in str(c["path"]).split(" -> "):
            label = _dot_label(part)
            if not label:
                continue
            nid = ids.setdefault(label, "n%d" % len(ids))
            if c["severity"] in ("critical", "high"):
                hot.add(nid)
            if first is None:
                first = nid
            if prev is not None and prev != nid:
                edges[(prev, nid)] = True
            prev = nid
        if first is not None and first != cid:
            edges[(cid, first)] = True
    lines = ["digraph chains {", "  rankdir=LR;", "  node [shape=box, fontsize=10];"]
    for label, nid in ids.items():
        shape = ", shape=note" if nid in chain_nodes else ""
        lines.append('  %s [label="%s", color=%s%s];' % (nid, label, "red" if nid in hot else "orange", shape))
    lines += ["  %s -> %s;" % e for e in edges]
    lines.append("}")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


BANNED = (
    (".get(\"", "raw field read; use a field spec with dig()"),
    ("or []", "denial collapsed into an empty list"),
    ("az([\"rest\"", "inline transport call; use arg_rows/graph"),
    ("DENIED[", "manual denial accounting"),
    ("== \"false\"", "string comparison on a boolean"),
    ("!= \"true\"", "string comparison on a boolean"),
)


def _string_literals(node):
    """The string constants an expression can evaluate to."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.IfExp):
        return _string_literals(node.body) + _string_literals(node.orelse)
    return []


TRANSPORT_RESULT_CALLS = ("graph(", "graph_all(", "arg_rows(", "arg(", "per_sub(", "ca_all(", "arm(",
                         "_kv_rows(", "_kv_vaults(", "kv_rows(", "az(", "scan_guests(", "scan_dynamic(", "_strengths(",
                         "dynamic_groups(")


def _transport_value(node):
    """True when an expression reads from the transport layer."""
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Name) and child.func.id + "(" in TRANSPORT_RESULT_CALLS:
            return True
    return False


SCOPED_CALLS = ("arg_rows", "arg")


def _query_text(node, assigned, seen=None):
    """Source text of a query argument, following assignments to a local name."""
    seen = set() if seen is None else seen
    if isinstance(node, ast.Name):
        if node.id in seen:
            return ""
        seen.add(node.id)
        parts = []
        for value in assigned.get(node.id, []):
            parts.append(ast.unparse(value).lower())
            for inner in ast.walk(value):
                if isinstance(inner, ast.Name) and inner.id in assigned:
                    parts.append(_query_text(inner, assigned, seen))
        return " ".join(parts)
    text = ast.unparse(node).lower()
    parts = [text]
    for inner in ast.walk(node):
        if isinstance(inner, ast.Name) and inner.id in assigned:
            parts.append(_query_text(inner, assigned, seen))
    return " ".join(parts)


def _own_nodes(scope):
    """Every node of a scope, without descending into a nested function or class."""
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue
        stack.extend(ast.iter_child_nodes(node))


def _unfiltered_unscoped(source):
    """(line, query) for every scoped=False call that neither filters nor is declared tenant-wide.

    A local name is resolved inside its own scope only: two checks that both call
    their query q must not answer for each other.
    """
    out = []
    tree = ast.parse(source)
    scopes = [tree] + [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for scope in scopes:
        assigned = defaultdict(list)
        for node in _own_nodes(scope):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assigned[target.id].append(node.value)
        for node in _own_nodes(scope):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id not in SCOPED_CALLS:
                continue
            for kw in node.keywords:
                if kw.arg != "scoped":
                    continue
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    continue
                query = node.args[0] if node.args else None
                if query is None:
                    continue
                text = _query_text(query, assigned)
                if "tenant_wide(" in text or "filtered_in_python(" in text:
                    continue
                if re.search(r"subscriptionid\s*(not\s+in|!in|in\b|==|=)", text):
                    continue
                out.append((node.lineno, text[:70]))
    return out


def _silent_coercions(source):
    """(line, function, shape) for every failed read turned into an empty container."""
    out = []
    tree = ast.parse(source)
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        tainted = set()
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and _transport_value(node.value):
                        tainted.add(target.id)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "lst":
                if node.args and _transport_value(node.args[0]):
                    out.append((node.lineno, fn.name, "lst of a read"))
            if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
                if _transport_value(node.values[0]) or (isinstance(node.values[0], ast.Name) and node.values[0].id in tainted):
                    for value in node.values[1:]:
                        empty = (isinstance(value, ast.List) and not value.elts) or (isinstance(value, ast.Dict) and not value.keys)
                        if empty:
                            out.append((node.lineno, fn.name, "or-empty fallback"))
            if isinstance(node, ast.If) and isinstance(node.test, ast.Compare):
                test = node.test
                left = test.left
                if not (len(test.ops) == 1 and isinstance(test.ops[0], ast.Is) and isinstance(left, ast.Name)):
                    continue
                if not (isinstance(test.comparators[0], ast.Constant) and test.comparators[0].value is None):
                    continue
                if left.id not in tainted:
                    continue
                for branch in node.body:
                    if not isinstance(branch, ast.Assign):
                        continue
                    empty = (isinstance(branch.value, ast.List) and not branch.value.elts) or (isinstance(branch.value, ast.Dict) and not branch.value.keys)
                    if empty and any(isinstance(t, ast.Name) and t.id == left.id for t in branch.targets):
                        out.append((branch.lineno, fn.name, "if None then empty"))
    return out


def _declared(source):
    """(check names, ids emitted, ids computed, note/deny names, static id severities)."""
    tree = ast.parse(source)
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name) and dec.func.id == "check":
                    lit = _string_literals(dec.args[0]) if dec.args else []
                    names.extend(lit)
    emitted = Counter()
    computed = []
    attributed = []
    static = defaultdict(set)
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            continue
        if node.func.id == "unread" and len(node.args) >= 3:
            for i in _string_literals(node.args[2]):
                emitted[i] += 1
            continue
        if node.func.id == "add" and len(node.args) >= 2:
            lit = _string_literals(node.args[1])
            if lit:
                for i in lit:
                    emitted[i] += 1
                if isinstance(node.args[0], ast.Constant) and isinstance(node.args[1], ast.Constant):
                    static[lit[0]].add(str(node.args[0].value))
            else:
                computed.append((node.lineno, ast.unparse(node.args[1])[:60]))
        elif node.func.id in ("note", "deny") and node.args:
            attributed.append((node.lineno, node.func.id, _string_literals(node.args[0])))
    return names, emitted, computed, attributed, static


def _read_baseline(path):
    """(total, {check: count}) from the ratchet file, bare integer accepted."""
    total = 0
    per = {}
    if not os.path.exists(path):
        return None, per
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh.read().splitlines():
            parts = line.split()
            if not parts:
                continue
            if parts[0] == "total" and len(parts) > 1:
                total = int(parts[1])
            elif parts[0] == "check" and len(parts) > 2:
                per[parts[1]] = int(parts[2])
            elif parts[0].isdigit():
                total = int(parts[0])
    return total, per


def _write_baseline(path, total, per):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("total " + str(total) + "\n")
        for name in sorted(per):
            fh.write("check " + name + " " + str(per[name]) + "\n")


def lint(path=None):
    path = path or os.path.abspath(__file__)
    with open(path, "r", encoding="utf-8") as fh:
        source = fh.read()
    blocks = re.split(r"(?=@check\()", source)
    rows = []
    per = Counter()
    for block in blocks:
        head_match = re.match(r'@check\("([^"]+)"\)', block)
        if not head_match:
            continue
        name = head_match.group(1)
        body = block
        head = body.find("\ndef ")
        scan = head + 1 if head >= 0 else 1
        cuts = [body.find(stop, scan) for stop in ("\ndef ", "\nclass ", "\n@")]
        cuts = [c for c in cuts if c > 0]
        if cuts:
            body = body[:min(cuts)]
        for token, why in BANNED:
            n = body.count(token)
            if n:
                rows.append((n, name, token, why))
                per[name] += n
    total = sum(r[0] for r in rows)
    rows.sort(reverse=True)
    print("lint: %d banned constructs in %d checks" % (total, len({r[1] for r in rows})))
    for n, name, token, why in rows[:25]:
        print("  %-28s %4d  %-14s %s" % (name, n, token, why))
    failures = []

    names, emitted, computed, attributed, static = _declared(source)
    known = set(names)
    for lineno, kind, lits in attributed:
        for lit in lits:
            if lit not in known:
                failures.append("phantom check id at line %d: %s(\"%s\") is not a registered check" % (lineno, kind, lit))
    if computed:
        print("lint: %d computed finding ids, checked for spelling only:" % len(computed))
        for lineno, expr in computed[:6]:
            print("  line %-5d %s" % (lineno, expr))

    for lineno, name, shape in _silent_coercions(source):
        failures.append("failed read coerced to an empty container at line %d in %s (%s); use unread() or unread_list()" % (lineno, name, shape))

    for lineno, query in _unfiltered_unscoped(source):
        failures.append("scoped=False query does not filter subscriptionId at line %d (%s); add the filter or wrap the query in tenant_wide()" % (lineno, query))

    spelled = defaultdict(set)
    for i in emitted:
        spelled[i.replace("-", "").replace("_", "")].add(i)
    for _, group in sorted(spelled.items()):
        if len(group) > 1:
            failures.append("one finding, several spellings: " + ", ".join(sorted(group)))
    for i in sorted(emitted):
        if i not in FRAMEWORK and _infer(i) == "MISC-":
            failures.append("finding id has no register tag: " + i + " (add a FRAMEWORK row)")
    for finding_id, severities in sorted(static.items()):
        if len(severities) > 1:
            failures.append("finding id carries several severities: " + finding_id + " (" + ", ".join(sorted(severities)) + "); one id is one misconfiguration at one severity")

    baseline = os.path.join(os.path.dirname(path), ".lint-baseline")
    allowed, allowed_per = _read_baseline(baseline)
    if allowed is None:
        _write_baseline(baseline, total, per)
        print("lint baseline written: " + str(total))
    elif total > allowed:
        failures.append("lint regression: %d > %d banned constructs" % (total, allowed))
    else:
        grew = [(n, per[n], allowed_per[n]) for n in sorted(per) if per[n] > allowed_per.get(n, 0)]
        if grew:
            for n, now, before in grew[:10]:
                failures.append("lint regression in %s: %d > %d" % (n, now, before))
        if total < allowed or per != allowed_per:
            _write_baseline(baseline, total, per)
            print("lint baseline tightened: " + str(allowed) + " -> " + str(total))
    if failures:
        for line in failures:
            print("lint error: " + line, file=sys.stderr)
        return 1
    return 0


def main():
    ap = argparse.ArgumentParser(description="Azure and Entra ID misconfiguration enumerator. Text report only.")
    ap.add_argument("--subs", default=os.environ.get("SUBS", ""), help="comma-separated subscription ids; defaults to SUBS or the current login")
    ap.add_argument("--azurehound", default="azurehound.json", help="AzureHound JSON export used for offline identity checks")
    ap.add_argument("--no-az", action="store_true", help="skip every control-plane check and read only the AzureHound export")
    ap.add_argument("--no-subs", action="store_true", help="tenant mode: no subscription list, every ARM check is skipped and only the Entra ID checks run")
    ap.add_argument("--tenant", default="", help="audit this tenant id explicitly; tokens are requested for it, so a guest or multi-tenant login works")
    ap.add_argument("--peer-tenant", default="", help="comma-separated other tenants this login can read; their privileged holders are compared against this tenant")
    ap.add_argument("--no-entra", action="store_true", help="skip every Entra ID and Graph check")
    ap.add_argument("--report", default="", help="write the same text report to this file")
    ap.add_argument("--dot", default="", help="write a graphviz file of the attack chains")
    ap.add_argument("--baseline", default="", help="plain-text check|subject|subscription|scope list; first run writes it, later runs print only new findings")
    ap.add_argument("--check", default="", help="comma-separated check names to run alone")
    ap.add_argument("--min-severity", default="info", choices=["critical", "high", "medium", "low", "info"], help="lowest severity to print")
    ap.add_argument("--fail-on", default="", choices=["", "critical", "high", "medium", "low", "info"], help="exit 1 when a finding at or above this severity exists")
    ap.add_argument("--list-checks", action="store_true", help="print every check name and exit")
    ap.add_argument("--lint", action="store_true", help="count banned constructs per check; exit 1 only when the count exceeds .lint-baseline")
    ap.add_argument("--strict", action="store_true", help="exit 3 when any check is partial, absent, error, truncated, throttled or failed")

    ap.add_argument("--include-vms", action="store_true", help="include VM internals: disks, JIT, extensions, custom data")
    args = ap.parse_args()

    if args.list_checks:
        for name, _ in REGISTRY:
            print(name)
        return 0

    if args.lint:
        return 1 if lint() else 0

    known = {n for n, _ in REGISTRY}
    unknown = [c for c in [x.strip() for x in args.check.split(",") if x.strip()] if c not in known]
    if unknown:
        print("unknown check: " + ",".join(unknown) + "; use --list-checks", file=sys.stderr)
        return 2

    subs = [s.strip().lower() for s in args.subs.replace("'", "").split(",") if s.strip()]
    CFG["tenant"] = str(args.tenant or "").strip().lower()
    CFG["peers"] = str(args.peer_tenant or "").strip().lower()
    if args.no_subs:
        subs = []
    elif not subs and not args.no_az and CFG["tenant"]:
        doc = az(["rest", "--url", ARM_BASE + "/subscriptions?api-version=2022-12-01"])
        found = [str(dig(v, "subscriptionId")) for v in lst(dig(doc, "value")) if str(val(dig(v, "state"), "")) != "Disabled"]
        if found:
            subs = found
            print("subscriptions discovered in tenant " + CFG["tenant"])
    elif not subs and not args.no_az:
        discovered = az(["account", "list", "--all", "--query", "[].id"])
        if discovered:
            subs = [str(s) for s in discovered]
            print("subscriptions discovered from the current login")
    if not subs and not args.no_az and not args.no_subs:
        print("no subscriptions given: set SUBS or pass --subs a,b,c, or use --no-subs for tenant-only checks", file=sys.stderr)
        return 2

    tee = None
    if args.report:
        tee = Tee(args.report)
        sys.stdout = tee
        atexit.register(_tee_restore, tee)

    if args.no_subs:
        print("scope: tenant only; no subscription is in scope")
        print("skipped: " + str(len([n for n, _ in REGISTRY if n.startswith("sub-") or n in GRAPH_SUB_CHECKS])) + " checks read subscription resources")
    else:
        print("scope: control plane for the given subscriptions" + ("; VM internals included" if args.include_vms else "; VM internals excluded, no --include-vms"))
        if args.no_az:
            skipped = [n for n, _ in REGISTRY if n not in OFFLINE_CHECKS]
            print("subscriptions: none (offline mode, azurehound only)")
            print("skipped: " + str(len(skipped)) + " checks need az; only the AzureHound export is read")
        else:
            print("subscriptions: " + str(len(subs)))
        for s in subs:
            print("  " + s)

    inv = {}
    if not args.no_az and subs and not args.no_subs:
        rows = arg_rows("Resources | where subscriptionId in (" + subq(subs) + ") | summarize n=count() by subscriptionId", subs, scoped=False)
        if rows is None:
            add("info", "inventory-unavailable", "all", "Resource Graph returned nothing", "every subscription check is not assessed", repro="az graph query -q 'Resources | summarize n=count()'")
        for r in lst(rows):
            inv[str(dig(r, "subscriptionId")).strip().lower()] = dig(r, "n")
        print("inventory: " + ", ".join(s + "=" + str(inv.get(str(s).strip().lower(), 0)) for s in subs))
        for s in subs:
            if not inv.get(str(s).strip().lower()):
                add("info", "subscription-unexamined", s, "0 resources returned", "no inventory; subscription checks are not assessed", s, repro="az graph query -q 'Resources | where subscriptionId == \"" + s + "\" | summarize n=count()'")

    if not args.no_az and not args.no_entra:
        org = graph("organization?$select=id,displayName")
        for o in lst(dig(org, "value")):
            HOME_TENANT["id"] = str(dig(o, "id")).strip().lower()
            HOME_TENANT["name"] = str(val(dig(o, "displayName"), ""))
            break
        wanted = str(args.tenant or "").strip().lower()
        if wanted:
            if HOME_TENANT["id"] and HOME_TENANT["id"] != str(wanted).strip().lower():
                print("tenant mismatch: the token resolved to " + HOME_TENANT["id"] + ", --tenant asked for " + wanted, file=sys.stderr)
                print("the login has no usable access to " + wanted + "; try: az login --tenant " + wanted, file=sys.stderr)
                return 2
            if not HOME_TENANT["id"]:
                HOME_TENANT["id"] = str(wanted).strip().lower()
                add("low", "tenant-identity-unverified", "tenant", "--tenant=" + wanted + " organization unreadable", "the results are attributed to the requested tenant but the token was not confirmed")
        if HOME_TENANT["id"]:
            print("tenant: " + HOME_TENANT["id"] + (" (" + HOME_TENANT["name"] + ")" if HOME_TENANT["name"] else ""))
    global NO_ENTRA
    NO_ENTRA = bool(args.no_entra)
    CFG["azurehound"] = args.azurehound
    try:
        nodes, ah_state, ah_detail = load_ah(args.azurehound)
        idx = Index(nodes, ah_state, ah_detail)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        idx = Index([], "unreadable", os.path.basename(str(args.azurehound)) + ": " + type(exc).__name__)
        add("low", "azurehound-unreadable", os.path.basename(str(args.azurehound)), str(type(exc).__name__) + ": " + str(exc)[:120], "the offline export was not readable; identity resolution falls back to live lookups only")
    skipped, kind_hist = idx.summary()
    if skipped:
        add("low", "azurehound-nodes-skipped", os.path.basename(str(args.azurehound)), "nodes=" + str(skipped) + " not objects", "the export contains entries that are not directory objects; they were ignored")
    if kind_hist:
        print("azurehound: " + ", ".join(k + "=" + str(v) for k, v in Counter(kind_hist).most_common(6)))
    elif idx.state != "ok":
        print("azurehound: " + idx.state + " (" + idx.detail + "); identity checks report absent")

    selected = set(x.strip() for x in args.check.split(",") if x.strip())
    run(subs, idx, {"checks": selected, "no_az": args.no_az, "no_entra": args.no_entra,
                    "no_subs": args.no_subs, "include_vms": args.include_vms})
    report_dataset_gaps()

    finalize_coverage()
    for running, written in PHANTOM:
        print("attribution: " + str(written) + " is not a registered check; booked against " + str(running), file=sys.stderr)

    seen = set()
    out_all = []
    for f in FINDINGS:
        k = (f["check"], str(f["subject"]), f["subscription"], str(f["evidence"])[:80])
        if k in seen:
            continue
        seen.add(k)
        out_all.append(f)
    floor = SEV[args.min_severity]
    out = [f for f in out_all if SEV[f["severity"]] <= floor]
    out.sort(key=lambda f: (SEV[f["severity"]], -f["score"], f["subscription"], f["check"]))
    chains = [c for c in CHAINS if SEV[c["severity"]] <= floor]
    ordered = sorted(chains, key=lambda c: (SEV[c["severity"]], str(c["chain"]), str(c["path"])))
    chain_rows = [{"id": "CH-" + str(i + 1).zfill(2), "chain": c} for i, c in enumerate(ordered)]
    chains_by_check = defaultdict(list)
    for row in chain_rows:
        chains_by_check[str(row["chain"]["source"])].append(str(row["id"]))

    if args.baseline:
        keys = sorted({baseline_key(f) for f in out_all} | {"chain|" + str(c["severity"]) + "|" + str(c["chain"]) + "|" + str(c["path"]) for c in CHAINS})
        prior = set()
        if os.path.exists(args.baseline):
            with open(args.baseline, "r", encoding="utf-8") as fh:
                prior = set(fh.read().splitlines())
        examined = [c for c in COVERAGE.values() if c["status"] in ("ok", "empty", "truncated", "partial", "sampled")]
        partial_run = bool(args.check or args.no_az or args.no_entra or args.no_subs
                           or args.include_vms or CFG.get("peers"))
        if not partial_run and not examined:
            written = sorted(prior)
            blocked = True
        else:
            written = sorted(set(keys) | prior) if partial_run else keys
            blocked = False
        kept = set(written)
        if prior:
            fresh = [k for k in keys if k not in prior]
            gone = [k for k in sorted(prior) if k not in set(keys)]
            prior_body = {key_body(k) for k in prior}
            moved = [k for k in fresh if key_body(k) in prior_body]
            resolved = [k for k in gone if key_body(k) not in {key_body(x) for x in keys} and k not in kept]
            print("")
            print("=== new since baseline: " + str(len(fresh) - len(moved)) + " ===")
            for k in fresh:
                if k not in moved:
                    print("  " + k)
            if moved:
                print("=== severity changed since baseline: " + str(len(moved)) + " ===")
                for k in moved:
                    print("  " + k)
            if resolved:
                print("=== resolved since baseline: " + str(len(resolved)) + " ===")
                for k in resolved:
                    print("  " + k)
        if blocked:
            print("")
            print("baseline not updated: no check completed, so an empty baseline would erase the prior state")
        elif partial_run:
            print("")
            print("baseline merged, not replaced: partial scope selected")
        with open(args.baseline, "w", encoding="utf-8") as fh:
            fh.write("\n".join(written) + "\n")
        print("")
        print("baseline updated: " + args.baseline + " (" + str(len(prior)) + " -> " + str(len(written)) + " keys)")

    if not AZ_OK:
        print("\nblind spot: az cli missing or unreachable; every control-plane result below is unexamined")

    print("\n=== coverage ===")
    print("%-28s %-9s %8s %7s" % ("CHECK", "STATUS", "EXAMINED", "DENIED"))
    for name, _ in REGISTRY:
        if name not in COVERAGE:
            continue
        c = COVERAGE[name]
        print("%-28s %-9s %8d %7d" % (name, c["status"], c["examined"], c["denied"]))
    missing = [n for n, _ in REGISTRY if n not in COVERAGE]
    if missing:
        print("not run: " + ",".join(missing))
    for path in TRUNCATED[:20]:
        print("truncated: " + str(path)[:100])
    if len(TRUNCATED) > 20:
        print("truncated: " + str(len(TRUNCATED) - 20) + " more pages not followed")
    blind = [(n, COVERAGE[n]["status"], COVERAGE[n]["denied"]) for n in COVERAGE if COVERAGE[n]["status"] in ("partial", "error", "absent", "truncated", "failed", "degraded", "throttled")]
    print("\n=== blind spots ===")
    if not blind:
        print("none: every executed check returned a usable response")
    for n, st, d in sorted(blind):
        print("%-30s %-8s denied=%-3d %s" % (n, st, d, COVERAGE[n].get("detail", "")))

    print("\n=== by subscription ===")
    print("%-40s %5s %5s %6s %5s %7s" % ("SUBSCRIPTION", "CRIT", "HIGH", "MED", "LOW", "RES"))
    by_sub = Counter()
    for f in out:
        by_sub[(str(f["subscription"]).strip().lower(), f["severity"])] += 1
    for s in subs + ["tenant"]:
        key = str(s).strip().lower()
        c = Counter({sev: by_sub[(key, sev)] for sev in SEV if by_sub[(key, sev)]})
        print("%-40s %5d %5d %6d %5d %7s" % (s, c.get("critical", 0), c.get("high", 0), c.get("medium", 0), c.get("low", 0), inv.get(key, "-")))

    print("\n=== findings ===")
    print("%-9s %3s %-14s %-32s %-32s %s" % ("SEV", "SCR", "SUBSCRIPTION", "CHECK", "SUBJECT", "EVIDENCE"))
    for f in out:
        print("%-9s %3s %-14s %-32s %-32s %s" % (f["severity"], f["score"], str(f["subscription"])[:14], f["check"][:32], str(f["subject"])[:32], f["evidence"][:70]))

    if chain_rows:
        print("\n=== chains ===")
        print("chains: " + str(len(chain_rows)) + "; each id is repeated in the findings below")
        for row in chain_rows:
            c = row["chain"]
            print(row["id"] + " " + c["severity"] + " " + c["chain"] + " [" + str(c["source"]) + "]: " + c["path"])


    lines = []
    cur_sub = None
    for f in sorted(out, key=lambda x: (str(x["subscription"]), SEV[x["severity"]], -x["score"], x["check"])):
        if f["subscription"] != cur_sub:
            cur_sub = f["subscription"]
            lines.append("")
            lines.append("#" * 100)
            lines.append("# SUBSCRIPTION / SCOPE: " + str(cur_sub))
            lines.append("#" * 100)
        lines.append("")
        lines.append("[%s] %s   (%s %s, score %s)" % (f["severity"].upper(), f["check"], f["register"], f["cwe"], f["score"]))
        lines.append("  subject  : " + str(f["subject"]))
        lines.append("  scope    : " + str(f["scope"]))
        lines.append("  evidence : " + str(f["evidence"]))
        lines.append("  why      : " + str(f["why"]))
        lines.append("  repro    : " + str(f["repro"]))
        linked = chains_by_check.get(str(f["source"]))
        if linked:
            lines.append("  chains   : " + ", ".join(linked))
    print("\n".join(lines))

    if chains:
        print("")
        print("#" * 100)
        print("# ATTACK CHAINS")
        print("#" * 100)
        for row in chain_rows:
            c = row["chain"]
            print("")
            print("[%s] %s %s" % (c["severity"].upper(), row["id"], c["chain"]))
            print("  check: " + str(c["source"]))
            print("  path : " + c["path"])
            print("  why  : " + c["why"])

    if args.dot:
        dot(args.dot, chain_rows)
        print("\nwrote " + args.dot + " (" + str(len(chain_rows)) + " chains)")

    if tee is not None:
        _tee_restore(tee)
        print("report written: " + args.report + " (" + str(len(out)) + " findings, " + str(len(chains)) + " chains)")

    if args.fail_on:
        limit = SEV[args.fail_on]
        if any(SEV[f["severity"]] <= limit for f in out_all) or any(SEV[c["severity"]] <= limit for c in CHAINS):
            return 1
    if args.strict:
        bad = [n for n, c in COVERAGE.items() if c.get("status") in ("partial", "absent", "error", "truncated", "failed", "degraded", "throttled")]
        if bad:
            print("\nstrict: " + str(len(bad)) + " checks did not complete cleanly", file=sys.stderr)
            return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
