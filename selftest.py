"""Failure-path self-test: every transport read returns None, no verdict may follow.

Run: python3 selftest.py
Exit 0 when a total read failure produces no medium, high or critical finding.
"""
import importlib.util
import io
import os
import sys
import contextlib

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("enumerate_entra", os.path.join(HERE, "enumerate-entra.py"))
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)

ALLOWED = {
    "check-error",
}

SAMPLE_NODES = [
    {"kind": "AZUser", "id": "u1", "properties": {"displayName": "User One", "userPrincipalName": "u1@example.com", "accountEnabled": True}},
    {"kind": "AZGroup", "id": "g1", "properties": {"displayName": "Group One"}},
    {"kind": "AZServicePrincipal", "id": "s1", "properties": {"displayName": "SP One", "appId": "a1"}},
]


def invariants():
    """Assertions on the value-level conventions the checks rely on."""
    M.HOME_TENANT["id"] = ""
    assert M.tenant_rel("11111111-1111-1111-1111-111111111111") == "unknown"
    assert M.same_tenant("11111111-1111-1111-1111-111111111111") is False
    M.HOME_TENANT["id"] = "11111111-1111-1111-1111-111111111111"
    assert M.tenant_rel("11111111-1111-1111-1111-111111111111") == "home"
    assert M.tenant_rel("22222222-2222-2222-2222-222222222222") == "foreign"
    assert M.tenant_rel("") == "unknown"
    assert M.is_any_text("") is False
    assert M.any_source("") is False
    assert M.any_source("0.0.0.0/0") is True
    assert M.any_source("::/0") is True
    assert M.port_span("") is None
    assert M.port_span("*") == (0, 65535)
    guid = "00000000-0000-0000-0000-00000000000a"
    assert M._owner(None, "/subscriptions/" + guid + "/x", "tenant") == guid
    assert M._owner(None, "name-only", "tenant") == ""
    assert M._owner("explicit", "name-only", "tenant") == "explicit"
    M.HOME_TENANT["id"] = ""
    # An undecided comparison books a denial, so the check cannot report ok.
    reset()
    M.CURRENT["check"] = "entra-cba-config"
    M.undecided("lighthouse-tenant-unknown", "x", "y")
    assert M.DENIED["entra-cba-config"] == 1
    # A denial from a direct az() call is booked once by denied_now().
    reset()
    M.CURRENT["check"] = "sub-keyvault-logs"
    M.LAST_ERROR.update(kind="denied", detail="403", booked="")
    M.denied_now("sub-keyvault-logs")
    assert M.DENIED["sub-keyvault-logs"] == 1
    # A denial the transport already booked is not booked again.
    reset()
    M.CURRENT["check"] = "entra-apps"
    M.LAST_ERROR.update(kind="denied", detail="403", booked="")
    M.mark_failure()
    M.denied_now("entra-apps")
    assert M.DENIED["entra-apps"] == 1
    reset()


def fail_all():
    def none(*a, **k):
        return None
    for name in ("az", "graph", "graph_all", "arg_rows", "arg", "ca_all", "arm"):
        if hasattr(M, name):
            setattr(M, name, none)


def reset():
    for table in (M.FINDINGS, M.CHAINS, M.PHANTOM, M.DATASET_GAPS):
        table.clear()
    M.FINDING_KEYS.clear()
    M.COVERAGE.clear()
    M.DENIED.clear()
    M.EXHAUSTED.clear()
    M.PARSE.clear()
    M.TRUNC_CHECKS.clear()
    M.GUEST_PARTIAL.clear()
    M.LAST_ERROR.clear()
    M.LAST_QUERY.clear()
    M.DATASET_NOTED["done"] = False
    M.CURRENT["check"] = ""
    M.CURRENT["suppress"] = False


def main():
    invariants()
    fail_all()
    idx = M.Index(list(SAMPLE_NODES))
    offenders = []
    unclean = []
    raised = []
    for name, fn in M.REGISTRY:
        reset()
        M.CURRENT["check"] = name
        ctx = {"subs": ["00000000-0000-0000-0000-000000000001"], "idx": idx, "dynamic": set(),
               "guests": set(), "dyn_done": False, "guests_done": False, "include_vms": True,
               "selected": []}
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                fn(ctx)
        except Exception as exc:
            raised.append((name, repr(exc)[:80]))
            continue
        for finding in M.FINDINGS:
            if M.SEV[finding["severity"]] <= M.SEV["medium"] and finding["check"] not in ALLOWED:
                offenders.append((name, finding["severity"], finding["check"]))
        coverage = M.COVERAGE.get(name)
        if name in M.OFFLINE_CHECKS:
            continue
        if coverage and coverage["status"] in ("ok", "empty") and not M.FINDINGS:
            unclean.append((name, coverage["status"]))
    if raised:
        print("checks that raised on a failed read: " + str(len(raised)))
        for name, why in raised:
            print("  " + name + ": " + why)
    if offenders:
        print("findings at medium or above from a failed read: " + str(len(offenders)))
        for name, sev, finding in offenders:
            print("  " + name + ": " + sev + " " + finding)
    if unclean:
        print("checks that claimed a clean result with nothing read: " + str(len(unclean)))
        for name, status in unclean:
            print("  " + name + " status=" + status)
    if not (raised or offenders or unclean):
        print("ok: " + str(len(M.REGISTRY)) + " checks, failed reads produced no verdict")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
