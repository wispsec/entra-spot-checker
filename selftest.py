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
assert spec and spec.loader, "enumerate-entra.py not found next to selftest.py"
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


class _Proc:
    def __init__(self, code):
        self.returncode = 0 if code == 200 else 1
        self.stdout = '{"value": []}' if code == 200 else ""
        self.stderr = {200: "", 403: "(403) Forbidden", 404: "(404) ResourceNotFound", 500: "unexpected failure"}[code]


def _run(name, ctx, **fakes):
    """Run one check with module functions replaced, then restore them."""
    keep = {k: getattr(M, k) for k in fakes}
    reset()
    M.CHECK_ERR.clear()
    M.CURRENT["check"] = name
    try:
        for k, v in fakes.items():
            setattr(M, k, v)
        with contextlib.redirect_stdout(io.StringIO()):
            dict(M.REGISTRY)[name](ctx)
    finally:
        for k, v in keep.items():
            setattr(M, k, v)
    return {f["check"] for f in M.FINDINGS}


def regressions():
    """Semantic cases the failure-path sweep cannot see."""
    real_run = M.subprocess.run
    subs = ["00000000-0000-0000-0000-00000000000" + str(i) for i in range(1, 4)]
    # A denied subscription next to a readable one is partial, not a transport error.
    expect = {(403, 200): "partial", (200, 403): "partial", (404, 200): "partial",
              (200, 404): "partial", (403, 404, 200): "partial", (500, 200): "error"}
    try:
        for codes, want in expect.items():
            seq = iter(codes)
            M.subprocess.run = lambda *a, **k: _Proc(next(seq))
            _run("sub-diagnostics", {"subs": subs[:len(codes)]})
            got = M.COVERAGE["sub-diagnostics"]["status"]
            assert got == want, "per_sub " + str(codes) + " status=" + got + " want " + want
    finally:
        M.subprocess.run = real_run
    # Conditional Access bypass findings need an enforced policy.
    bypass = {"ca-exclusion-dynamic-group", "ca-all-trusted-locations-excluded", "ca-named-location-excluded",
              "ca-device-filter"}
    idx = M.Index(list(SAMPLE_NODES))
    for state, fires in (("disabled", False), ("enabledForReportingButNotEnforced", False), ("enabled", True)):
        pol = {"state": state, "displayName": "p", "conditions": {
            "users": {"excludeGroups": ["g1"]}, "locations": {"excludeLocations": ["AllTrusted", "loc1"]},
            "devices": {"deviceFilter": {"mode": "exclude", "rule": "x"}}}}
        got = _run("entra-ca", {"dyn_done": True, "dynamic": {"g1"}, "dyn": {"g1": "guest"}, "idx": idx},
                   ca_all=lambda *a, **k: [pol], graph_all=lambda *a, **k: [])
        assert (got >= bypass) if fires else not (got & bypass), state + " " + str(sorted(got & bypass))
        assert fires or not M.CHAINS, state + " produced an attack chain"
    # A field that only beta returns is merged onto the v1.0 row, never read from v1.0.
    real_graph_all = M.graph_all
    M.CA_BETA["state"] = ""
    M.CA_BETA["policies"] = {}
    v10 = [{"id": "p1", "displayName": "p", "conditions": {}, "sessionControls": {}, "grantControls": {}}]
    brows = [{"id": "p1", "conditions": {"deviceStates": {"includeStates": ["All"]}},
              "sessionControls": {"secureSignInSession": {"isEnabled": True},
                                  "continuousAccessEvaluation": {"isEnabled": True}},
              "grantControls": {"authenticationStrength": {"id": "s1"}}}]
    try:
        M.graph_all = lambda path, limit=25, beta=False, max_pages=None: brows if beta else v10
        assert M._merge_ca_beta(v10, 5) is True
    finally:
        M.graph_all = real_graph_all
    assert v10[0]["conditions"]["deviceStates"]["includeStates"] == ["All"], v10
    assert v10[0]["sessionControls"]["secureSignInSession"]["isEnabled"] is True, v10
    assert v10[0]["grantControls"]["authenticationStrength"]["id"] == "s1", v10
    M.CA_BETA["state"] = ""
    M.CA_BETA["policies"] = {}
    # User actions live under applications, not under conditions.
    pol = {"state": "enabled", "displayName": "p",
           "conditions": {"users": {"excludeRoles": ["r1"]},
                          "applications": {"includeUserActions": ["urn:user:registersecurityinfo"]}}}
    _run("entra-ca", {"idx": idx, "dynamic": set(), "dyn_done": True},
         ca_all=lambda *a, **k: [pol], graph_all=lambda *a, **k: [], licensed=lambda p: False)
    hits = [f for f in M.FINDINGS if f["check"] == "ca-user-action-policy"]
    assert hits and hits[0]["severity"] == "high", M.FINDINGS
    # Device states are a condition-set property, not a device-filter property.
    pol = {"state": "enabled", "displayName": "p",
           "conditions": {"deviceStates": {"includeStates": ["Compliant"]}}}
    got = _run("entra-ca-scope-detail", {"idx": idx, "dynamic": set()},
               ca_all=lambda *a, **k: [pol], graph_all=lambda *a, **k: None)
    assert "ca-device-state-restricted" in got, got
    # Token protection is read from the merged beta field, and its absence is not a verdict.
    pol = {"state": "enabled", "displayName": "p",
           "sessionControls": {"secureSignInSession": {"isEnabled": True}}}
    M.CA_BETA["state"] = "ok"
    got = _run("entra-ca-session", {"idx": idx}, ca_all=lambda *a, **k: [pol])
    assert "session-token-protection" in got and "no-token-protection" not in got, got
    M.CA_BETA["state"] = "failed"
    bare = {"state": "enabled", "displayName": "p", "sessionControls": {}}
    got = _run("entra-ca-session", {"idx": idx}, ca_all=lambda *a, **k: [bare])
    assert "no-token-protection" not in got and "ca-session-control-unread" in got, got
    M.CA_BETA["state"] = ""
    # A strength-based policy is not a missing MFA policy.
    pol = {"state": "enabled", "displayName": "p",
           "conditions": {"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": ["All"]}},
           "grantControls": {"authenticationStrength": {"id": "s1"}}}
    got = _run("entra-mfa-baseline", {"idx": idx}, ca_all=lambda *a, **k: [pol],
               graph=lambda *a, **k: {"isEnabled": False},
               _strengths=lambda: {"s1": ("Phishing resistant", ["password,fido2"])})
    assert "mfa-not-required-for-all" not in got, got
    # A grant control that could not be read is not a verdict either.
    pol = {"state": "enabled", "displayName": "p",
           "conditions": {"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": ["All"]}},
           "grantControls": {}}
    got = _run("entra-mfa-baseline", {"idx": idx}, ca_all=lambda *a, **k: [pol],
               graph=lambda *a, **k: {"isEnabled": False}, _strengths=lambda: {})
    assert "mfa-not-required-for-all" not in got and "mfa-control-unread" in got, got
    reset()
    # A property the API did not return is unknown, never off.
    rows = [{"name": "v", "subscriptionId": subs[0], "soft": "Enabled", "enhanced": "", "immut": ""}]
    got = _run("sub-backup-rsv-posture", {"subs": subs}, arg_rows=lambda *a, **k: rows)
    assert not got & {"rsv-immutability-off", "rsv-enhanced-softdelete-off"}, sorted(got)
    assert {"rsv-immutability-unknown", "rsv-enhanced-softdelete-unknown"} <= got, sorted(got)
    rows = [{"name": "v", "subscriptionId": subs[0], "enhanced": "Disabled", "immut": "Unlocked"}]
    got = _run("sub-backup-rsv-posture", {"subs": subs}, arg_rows=lambda *a, **k: rows)
    assert {"rsv-immutability-off", "rsv-enhanced-softdelete-off"} <= got, sorted(got)
    rows = [{"name": "b", "subscriptionId": subs[0], "type": "microsoft.dataprotection/backupvaults", "props": {}}]
    got = _run("sub-backup", {"subs": subs}, arg_rows=lambda *a, **k: rows)
    assert not got & {"backup-immutability-off", "backup-no-multi-user-auth"}, sorted(got)
    # Backup vault immutability lives under securitySettings; MUA is a Resource Guard.
    for props, want in (({"securitySettings": {"immutabilitySettings": {"state": "Locked"}}, "isVaultProtectedByResourceGuard": True}, set()),
                        ({"securitySettings": {"immutabilitySettings": {"state": "Disabled"}}, "isVaultProtectedByResourceGuard": False},
                         {"backup-immutability-off", "backup-no-multi-user-auth"})):
        rows = [{"name": "b", "subscriptionId": subs[0], "type": "microsoft.dataprotection/backupvaults", "props": props}]
        got = _run("sub-backup", {"subs": subs}, arg_rows=lambda *a, **k: rows) & {
            "backup-immutability-off", "backup-immutability-unknown", "backup-no-multi-user-auth", "backup-mua-unknown"}
        assert got == want, sorted(got)
    rows = [{"name": "a", "subscriptionId": subs[0], "localAuth": ""}]
    got = _run("sub-appinsights-keys", {"subs": subs}, arg_rows=lambda *a, **k: rows)
    assert "appinsights-local-auth" not in got and "appinsights-local-auth-unknown" in got, sorted(got)
    # App owner takeover: granted dangerous Graph permissions decide, not requested ones.
    human = {"value": [{"id": "u", "userPrincipalName": "dev@example.com"}]}
    table = {
        "servicePrincipals?$filter=appId eq '" + M.GRAPH_APP_ID: {"value": [{"id": "gsp", "appRoles": [
            {"id": "r-role", "value": "RoleManagement.ReadWrite.Directory"},
            {"id": "r-read", "value": "User.Read.All"},
            {"id": "r-group", "value": "Group.ReadWrite.All"}]}]},
        "servicePrincipals/sp-tier0?": {"appId": "a-tier0", "displayName": "Tier0App", "servicePrincipalType": "Application"},
        "servicePrincipals/sp-tier0/owners": {"value": []},
        "applications(appId='a-tier0')/owners": human,
        "servicePrincipals/sp-group?": {"appId": "a-group", "displayName": "GroupApp", "servicePrincipalType": "Application"},
        "servicePrincipals/sp-group/owners": "denied",
        "applications(appId='a-group')/owners": "absent",
        "applications(appId='a-requested')/owners": human,
        "servicePrincipals?$filter=appId eq '00000002-0000-0ff1-ce00": {"value": [{"id": "exo", "appRoles": [
            {"id": "r-exo", "value": "full_access_as_app"}]}]},
        "servicePrincipals?$filter=appId eq '00000003-0000-0ff1-ce00": {"value": []},
        "servicePrincipals/sp-mail?": {"appId": "a-mail", "displayName": "MailApp", "servicePrincipalType": "Application"},
        "servicePrincipals/sp-mail/owners": human,
        "applications(appId='a-mail')/owners": "absent",
    }

    def fake_graph(path, *a, **k):
        hit = next((v for p, v in table.items() if path.startswith(p)), "absent")
        if isinstance(hit, str):
            M.LAST_ERROR.update(kind=hit, detail=hit, booked="")
            return None
        return hit

    def fake_graph_all(path, *a, **k):
        if path.startswith("applications?"):
            return [{"appId": "a-requested", "displayName": "RequestedOnly", "requiredResourceAccess": [
                {"resourceAppId": M.GRAPH_APP_ID, "resourceAccess": [{"type": "Role"}] * 3}]}]
        if path.startswith("servicePrincipals/exo/"):
            return [{"principalId": "sp-mail", "principalType": "ServicePrincipal", "appRoleId": "r-exo"}]
        return [{"principalId": "sp-tier0", "principalType": "ServicePrincipal", "appRoleId": "r-role"},
                {"principalId": "sp-read", "principalType": "ServicePrincipal", "appRoleId": "r-read"},
                {"principalId": "sp-group", "principalType": "ServicePrincipal", "appRoleId": "r-group"}]
    _run("entra-app-hygiene", {}, graph=fake_graph, graph_all=fake_graph_all)
    assert not [f for f in M.FINDINGS if f["check"] == "high-priv-app-owned-by-human"], "requested-only app flagged"
    _run("entra-privileged-sps", {}, graph=fake_graph, graph_all=fake_graph_all)
    hits = {(f["check"], str(f["subject"]), f["severity"]) for f in M.FINDINGS if f["check"].startswith(("high-priv-app", "app-owner-takeover"))}
    assert hits == {("high-priv-app-owned-by-human", "Tier0App", "critical"),
                    ("high-priv-app-owned-by-human", "MailApp", "high"),
                    ("app-owner-takeover-unassessed", "GroupApp", "info")}, sorted(hits)
    assert len(M.CHAINS) == 2 and M.DENIED["entra-privileged-sps"] == 1, (M.CHAINS, M.DENIED)
    assert M.COVERAGE["entra-privileged-sps"]["examined"] == 4
    assert "entra-privileged-sps" not in M.OFFLINE_CHECKS
    # Dynamic rules: who can steer membership.
    steer = {
        'user.mail -contains "partner"': "guest",
        '(user.mail -contains "partner") -and (user.userType -eq "Member")': "privileged",
        'user.otherMails -any (_ -contains "contoso")': "guest",
        'user.mail -eq "a@b.com"': "privileged",
        'user.department -eq "IT"': "privileged",
        'user.objectId -ne null': "guest",
        'user.objectId -ne null -and user.userType -eq "Member"': "guest",
        '(user.dirSyncEnabled -ne true) and (user.displayName -Contains "Admin")': "guest",
        'user.department -ne "IT"': "guest",
        'user.employeeType -ne "Contractor"': "guest",
        'user.accountEnabled -ne true': "guest",
        'user.department -eq "IT" -and user.employeeType -ne "Contractor"': "privileged",
        'user.userType -eq "Guest"': "guest",
        'device.displayName -startsWith "SEC-"': "device",
        'device.displayName -startsWith "SEC-" -and device.deviceOwnership -eq "Company"': "privileged",
        'user.extension_abc123_team -eq "red"': "privileged",
        'user.extensionAttribute5 -eq "VIP"': "privileged",
        'user.customSecurityAttributes.Engineering_Project -eq "Baker"': "privileged",
        'device.extensionAttribute1 -eq "PAW"': "privileged",
        '(user.department -eq "IT") -or (user.mail -contains "x")': "guest",
        'user.objectId -eq "11111111-1111-1111-1111-111111111111"': "fixed",
        '(user.userType -eq "Member") -or (user.mail -contains "x")': "guest",
        'user.accountEnabled -eq true': "guest",
        'user.accountEnabled -eq false': "privileged",
        'device.accountEnabled -eq false': "privileged",
        # -and binds tighter than -or: an open -or branch decides.
        '(user.mail -contains "x") -or (user.department -eq "IT" -and user.userType -eq "Member")': "guest",
        'user.department -eq "IT" -or user.mail -contains "x" -and user.userType -eq "Member"': "privileged",
        '(user.mail -contains "x" -or user.displayName -startsWith "p") -and user.userType -eq "Member"': "privileged",
        'user.userType -ne "Member"': "guest",
        'user.userType -eq "Member"': "privileged",
        '(user.department -eq "IT")\n-or\n(user.mail -contains "x")': "guest",
        '(user.mail -contains "x") -and (user.userType -in ["Member"])': "privileged",
        'user.userType -in ["Guest"]': "guest",
        'user.assignedPlans -any (assignedPlan.servicePlanId -eq "x" -and assignedPlan.capabilityStatus -eq "Enabled")': "privileged",
    }
    for rule, want in steer.items():
        assert M.rule_steer(rule)[0] == want, rule + " -> " + M.rule_steer(rule)[0] + " want " + want
    # Without an AzureHound export the CA check still runs and reads rules live.
    nodes, state, detail = M.load_ah("/nonexistent-azurehound.json")
    no_idx = M.Index(nodes, state, detail)
    dyn_rows = [{"id": "g1", "displayName": "Partners", "membershipRule": 'user.mail -contains "partner"'},
                {"id": "g2", "displayName": "IT", "membershipRule": 'user.department -eq "IT"'},
                {"id": "g3", "displayName": "Frozen", "membershipRule": 'user.department -eq "HR"', "membershipRuleProcessingState": "Paused"}]

    def dyn_graph_all(path, *a, **k):
        return dyn_rows if "DynamicMembership" in path else []
    pol = {"state": "enabled", "displayName": "MFA all", "conditions": {"users": {"excludeGroups": ["g1", "g2"]}}}
    got = _run("entra-ca", {"subs": [], "idx": no_idx, "dynamic": set()}, ca_all=lambda *a, **k: [pol],
               graph_all=dyn_graph_all, graph=lambda *a, **k: {"value": []})
    hits = [f for f in M.FINDINGS if f["check"] == "ca-exclusion-dynamic-group"]
    assert len(hits) == 1 and hits[0]["severity"] == "high", hits
    assert "Partners steer=guest" in hits[0]["evidence"] and "IT steer=privileged" in hits[0]["evidence"], hits[0]["evidence"]
    assert [c["chain"] for c in M.CHAINS] == ["attribute-to-ca-bypass"], M.CHAINS
    # No subscription in scope: RBAC unread, so the evidence must not claim the group grants nothing.
    ev = [f["evidence"] for f in M.FINDINGS if f["check"] == "dynamic-group-steerable" and f["subject"] == "Partners"]
    assert ev and "grants=not assessed" in ev[0], ev
    # Capability decides severity: a guest-steerable group holding Owner is critical.
    owner = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"

    def dyn_arg_rows(query, subs, scoped=True):
        if "roledefinitions" in query:
            return [{"id": "/providers/microsoft.authorization/roledefinitions/" + owner, "name": "Owner",
                     "perms": [{"actions": ["*"], "notActions": []}]}]
        return [{"principalId": gid, "roleId": "/subscriptions/s1/providers/microsoft.authorization/roledefinitions/" + owner,
                 "scope": "/subscriptions/s1"} for gid in ("g1", "g2")]
    got = _run("entra-dynamic-groups", {"subs": ["s1"], "idx": no_idx, "dynamic": set()}, graph_all=dyn_graph_all,
               graph=lambda *a, **k: {"value": []}, arg_rows=dyn_arg_rows)
    sev = {(f["check"], f["subject"]): f["severity"] for f in M.FINDINGS}
    assert sev == {("dynamic-group-steerable", "Partners"): "critical", ("dynamic-group-steerable", "IT"): "medium",
                   ("dynamic-group-processing-paused", "Frozen"): "low"}, sev
    assert [c["chain"] for c in M.CHAINS] == ["dynamic-group-to-capability"], M.CHAINS
    # A failed rule read draws no attribute-usage verdict.
    got = _run("entra-custom-security-attributes", {"idx": no_idx},
               graph_all=lambda path, *a, **k: [{"name": "Clearance"}] if "customSecurity" in path else None)
    assert "csa-unused" not in got and "csa-usage-unassessed" in got, sorted(got)
    # Every reader of the export fallback is partial, not only the one that saw the live failure.
    ah_idx = M.Index([{"kind": "AZGroup", "id": "g9", "properties": {"displayName": "Dyn", "membershipRule": 'user.department -eq "x"'}}])
    shared = {"subs": [], "idx": ah_idx, "dynamic": set()}
    def denied_rules(path, *a, **k):
        if "customSecurity" in path:
            return [{"name": "x"}]
        M.LAST_ERROR.update(kind="denied", detail="403", booked="")
        return None
    _run("entra-custom-security-attributes", shared, graph_all=denied_rules)
    assert M.DENIED["entra-custom-security-attributes"] >= 1
    shared["subs"] = ["s1"]
    _run("entra-dynamic-groups", shared, graph_all=lambda *a, **k: None, graph=lambda *a, **k: {"value": []},
         arg_rows=lambda *a, **k: [])
    assert M.DENIED["entra-dynamic-groups"] == 1, M.DENIED
    # A check that reads the classification through scan_dynamic is partial on the fallback too.
    fresh = {"subs": [], "idx": ah_idx, "dynamic": set()}
    def denied_dyn_only(path, *a, **k):
        return denied_rules(path) if "DynamicMembership" in path else []
    _run("entra-ca", fresh, graph_all=denied_dyn_only, graph=lambda *a, **k: {"value": []},
         ca_all=lambda *a, **k: [{"state": "enabled", "displayName": "p", "conditions": {"users": {"excludeGroups": ["g9"]}}}])
    assert M.DENIED["entra-ca"] >= 1, M.DENIED
    # Two groups sharing a display name stay two nodes.
    same = {"dyn_rules": {"aaaaaaaa-1": ("IT", "", ""), "bbbbbbbb-2": ("IT", "", "")}}
    assert M.group_node(same, "aaaaaaaa-1") != M.group_node(same, "bbbbbbbb-2")
    # Dot: equal labels are one node, so paths through one group join.
    import tempfile
    reset()
    M.chain("a", "anyone who can invite a guest -> group Partners -> Owner on /subscriptions/s1", "critical", "x")
    M.chain("b", "anyone who can invite a guest -> group Partners -> excluded from MFA all", "high", "x")
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "c.dot")
        M.dot(path)
        text = open(path, encoding="utf-8").read()
    edges = [line for line in text.splitlines() if "->" in line and "tooltip" not in line]
    assert text.count('tooltip="') == 6 and len(edges) == 5, text
    assert "CH-01 a:" in text and "CH-02 b:" in text, text
    # The two shared hops stay one node each, not one node per chain.
    assert text.count('tooltip="anyone who can invite a guest"') == 1, text
    assert text.count('tooltip="group Partners"') == 1, text
    reset()
    # A peer-tenant truncation stays labelled with its tenant and stays on the peer check.
    reset()
    M.TRUNCATED[:] = ["users"]
    M.CURRENT["check"] = "entra-peer-tenant-privilege"
    peer = "33333333-3333-3333-3333-333333333333"

    def collect():
        M.TRUNCATED.append("users")
        M.TRUNC_CHECKS.add(M.CURRENT["check"])
    keep_name = M.tenant_name
    setattr(M, "tenant_name", lambda t: "")
    try:
        M.with_tenant(peer, collect)
    finally:
        setattr(M, "tenant_name", keep_name)
    assert M.TRUNCATED == ["users", "tenant " + peer + ": users"], M.TRUNCATED
    assert "entra-peer-tenant-privilege" in M.TRUNC_CHECKS
    M.TRUNCATED.clear()
    reset()
    # An exclusion that resolves to an emergency account is the intended state.
    bg_idx = M.Index([{"kind": "AZUser", "id": "bg1", "properties": {"displayName": "Break Glass"}},
                      {"kind": "AZUser", "id": "u1", "properties": {"displayName": "User One"}}], "ok")

    def ca_excl(excl):
        return [{"state": "enabled", "displayName": "p",
                 "conditions": {"users": {"includeUsers": ["All"], "excludeUsers": excl},
                                "applications": {"includeApplications": ["All"]}},
                 "grantControls": {"builtInControls": ["mfa"]}}]

    got = _run("entra-ca", {"subs": [], "idx": bg_idx, "dynamic": set()}, ca_all=lambda *a, **k: ca_excl(["bg1"]),
               scan_dynamic=lambda c: None, graph_all=lambda *a, **k: [], licensed=lambda plans: False)
    assert "ca-policy-has-exclusions" not in got, got
    assert "ca-risk-not-licensed" in got and "ca-no-risk-conditions" not in got, got
    got = _run("entra-ca", {"subs": [], "idx": bg_idx, "dynamic": set()}, ca_all=lambda *a, **k: ca_excl(["u1"]),
               scan_dynamic=lambda c: None, graph_all=lambda *a, **k: [], licensed=lambda plans: True)
    assert "ca-policy-has-exclusions" in got, got
    assert "ca-no-risk-conditions" in got and "ca-risk-not-licensed" not in got, got
    # One emergency account is a single point of failure; a named account no policy exempts is high.
    got = _run("entra-breakglass", {"subs": [], "idx": bg_idx, "dynamic": set()}, ca_all=lambda *a, **k: ca_excl(["bg1"]))
    assert "breakglass-single-account" in got, got
    got = _run("entra-breakglass", {"subs": [], "idx": bg_idx, "dynamic": set()}, ca_all=lambda *a, **k: ca_excl(["u1"]))
    assert "breakglass-not-excluded" in got, got
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
    regressions()
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
