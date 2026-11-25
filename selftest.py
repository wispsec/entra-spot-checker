"""Failure-path self-test: every transport read returns None, no verdict may follow.

Run: python3 selftest.py
Exit 0 when a total read failure produces no medium, high or critical finding.
"""
import base64
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

# The shape an AzureHound export uses: the object is nested under "data".
SAMPLE_NODES = [
    {"kind": "AZUser", "data": {"id": "u1", "displayName": "User One", "userPrincipalName": "u1@example.com",
                                "accountEnabled": True, "userType": "Member", "onPremisesSyncEnabled": False,
                                "passwordPolicies": None}},
    {"kind": "AZGroup", "data": {"id": "g1", "displayName": "Group One", "securityEnabled": True,
                                 "isAssignableToRole": False}},
    {"kind": "AZServicePrincipal", "data": {"id": "s1", "displayName": "SP One", "appId": "a1",
                                            "servicePrincipalType": "Application"}},
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


def load_shape():
    """load_ah() reads each document shape an export uses, and keeps the kind."""
    import tempfile
    cases = [
        ('{"data": [{"kind": "AZUser", "data": {"id": "u1"}}]}', 1),
        ('[{"kind": "AZUser", "data": {"id": "u1"}}]', 1),
        ('{"kind": "AZUser", "data": {"id": "u1"}}\n{"kind": "AZGroup", "data": {"id": "g1"}}\n', 2),
    ]
    directory = tempfile.mkdtemp()
    try:
        for index, (body, expected) in enumerate(cases):
            path = os.path.join(directory, "export%d.json" % index)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(body)
            nodes, state, _detail = M.load_ah(path)
            assert state == "ok", (index, state)
            assert len(nodes) == expected, (index, nodes)
            kinds = M.Index(nodes).kinds
            assert kinds, (index, nodes)
    finally:
        for name in os.listdir(directory):
            os.remove(os.path.join(directory, name))
        os.rmdir(directory)


def dataset_shape():
    """One node is readable in every export shape the loader accepts.

    The payload key has moved between AzureHound versions: "data" today,
    "properties" or "props" earlier. A node that carries its object id outside
    the payload must keep it, because resolve() is keyed on it.
    """
    for key in ("data", "properties", "props"):
        idx = M.Index([{"kind": "AZUser", key: {"id": "x1", "displayName": "D", "userPrincipalName": "u@x"}}])
        user = idx.users()[0]
        assert idx.props(user)["displayName"] == "D", key
        assert idx.name(user) == "D", key
        assert idx.resolve("x1") == "D", key
        assert idx.kinds["azuser"] == 1, key
    idx = M.Index([{"kind": "AZUser", "id": "x2", "properties": {"displayName": "E"}}])
    assert idx.users()[0]["id"] == "x2"
    assert idx.name(idx.users()[0]) == "E"
    assert M.Index([]).kinds == {}


def path_reads():
    """dig() resolves a key that contains a dot, and a path that does not exist."""
    assert M.dig({"@odata.type": "#microsoft.graph.group"}, "@odata.type") == "#microsoft.graph.group"
    assert M.dig({"@odata": {"nextLink": "u"}}, "@odata.nextLink") == "u"
    assert M.dig({"a": {"b": {"c": 2}}}, "a.b.c") == 2
    assert M.dig({"a": {"b.c": 1}}, "a.b.c") == 1
    assert M.dig({"a": 1}, "a.z", "absent") == "absent"
    assert M.dig(None, "a", "absent") == "absent"
    assert M.dig({"a": {"b": 3}}, ("a", "b")) == 3


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
    # Attribute classes decide who writes a steering attribute.
    assert M.attribute_class("user.extensionAttribute5") == "onprem"
    assert M.attribute_class("user.onPremisesExtensionAttributes.extensionAttribute3") == "onprem"
    assert M.attribute_class("user.customSecurityAttributes.Eng_Project") == "csa"
    assert M.attribute_class("user.extension_00112233445566778899aabbccddeeff_team") == "schema"
    assert M.attribute_class("user.department") == ""
    assert M.schema_app_id("user.extension_00112233445566778899aabbccddeeff_team") == "00112233-4455-6677-8899-aabbccddeeff"
    assert M.schema_app_id("user.extabcdefgh_team") == ""
    # An application owner who writes a schema extension steers the group that reads it.
    app_id = "00112233445566778899aabbccddeeff"
    w_idx = M.Index([{"kind": "AZUser", "id": "u1", "properties": {"userPrincipalName": "a@example.com"}}], "ok")

    def w_graph_all(path, limit=25, beta=False, max_pages=None):
        if "roleDefinitions" in path:
            return [{"id": "rd1", "displayName": "Global Administrator",
                     "rolePermissions": [{"allowedResourceActions": ["microsoft.directory/x/allTasks"]}]}]
        if "roleAssignments" in path:
            return [{"principalId": "g1", "roleDefinitionId": "rd1"}]
        return []

    def w_graph(path, beta=False):
        if path.startswith("applications?$filter=appId"):
            return {"value": [{"id": "o1", "displayName": "CRM Sync", "appId": app_id}]}
        if "owners" in path:
            return {"value": [{"userPrincipalName": "dev@example.com"}]}
        return {"value": []}

    wctx = {"idx": w_idx, "dynamic": set(), "dyn_done": True}
    got = _run("entra-attribute-writers", wctx,
               dynamic_groups=lambda ctx: {"g1": ("Priv", 'user.extension_' + app_id + '_team -eq "red"', "On")},
               graph_all=w_graph_all, graph=w_graph)
    assert "schema-extension-steers-role-group" in got, got
    assert "owns CRM Sync" in wctx["steer_writer"]["g1"], wctx["steer_writer"]
    assert not M.CHAINS, M.CHAINS
    # The role check joins the writer segment and the role into one path.
    got = _run("entra-group-roles",
               {"idx": w_idx, "dynamic": {"g1"}, "dyn_done": True, "steer_writer": wctx["steer_writer"],
                "dyn_rules": {"g1": ("Priv", 'user.extension_' + app_id + '_team -eq "red"', "On")}},
               graph_all=w_graph_all, graph=w_graph, scan_dynamic=lambda ctx: None,
               dynamic_parents=lambda ctx, gid: set())
    assert "dynamic-group-holds-role" in got, got
    paths = [c["path"] for c in M.CHAINS]
    assert paths and "owns CRM Sync" in paths[0] and "role Global Administrator" in paths[0], paths
    # A dynamic group nested in a role-holding group inherits the role.
    def n_graph_all(path, limit=25, beta=False, max_pages=None):
        if "roleDefinitions" in path:
            return [{"id": "rd1", "displayName": "Global Administrator",
                     "rolePermissions": [{"allowedResourceActions": ["microsoft.directory/x/allTasks"]}]}]
        if "roleAssignments" in path:
            return [{"principalId": "parent1", "roleDefinitionId": "rd1"}]
        return []
    got = _run("entra-group-roles",
               {"idx": w_idx, "dynamic": {"g1"}, "dyn_done": True, "steer_writer": wctx["steer_writer"],
                "dyn_rules": {"g1": ("Priv", 'user.department -eq "IT"', "On")}},
               graph_all=n_graph_all, graph=w_graph, scan_dynamic=lambda ctx: None,
               dynamic_parents=lambda ctx, gid: {"parent1"})
    ev = [f["evidence"] for f in M.FINDINGS if f["check"] == "dynamic-group-holds-role"]
    assert any("viaNestedGroup" in e for e in ev), ev
    reset()
    # One row per privileged group: who can join it, and what membership gives.
    pctx = {"dyn_rules": {"g1": ("DG", 'user.department -eq "IT"', "On")},
            "steer_writer": {"g1": "user a@x -> owns App -> writes user.extension_x"},
            "caps": {"g1": [(3, "Owner on /subscriptions/s1")]},
            "caps_blind": set(),
            "group_roles": {"g1": {"name": "Global Administrator", "writable": True}}}
    rows = M.privileged_groups(pctx)
    assert len(rows) == 1, rows
    name, entry, grants, status = rows[0]
    assert name == "DG" and "owns App" in entry, rows
    assert "Global Administrator" in grants and "Owner on" in grants, rows
    assert status == "ok", rows
    # A failed capability read is unassessed, never "grants nothing".
    pctx["caps"] = {}
    pctx["caps_blind"] = {"g1"}
    rows = M.privileged_groups(pctx)
    assert rows and rows[0][3] == "unassessed" and rows[0][2] == "Global Administrator", rows
    # No role and no grant is not a row at all.
    pctx["group_roles"] = {}
    pctx["caps_blind"] = set()
    assert M.privileged_groups(pctx) == [], M.privileged_groups(pctx)
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
    # No subscription in scope: RBAC unread, so no severity is drawn for the steer.
    assert not [f for f in M.FINDINGS if f["check"] == "dynamic-group-steerable"], M.FINDINGS
    assert {f["check"] for f in M.FINDINGS if f["source"] == "entra-dynamic-groups"} == {"dynamic-group-rbac-unassessed", "dynamic-group-grant-unread", "dynamic-group-processing-paused"}, M.FINDINGS
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


def payloads():
    """Success-path cases: a documented payload shape must produce the stated verdict.

    The failure-path sweep below cannot see a check that reads the wrong field from
    a payload it successfully received, which is how every schema defect in this
    tree arrived. Each case here encodes one rule, so the rule is checked rather
    than remembered.
    """
    home = "11111111-1111-1111-1111-111111111111"
    foreign = "22222222-2222-2222-2222-222222222222"
    ga = "62e90394-69f5-4237-9190-012177145e10"
    owner = "/providers/microsoft.authorization/roledefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
    thumb = lambda hex_text: base64.b64encode(bytes.fromhex(hex_text)).decode()
    THUMB_AABB = thumb("aabbccdd")
    THUMB_FFFF = thumb("ffffffff")
    keep_home = M.HOME_TENANT["id"]
    keep_beta = M.CA_BETA["state"]
    M.HOME_TENANT["id"] = home
    M.CA_BETA["state"] = "ok"
    idx = M.Index(list(SAMPLE_NODES))
    orphan_idx = M.Index(list(SAMPLE_NODES))
    orphan_idx.absent.add("gone")

    def rows(fn):
        return lambda q, subs, scoped=True, **k: fn(q)

    def evidence(finding_id):
        return [f for f in M.FINDINGS if f["check"] == finding_id]

    def ga_defs(p, *a, **k):
        return ([{"id": "d1", "templateId": ga, "displayName": "Global Administrator"}]
                if "roleDefinitions" in p else [{"principalId": "p1", "roleDefinitionId": "d1"}])

    cases = [
        ("a federated issuer is an STS URL, not a tenant id", "entra-linked-identities", {"subs": []},
         {"graph_all": lambda *a, **k: [{"userPrincipalName": "u@x", "identities": [
             {"issuer": "https://sts.windows.net/" + home + "/", "signInType": "federated"}]}]},
         (), ("federated-identity-unknown-issuer",), None),
        ("a foreign federated issuer is reported", "entra-linked-identities", {"subs": []},
         {"graph_all": lambda *a, **k: [{"userPrincipalName": "u@x", "identities": [
             {"issuer": "https://sts.windows.net/" + foreign + "/", "signInType": "federated"}]}]},
         ("federated-identity-unknown-issuer",), (), None),
        ("includeRoles carries template ids", "entra-ca-scope-detail", {"subs": []},
         {"ca_all": lambda *a, **k: [{"state": "enabled", "displayName": "P", "conditions": {
             "users": {"includeRoles": [ga]}, "applications": {}}}],
          "graph_all": lambda *a, **k: [{"id": "obj-1", "templateId": ga, "displayName": "Global Administrator"}]},
         (), ("ca-role-uncovered",), None),
        ("persistent browser enabled with mode always is not a control", "entra-ca-session", {"subs": []},
         {"ca_all": lambda *a, **k: [{"state": "enabled", "displayName": "P", "sessionControls": {
             "persistentBrowser": {"isEnabled": True, "mode": "always"}}}]},
         ("no-persistent-browser-control",), (), None),
        ("a deny default action closes the site", "sub-appservice-restrictions", {"subs": ["s1"]},
         {"arg_rows": rows(lambda q: [{"parent": "/subscriptions/s1/resourcegroups/rg/providers/microsoft.web/sites/app",
                                       "ips": [], "scm": [], "scmMain": "", "defaultAction": "Deny"}]
                           if "sites/config" in q else
                           [{"name": "app", "subscriptionId": "s1", "rg": "rg", "clientCert": None}])},
         (), ("appservice-no-ip-restriction",), None),
        ("the DDoS enum is VirtualNetworkInherited", "sub-publicip-sku", {"subs": ["s1"]},
         {"arg_rows": lambda *a, **k: [{"name": "ip1", "subscriptionId": "s1", "sku": "Standard",
                                        "ddos": "VirtualNetworkInherited"}]},
         (), ("publicip-no-ddos",), None),
        ("a strength outside the map is undecided, not absent", "entra-mfa-baseline", {"subs": []},
         {"graph": lambda *a, **k: {"isEnabled": False},
          "ca_all": lambda *a, **k: [{"state": "enabled", "displayName": "P",
                                      "grantControls": {"authenticationStrength": {"id": "unmapped"}},
                                      "conditions": {"users": {"includeUsers": ["All"]},
                                                     "applications": {"includeApplications": ["All"]}}}],
          "_strengths": lambda: {}},
         ("mfa-control-unread",), ("mfa-not-required-for-all",), None),
        ("a service-principal owner is an owner", "entra-role-assignable-groups", {"subs": []},
         {"graph_all": lambda *a, **k: [{"id": "g1", "displayName": "G", "membershipRule": None}],
          "graph": lambda *a, **k: {"value": [{"id": "sp1", "displayName": "SP"}]}},
         ("role-assignable-group-owned-by-sp",), ("role-assignable-group-ownerless",), None),
        ("the review target is the scope query", "entra-access-review-scope", {"subs": []},
         {"graph_all": lambda *a, **k: [{"displayName": "R", "status": "Active",
                                         "scope": {"query": "/groups/x/transitiveMembers"}}]},
         ("access-review-scope",), ("access-reviews-only-apps",), None),
        ("an unset partner inbound inherits a blocked default", "entra-cross-tenant-escalation",
         {"subs": [], "idx": idx},
         {"graph_all": lambda p, *a, **k: [{"tenantId": foreign, "inboundTrust": {"isMfaAccepted": True}}]
          if "partners" in p else [],
          "graph": lambda *a, **k: {"b2bCollaborationInbound": {"usersAndGroups": {"accessType": "blocked"}}},
          "scan_guests": lambda c: set()},
         (), ("cross-tenant-trust-bypass",), None),
        ("the default domain is one mailbox, a custom domain is not", "sub-security-contacts", {"subs": ["s1"]},
         {"arg_rows": lambda *a, **k: [{"name": "c1", "subscriptionId": "s1", "email": "a@contoso.onmicrosoft.com"},
                                       {"name": "c2", "subscriptionId": "s1", "email": "soc@contoso.com"}]},
         ("security-contact-single-person",), (), lambda: [f["subject"] for f in evidence("security-contact-single-person")] == ["c1"]),
        ("orphan detection reads the assignments made to the principal", "sub-approle-orphans",
         {"subs": [], "idx": orphan_idx},
         {"graph": lambda p, *a, **k: {"value": [{"principalId": "gone", "resourceDisplayName": "API"}]}
          if "appRoleAssignedTo" in p else None},
         ("orphaned-app-role-assignment",), (), None),
        ("an agent group list is a list", "entra-pta-agents", {"subs": []},
         {"graph": lambda p, *a, **k: {"value": [{"onPremisesSyncEnabled": True}]} if "organization" in p else None,
          "graph_all": lambda *a, **k: [{"id": "g1", "displayName": "grp",
                                         "agents": [{"status": "inactive", "machineName": "m1"}]}]},
         ("pta-agent-group", "pta-agent-inactive"), ("no-pta-agents",), None),
        ("a token lifetime definition is a JSON string", "entra-token-lifetime", {"subs": []},
         {"graph_all": lambda *a, **k: [{"displayName": "P", "definition": ['{"MaxInactiveTime":"PT1H"}']}]},
         ("token-lifetime-policy",), (), lambda: "MaxInactiveTime=PT1H" in evidence("token-lifetime-policy")[0]["evidence"]),
        ("zero policies leaves device code flow unrestricted", "entra-ca",
         {"subs": [], "idx": idx, "dynamic": set(), "dyn": {}},
         {"ca_all": lambda *a, **k: []},
         ("ca-device-code-flow-unrestricted", "ca-no-signin-frequency"), (), None),
        ("a disabled role policy is not coverage", "entra-ca-roles", {"subs": []},
         {"ca_all": lambda *a, **k: [{"state": "disabled", "displayName": "P",
                                      "conditions": {"users": {"includeRoles": [ga]}}}]},
         ("ca-no-role-targeting",), (), None),
        ("the PIM alert switch is top level", "entra-pim-alerts", {"subs": []},
         {"graph_all": lambda *a, **k: [{"id": "a1", "isEnabled": True, "alertDefinition": {"displayName": "X"}}]},
         ("pim-alert",), (), lambda: "enabled=True" in evidence("pim-alert")[0]["evidence"]),
        ("an unread guest list is unknown, not a plain principal", "sub-rbac-write", {"subs": ["s1"]},
         {"arg_rows": rows(lambda q: [{"id": owner, "name": "Owner", "perms": [{"actions": ["*"]}]}]
                           if "roledefinitions" in q else
                           [{"principalId": "p1", "roleId": owner, "scope": "/subscriptions/s1"}]),
          "scan_guests": lambda c: None},
         ("principal-can-grant-access",), (), lambda: "type=unknown" in evidence("principal-can-grant-access")[0]["evidence"]),
        ("an unread catalog endpoint is not zero catalogs", "entra-governance", {"subs": []},
         {"graph_all": lambda p, *a, **k: None if "catalogs" in p else []},
         ("catalog-count-unreadable",), ("catalog-count",), None),
        ("an unresolved resource is not Microsoft Graph", "entra-app-overscope", {"subs": []},
         {"graph_all": lambda p, *a, **k: [{"clientId": "sp-client", "resourceId": "sp-missing", "scope": "User.Read"}]
          if "oauth2PermissionGrants" in p else
          ([{"appId": "app-1", "displayName": "A", "requiredResourceAccess": []}] if "applications" in p
           else [{"id": "sp-client", "appId": "app-1", "displayName": "A"}])},
         ("grant-resource-unresolved",), ("grant-without-manifest-scope",), None),
        ("a settings gap is per subscription", "sub-security-settings", {"subs": ["s1", "s2"]},
         {"arg_rows": lambda *a, **k: [{"name": "mcas", "subscriptionId": "s1"},
                                       {"name": "sentinel", "subscriptionId": "s1"}]},
         ("security-setting-absent",), (), lambda: [f["subscription"] for f in evidence("security-setting-absent")] == ["s1"]),
        ("a management-group row belongs to the tenant", "sub-custom-roles", {"subs": ["s1"]},
         {"arg_rows": rows(lambda q: [{"name": "Custom", "subscriptionId": "",
                                       "id": "/providers/Microsoft.Management/mg1/providers/microsoft.authorization/roledefinitions/x",
                                       "perms": [{"actions": ["microsoft.authorization/roleassignments/write"]}]}]
                           if "roledefinitions" in q else [])},
         ("custom-role-privilege-grant",), (), lambda: evidence("custom-role-privilege-grant")[0]["subscription"] == "tenant"),
        ("an unread capability set draws no severity", "entra-dynamic-groups",
         {"subs": [], "dynamic": set(), "dyn": {}},
         {"dynamic_groups": lambda c: c.setdefault("dyn_rules", {"g1": ("DG", 'user.mail -contains "x"', "On")}),
          "_group_capabilities": lambda c, g: ({}, set(g))},
         ("dynamic-group-grant-unread",), ("dynamic-group-steerable",), None),
        ("an unread policy list draws no exclusion verdict", "entra-breakglass-hardening", {"subs": []},
         {"graph_all": ga_defs, "ca_all": lambda *a, **k: None,
          "graph": lambda p, *a, **k: {"value": []} if "methods" in p else {"displayName": "A"}},
         ("breakglass-exclusion-unread",), ("breakglass-not-excluded",), None),
        ("a dotted key resolves instead of splitting", "entra-custom-roles", {"subs": []},
         {"graph_all": lambda *a, **k: [{"displayName": "R", "rolePermissions": [
             {"allowedResourceActions": ["microsoft.directory/users/authenticationMethods/standard/restore"]}]}]},
         ("custom-role-escalation-action",), (), None),
        ("the PIM policy carries its activation rules", "entra-pim-policy", {"subs": []},
         {"graph_all": lambda *a, **k: [{"displayName": "P", "rules": [
             {"@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule",
              "enabledRules": ["MultiFactorAuthentication", "Justification"]}]}]},
         ("pim-policy",), ("pim-activation-no-mfa", "pim-rules-unread"), None),
        ("a policy with no rules is not a missing second factor", "entra-pim-policy", {"subs": []},
         {"graph_all": lambda *a, **k: [{"displayName": "P", "rules": []}]},
         ("pim-rules-unread",), ("pim-activation-no-mfa",), None),
        ("ticketing is an enabled rule, not a rule type", "entra-pim-activation-rules", {"subs": []},
         {"graph_all": lambda *a, **k: [{"displayName": "P", "rules": [
             {"@odata.type": "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule",
              "enabledRules": ["MultiFactorAuthentication", "Justification", "Ticketing"]}]}]},
         (), ("pim-no-ticketing",), None),
        ("a mixed-case escalation action still matches", "entra-custom-roles", {"subs": []},
         {"graph_all": lambda *a, **k: [{"displayName": "R", "rolePermissions": [
             {"allowedResourceActions": ["microsoft.directory/oauth2PermissionGrants/allProperties/allTasks"]}]}]},
         ("custom-role-escalation-action",), (), None),
        ("the restricted consent default is not broad consent", "entra-consent-grant-policy", {"subs": []},
         {"graph_all": lambda *a, **k: [],
          "graph": lambda *a, **k: {"defaultUserRolePermissions": {
              "permissionGrantPoliciesAssigned": ["managePermissionGrantsForSelf.microsoft-user-default-low"]}}},
         ("consent-restricted-by-default",), ("no-consent-grant-policy",), None),
        ("a wildcard on one domain is not a top-level domain", "sub-firewall-rules", {"subs": ["s1"]},
         {"arg_rows": lambda *a, **k: [{"name": "fw", "rule": "r", "action": "Allow", "src": "*",
                                        "dst": "*", "port": "443", "fqdn": '["*.contoso.com"]',
                                        "subscriptionId": "s1"}]},
         ("firewall-fqdn-wildcard",), ("firewall-fqdn-wildcard-broad",), None),
        ("a wildcard on a public suffix is a top-level domain", "sub-firewall-rules", {"subs": ["s1"]},
         {"arg_rows": lambda *a, **k: [{"name": "fw", "rule": "r", "action": "Allow", "src": "10.0.0.1",
                                        "dst": "10.0.0.2", "port": "443", "fqdn": '["*.co.uk"]',
                                        "subscriptionId": "s1"}]},
         ("firewall-fqdn-wildcard-broad",), ("firewall-fqdn-wildcard",), None),
        ("a dropped default route is not an internet default route", "sub-net-routes", {"subs": ["s1"]},
         {"arg_rows": lambda *a, **k: [{"name": "rt", "route": "r", "hop": "None",
                                        "addr": "0.0.0.0/0", "subscriptionId": "s1"}]},
         ("route-default-dropped",), ("route-default-to-internet",), None),
        ("an unreturned rotation flag is not a disabled rotation", "sub-aks-kv-provider", {"subs": ["s1"]},
         {"arg_rows": lambda *a, **k: [{"name": "aks", "subscriptionId": "s1", "kv": "true", "csi": "",
                                        "ident": "SystemAssigned", "kubelet": "k1"}]},
         ("aks-kv-secret-rotation-unknown",), ("aks-kv-secret-rotation-off",), None),
        ("an unreturned multi-user authorisation state is not off", "sub-backup-vault-posture", {"subs": ["s1"]},
         {"arg_rows": lambda *a, **k: [{"name": "v", "subscriptionId": "s1",
                                        "props": {"securitySettings": {"softDeleteSettings": {"softDeleteState": "Enabled"}}}}]},
         ("backup-vault-mua-unknown",), ("backup-vault-mua-off",), None),
        ("the App Insights retention property is Pascal case", "sub-appinsights-keys", {"subs": ["s1"]},
         {"arg_rows": lambda *a, **k: [{"name": "appi", "subscriptionId": "s1", "localAuth": "true",
                                        "retention": "30", "publicIngest": ""}]},
         ("appinsights-short-retention",), (), None),
        ("data sources are read by type, not as a list", "sub-datacollection", {"subs": ["s1"]},
         {"arg_rows": lambda *a, **k: [{"name": "dcr", "subscriptionId": "s1", "ident": "SystemAssigned",
                                        "syslog": 2}]},
         ("dcr-syslog",), (), None),
        ("Sms is a reset method id", "entra-sspr", {"subs": []},
         {"graph": lambda p, *a, **k: ({"authenticationMethodConfigurations": [{"id": "Sms", "state": "enabled"}]}
                                       if "authenticationMethodsPolicy" in p
                                       else {"defaultUserRolePermissions": {"allowedToUseSSPR": False}})},
         ("sspr-single-method",), ("sspr-no-method",), None),
        ("a Block policy for named users leaves legacy clients open", "entra-legacy-auth-block", {"subs": []},
         {"ca_all": lambda *a, **k: [{"state": "enabled", "displayName": "P",
                                      "conditions": {"clientAppTypes": ["exchangeActiveSync", "other"],
                                                     "users": {"includeUsers": ["u1"]}},
                                      "grantControls": {"builtInControls": ["block"]}}]},
         ("legacy-block-narrow", "ca-legacy-auth-not-blocked"), ("legacy-auth-blocked",), None),
        ("a compliant-device policy does not require MFA", "entra-mfa-baseline", {"subs": []},
         {"graph": lambda *a, **k: {"isEnabled": False},
          "ca_all": lambda *a, **k: [{"state": "enabled", "displayName": "P",
                                      "conditions": {"users": {"includeUsers": ["All"]},
                                                     "applications": {"includeApplications": ["All"]}},
                                      "grantControls": {"builtInControls": ["compliantDevice"]}}],
          "_strengths": lambda: {}},
         ("mfa-not-required-for-all",), ("mfa-control-unread",), None),
        ("a subscription with no Sentinel content is named", "sub-sentinel-depth", {"subs": ["s1", "s2"]},
         {"arg_rows": lambda *a, **k: [{"type": "microsoft.securityinsights/alertrules", "subscriptionId": "s1", "n": 3}]},
         ("sentinel-absent", "sentinel-missing-content"), (), lambda: [f["subscription"] for f in evidence("sentinel-absent")] == ["s2"]),
        ("an exclusion through a group counts as an exclusion", "entra-breakglass-hardening", {"subs": []},
         {"graph_all": lambda p, *a, **k: ([{"id": "d1", "templateId": ga, "displayName": "Global Administrator"}]
                                           if "roleDefinitions" in p else [{"principalId": "u1", "roleDefinitionId": "d1"}]),
          "ca_all": lambda *a, **k: [{"state": "enabled", "displayName": "P",
                                      "conditions": {"users": {"excludeGroups": ["g1"]}}}],
          "graph": lambda p, *a, **k: ({"value": [{"id": "g1"}]} if "transitiveMemberOf" in p
                                       else {"displayName": "Emergency", "userPrincipalName": "bg@x",
                                             "accountEnabled": True})},
         ("breakglass-excluded",), ("breakglass-not-excluded",), None),
        ("a service principal with no application object has no readable manifest", "entra-app-overscope", {"subs": []},
         {"graph_all": lambda p, *a, **k: ([{"clientId": "sp1", "resourceId": "sp2", "scope": "User.Read"}]
                                           if "oauth2PermissionGrants" in p else
                                           ([] if "applications" in p else
                                            [{"id": "sp1", "appId": "a1", "displayName": "Client"},
                                             {"id": "sp2", "appId": "00000003-0000-0000-c000-000000000000",
                                              "displayName": "Graph"}]))},
         ("grant-manifest-unreadable",), ("grant-without-manifest-scope",), None),
        ("a failed owner read does not become 'no human owner'", "sub-azure-takeover", {"subs": ["s1"]},
         {"arg_rows": lambda *a, **k: [{"principalId": "sp1", "roleId": "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
                                        "scope": "/subscriptions/s1"}],
          "graph": lambda p, *a, **k: (None if "owners" in p else
                                       {"id": "sp1", "appId": "a1", "displayName": "SP",
                                        "servicePrincipalType": "Application"})},
         (), ("azure-privileged-sp-no-human-owner",), None),
        ("two applications claiming one identifier is a collision", "entra-app-identifiers", {"subs": []},
         {"graph_all": lambda p, *a, **k: ([{"id": "contoso.com", "isVerified": True}] if "domains" in p else
                                           ([{"displayName": "A", "identifierUris": ["https://sp.contoso.com/a"]},
                                             {"displayName": "B", "identifierUris": ["https://sp.contoso.com/a"]}]
                                            if "applications" in p else []))},
         ("app-identifier-duplicate",), (), None),
        ("an identifier on an unverified domain is not proven", "entra-app-identifiers", {"subs": []},
         {"graph_all": lambda p, *a, **k: ([{"id": "contoso.com", "isVerified": False}] if "domains" in p else
                                           ([{"displayName": "A", "identifierUris": ["https://sp.contoso.com/a"]}]
                                            if "applications" in p else []))},
         ("app-identifier-unverified-domain",), (), None),
        ("two principals claiming one name is a collision", "entra-app-identifiers", {"subs": []},
         {"graph_all": lambda p, *a, **k: ([] if "domains" in p or "applications" in p else
                                           [{"displayName": "A", "servicePrincipalNames": ["api://x"]},
                                            {"displayName": "B", "servicePrincipalNames": ["api://x"]}])},
         ("sp-name-collision",), (), None),
        ("assignment required with nobody assigned is unusable", "entra-app-assignees", {"subs": []},
         {"graph_all": lambda *a, **k: [{"id": "sp1", "displayName": "A"}],
          "graph": lambda *a, **k: {"value": []}},
         ("enterprise-app-no-assignee",), (), None),
        ("a hidden application is not visible to its users", "entra-app-visibility", {"subs": []},
         {"graph_all": lambda *a, **k: [{"id": "sp1", "displayName": "A", "tags": ["HideApp"]}]},
         ("sp-hidden-from-users",), (), None),
        ("a pinned signing key that matches a credential is not a finding", "entra-saml-config", {"subs": []},
         {"graph_all": lambda *a, **k: [{"displayName": "A", "notificationEmailAddresses": ["a@x"],
                                         "preferredTokenSigningKeyThumbprint": "aabbccdd",
                                         "keyCredentials": [{"customKeyIdentifier": THUMB_AABB}]}]},
         (), ("saml-pinned-key-missing",), None),
        ("a pinned signing key that matches nothing is a finding", "entra-saml-config", {"subs": []},
         {"graph_all": lambda *a, **k: [{"displayName": "A", "notificationEmailAddresses": ["a@x"],
                                         "preferredTokenSigningKeyThumbprint": "aabbccdd",
                                         "keyCredentials": [{"customKeyIdentifier": THUMB_FFFF}]}]},
         ("saml-pinned-key-missing",), (), None),
    ]
    fails = []
    try:
        for label, name, ctx, fakes, want, unwanted, probe in cases:
            got = _run(name, ctx, **fakes)
            for finding in want:
                if finding not in got:
                    fails.append(label + ": missing " + finding)
            for finding in unwanted:
                if finding in got:
                    fails.append(label + ": unexpected " + finding)
            if probe is not None and not probe():
                fails.append(label + ": evidence or attribution differs")
    finally:
        M.HOME_TENANT["id"] = keep_home
        M.CA_BETA["state"] = keep_beta
    return fails


def main():
    invariants()
    load_shape()
    dataset_shape()
    path_reads()
    regressions()
    fails = payloads()
    if fails:
        print("payload cases that produced the wrong verdict: " + str(len(fails)))
        for line in fails:
            print("  " + line)
        return 1
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
