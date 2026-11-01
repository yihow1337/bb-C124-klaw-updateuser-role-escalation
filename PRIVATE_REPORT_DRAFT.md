# PRIVATE REPORT DRAFT — C124
## Klaw `updateUser` privilege escalation via destination-role check gap

**Status:** CONFIRMED locally. NOT submitted. NOT disclosed. No public branch/issue.
**Program:** Bugcrowd Aiven Managed Bug Bounty (`aiven-mbb-og`)
**Asset:** `github.com/Aiven-Open` → `github.com/Aiven-Open/klaw`
**Exact revision:** `f1c24b9d3c8a079dba0a54e7713a09fdd43a974b` (describe `v2.10.6-1-gf1c24b9`, also present on `origin/main` as of 2026-11-02)
**Severity (researcher):** High (~Bugcrowd P2) — Broken Access Control › Privilege Escalation
**CWE:** CWE-269 Improper Privilege Management / CWE-863 Incorrect Authorization
**Date:** 2026-11-02 (Asia/Taipei)

---

### Summary

`UsersTeamsControllerService.updateUser` is intended to stop callers who only hold `ADD_EDIT_DELETE_USERS` from creating or elevating SUPERADMIN / fully-privileged users (security change noted in Klaw v2.10.0). The guard calls `verifySuperAdminAccess(newUser, permissions)`, but **`permissions` is loaded from the target's EXISTING role** (`existingUserInfo.getRole()`), not from the role being assigned (`newUser.getRole()`).

Consequence: a caller with only `ADD_EDIT_DELETE_USERS` can change any non-privileged user (including themselves) to any **custom** role that already carries elevated permissions such as `FULL_ACCESS_USERS_TEAMS_ROLES`, `UPDATE_PERMISSIONS`, `APPROVE_ALL_REQUESTS_TEAMS`, or `SHUTDOWN_KLAW`. The literal role name `SUPERADMIN` is still blocked; the bypass is any other role name that holds the same (or other dangerous) permissions.

The sibling method `addNewUser` correctly loads permissions from `newUser.getRole()` and rejects the same assignment — proving the UPDATE path asymmetry is unintentional.

### Fingerprint

| Field | Value |
|---|---|
| TARGET | Aiven-Open/klaw @ f1c24b9 (Bugcrowd aiven-mbb-og) |
| COMPONENT | UsersTeamsControllerService / UsersTeamsController |
| ENTRY POINT | `POST /updateUser` (`UserUpdateInfoModel`: username, role, teamId, …) |
| SINK | `HandleDbRequests.updateUser` → persisted role change + in-memory Spring `UserDetails` roles |
| ROOT CAUSE | Privilege check uses `existingUserInfo.getRole()` instead of destination `newUser.getRole()` |
| CWE | 269 / 863 |
| IMPACT | Tenant-local privilege escalation to any permission set attached to a non-SUPERADMIN custom role |
| PREREQUISITES | Authenticated user with `ADD_EDIT_DELETE_USERS`; at least one custom role (≠ `SUPERADMIN`) that already has elevated permissions |

### Vulnerable code

```java
// UsersTeamsControllerService.updateUser
UserInfo existingUserInfo =
    manageDatabase.getHandleDbRequests().getUsersInfo(newUser.getUsername());
int tenantId = commonUtilsService.getTenantId(getUserName());
Set<String> permissions =
    manageDatabase
        .getRolesPermissionsPerTenant(tenantId)
        .getOrDefault(existingUserInfo.getRole(), Collections.emptySet()); // ← EXISTING role
...
if (verifySuperAdminAccess(newUser, permissions)) {   // misses destination-role elevation
  return ApiResponse.notOk(TEAMS_ERR_102);
}
```

`verifySuperAdminAccess` only treats the destination as privileged when `newUser.getRole().equals("SUPERADMIN")` **or** when the supplied `permissions` set (here: existing role) contains `FULL_ACCESS_USERS_TEAMS_ROLES` / `UPDATE_PERMISSIONS`. Assigning e.g. role `POWERADMIN` that already has those permissions therefore passes.

Contrast — `addNewUser` (safe):

```java
Set<String> permissions =
    manageDatabase
        .getRolesPermissionsPerTenant(tenantId)
        .getOrDefault(newUser.getRole(), Collections.emptySet()); // ← NEW role
if (verifySuperAdminAccess(newUser, permissions)) {
  return ApiResponse.notOk(TEAMS_ERR_102);
}
```

### Attack scenario (synthetic)

1. Tenant has roles: `USER`, `TEAMADMIN` (holds `ADD_EDIT_DELETE_USERS`), `POWERADMIN` (holds `FULL_ACCESS_USERS_TEAMS_ROLES`, `APPROVE_ALL_REQUESTS_TEAMS`, …). Custom roles are a documented, supported feature.
2. Attacker authenticates as a `TEAMADMIN` user.
3. `POST /updateUser` with body `{ "username": "<self-or-victim>", "role": "POWERADMIN", "teamId": <allowed>, ... }`.
4. Server persists the new role. Attacker now has full user/team/role control and/or can approve any team's requests / shut down Klaw, depending on the custom role's permission set.

### Local verification (Temurin 21.0.13)

JUnit in `UsersTeamsControllerServiceTest` (synthetic mocks only; no live host):

| Test | Expectation | Result |
|---|---|---|
| `updateUser_privEscalationViaCustomPrivilegedRole_succeedsBug` | EXPLOIT: USER→POWERADMIN by TEAMADMIN → SUCCESS (bug) | PASS |
| `updateUser_assignLiteralSuperAdmin_stillBlocked` | NEG: USER→SUPERADMIN → TEAMS_ERR_102 | PASS |
| `addNewUser_customPrivilegedRole_correctlyBlocked` | NEG/contrast: addNewUser POWERADMIN → TEAMS_ERR_102 | PASS |

Surefire: 3/3, 0 failures. After applying the proposed fix (check both existing and destination role permissions), the exploit test flips to denied (separate fix run also 3/3 PASS).

### Suggested fix

Load and check permissions for **both** `existingUserInfo.getRole()` and `newUser.getRole()` (same helper as `addNewUser`). Optionally harden `verifySuperAdminAccess` to always derive destination permissions from `newUser.getRole()` internally so callers cannot pass the wrong set.

### Novelty / public-disclosure search (2026-11-02)

- GitHub Security Advisories for Aiven-Open/klaw: only GHSA-rp26-qv9w-xr5q (`/resetMemoryCache`), GHSA-v7m7-fr8v-hpx2 (password-hash disclosure), GHSA-75rx-m9vh-mm9p (case-lockout). **None cover updateUser role assignment.**
- NVD / public CVE index for klaw: CVE-2026-25999, CVE-2026-45080, CVE-2026-44367 — same three issues.
- Public writeups: a third-party note describing a *cross-tenant* `updateUser` tenant-scoping IDOR (different root cause: missing tenant binding). This finding is **intra-tenant destination-role check gap**, not tenant isolation.
- v2.10.0 release notes document the SUPERADMIN add/update restriction; the custom-role bypass of that control is not mentioned in issues/PRs/advisories found.

### Out of scope / not done

No live probing, no disclosure, no GitHub issue/PR/public branch, no Bugcrowd submission without operator approval.

## Relation to the publicly described cross-tenant updateUser issue
A separate, publicly described Klaw `updateUser` report concerns **cross-tenant** access (missing tenant scoping lets a user edit accounts in another tenant). This report is a **different root cause**: it is entirely **intra-tenant** and concerns *which role's permissions are checked*. `updateUser` evaluates `verifySuperAdminAccess` against `existingUserInfo.getRole()` (the target's current role) instead of `newUser.getRole()` (the role being assigned). Adding tenant scoping does not fix this: a same-tenant caller with only `ADD_EDIT_DELETE_USERS` can still assign a custom elevated role. The fix is independent (check the destination role, as `addNewUser` already does).
