## Title
Klaw updateUser: privilege escalation by assigning a custom elevated role (destination-role check gap)

## VRT
Broken Access Control > Privilege Escalation

## Target
github.com/Aiven-Open (klaw @ f1c24b9 / v2.10.6-1)

## Description
`POST /updateUser` authorizes privileged-role changes using the target user's *current* role permissions, not the role being assigned. A user who only has `ADD_EDIT_DELETE_USERS` can therefore assign any non-`SUPERADMIN` custom role that already carries `FULL_ACCESS_USERS_TEAMS_ROLES`, `UPDATE_PERMISSIONS`, `APPROVE_ALL_REQUESTS_TEAMS`, `SHUTDOWN_KLAW`, etc. `addNewUser` correctly checks the new role and rejects the same assignment.

## Steps to reproduce (local / synthetic)
1. Ensure a custom role (e.g. POWERADMIN) exists with elevated permissions (not the literal name SUPERADMIN).
2. Authenticate as a user that has `ADD_EDIT_DELETE_USERS` but not `FULL_ACCESS_USERS_TEAMS_ROLES` / `UPDATE_PERMISSIONS`.
3. `POST /updateUser` with `role=POWERADMIN` for self or another non-privileged user.
4. Observe success; the updated user now holds the elevated permissions.
5. Contrast: `POST` create-user with the same role is rejected; assigning literal `SUPERADMIN` is rejected.

## Impact
Tenant-local privilege escalation to whatever permission set the custom role holds (full user/team/role admin, cross-team approvals, shutdown, …).

## Fix
In `updateUser`, also load permissions for `newUser.getRole()` and pass them to `verifySuperAdminAccess` (mirror `addNewUser`).
