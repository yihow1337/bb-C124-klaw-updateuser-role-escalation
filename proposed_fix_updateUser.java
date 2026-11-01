// Replace the permissions lookup in updateUser(...) so BOTH roles are checked:
    Set<String> existingRolePermissions =
        manageDatabase
            .getRolesPermissionsPerTenant(tenantId)
            .getOrDefault(existingUserInfo.getRole(), Collections.emptySet());
    Set<String> destinationRolePermissions =
        manageDatabase
            .getRolesPermissionsPerTenant(tenantId)
            .getOrDefault(newUser.getRole(), Collections.emptySet());
    if (existingRolePermissions != null
        && existingRolePermissions.contains(PermissionType.FULL_ACCESS_USERS_TEAMS_ROLES.name())) {
      if (!Objects.equals(getUserName(), newUser.getUsername())) {
        return ApiResponse.notOk(TEAMS_ERR_102);
      }
    }
    if (verifySuperAdminAccess(newUser, existingRolePermissions)
        || verifySuperAdminAccess(newUser, destinationRolePermissions)) {
      return ApiResponse.notOk(TEAMS_ERR_102);
    }
// (mirrors addNewUser which already looks up newUser.getRole())
