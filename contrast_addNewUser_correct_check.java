    // Only a user with permission FULL_ACCESS_USERS_TEAMS_ROLES or UPDATE_PERMISSIONS
    // should be able to update other user who has permissions FULL_ACCESS_USERS_TEAMS_ROLES or
    // UPDATE_PERMISSIONS or
    // role SUPERADMIN_ROLE
    Set<String> permissions =
        manageDatabase
            .getRolesPermissionsPerTenant(tenantId)
            .getOrDefault(newUser.getRole(), Collections.emptySet());

    if (verifySuperAdminAccess(newUser, permissions)) {
      return ApiResponse.notOk(TEAMS_ERR_102);
    }

    if (isExternal
        && commonUtilsService.isNotAuthorizedUser(
            commonUtilsService.getPrincipal(), PermissionType.ADD_EDIT_DELETE_USERS)) {
