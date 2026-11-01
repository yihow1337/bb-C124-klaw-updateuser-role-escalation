
  // Only a user with permission FULL_ACCESS_USERS_TEAMS_ROLES or UPDATE_PERMISSIONS
  // should be able to update other user who has permissions FULL_ACCESS_USERS_TEAMS_ROLES or
  // UPDATE_PERMISSIONS or role SUPERADMIN_ROLE
  private boolean verifySuperAdminAccess(UserInfoModel newUser, Set<String> permissions) {
    return (newUser.getRole().equals(SUPERADMIN_ROLE)
            || (permissions != null
                && (permissions.contains(PermissionType.FULL_ACCESS_USERS_TEAMS_ROLES.name())
                    || permissions.contains(PermissionType.UPDATE_PERMISSIONS.name()))))
        && (commonUtilsService.isNotAuthorizedUser(
                getUserName(), PermissionType.FULL_ACCESS_USERS_TEAMS_ROLES)
            && commonUtilsService.isNotAuthorizedUser(
                getUserName(), PermissionType.UPDATE_PERMISSIONS));
  }

  private Pair<Boolean, String> validateSwitchTeams(UserInfoModel sourceUser) {
