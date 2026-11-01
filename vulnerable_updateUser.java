  public ApiResponse updateUser(UserInfoModel newUser) throws KlawException {
    log.info("updateUser {}", newUser.getUsername());

    if (commonUtilsService.isNotAuthorizedUser(
        getUserName(), PermissionType.ADD_EDIT_DELETE_USERS)) {
      return ApiResponse.NOT_AUTHORIZED;
    }

    if (newUser.getTeamId() == null) {
      return ApiResponse.notOk(TEAMS_ERR_101);
    }

    UserInfo existingUserInfo =
        manageDatabase.getHandleDbRequests().getUsersInfo(newUser.getUsername());
    int tenantId = commonUtilsService.getTenantId(getUserName());
    Set<String> permissions =
        manageDatabase
            .getRolesPermissionsPerTenant(tenantId)
            .getOrDefault(existingUserInfo.getRole(), Collections.emptySet());
    if (permissions != null
        && permissions.contains(PermissionType.FULL_ACCESS_USERS_TEAMS_ROLES.name())) {
      if (!Objects.equals(
          getUserName(), newUser.getUsername())) { // should be able to update same user
        return ApiResponse.notOk(TEAMS_ERR_102);
      }
    }

    // Only a user with permission FULL_ACCESS_USERS_TEAMS_ROLES or UPDATE_PERMISSIONS
    // should be able to update other user who has permissions FULL_ACCESS_USERS_TEAMS_ROLES or
    // UPDATE_PERMISSIONS or role SUPERADMIN_ROLE
    if (verifySuperAdminAccess(newUser, permissions)) {
      return ApiResponse.notOk(TEAMS_ERR_102);
    }

    return getApiResponseUpdateUser(newUser, existingUserInfo, tenantId);
  }

  private ApiResponse getApiResponseUpdateUser(
      UserInfoModel newUser, UserInfo existingUserInfo, int tenantId) throws KlawException {
    String pwdUpdated = newUser.getUserPassword();
    String existingPwd;
