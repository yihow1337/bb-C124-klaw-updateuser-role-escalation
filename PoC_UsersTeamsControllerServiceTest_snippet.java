  /**
   * C124 PoC — updateUser checks privileges of the EXISTING role, not the NEW role.
   * A caller with only ADD_EDIT_DELETE_USERS can therefore assign any non-SUPERADMIN
   * role that already carries FULL_ACCESS / UPDATE_PERMISSIONS / other elevated perms.
   * addNewUser correctly looks up newUser.getRole(); updateUser incorrectly uses
   * existingUserInfo.getRole().
   */
  @Test
  public void updateUser_privEscalationViaCustomPrivilegedRole_succeedsBug() throws KlawException {
    final String caller = "teamadmin";
    UserInfoModel targetUpdate = utilMethods.getUserInfoMock(); // username kwusera, role initially USER
    targetUpdate.setRole("POWERADMIN"); // elevated custom role (NOT the SUPERADMIN string)

    // Existing DB user is a normal USER (no elevated perms)
    UserInfo existing = utilMethods.getUserInfoMockDao(); // role USER
    existing.setUsername(targetUpdate.getUsername());

    Map<String, Set<String>> roles = new HashMap<>();
    roles.put("USER", Set.of(PermissionType.VIEW_TOPICS.name()));
    roles.put(
        "TEAMADMIN",
        Set.of(PermissionType.ADD_EDIT_DELETE_USERS.name(), PermissionType.VIEW_TOPICS.name()));
    roles.put(
        "POWERADMIN",
        Set.of(
            PermissionType.FULL_ACCESS_USERS_TEAMS_ROLES.name(),
            PermissionType.UPDATE_PERMISSIONS.name(),
            PermissionType.APPROVE_ALL_REQUESTS_TEAMS.name(),
            PermissionType.ADD_EDIT_DELETE_ENVS.name(),
            PermissionType.SHUTDOWN_KLAW.name()));

    when(commonUtilsService.isNotAuthorizedUser(caller, PermissionType.ADD_EDIT_DELETE_USERS))
        .thenReturn(false); // caller IS allowed to edit users
    // caller lacks FULL_ACCESS and UPDATE_PERMISSIONS (default stub returns true = not authorized)
    when(handleDbRequests.getUsersInfo(targetUpdate.getUsername())).thenReturn(existing);
    when(commonUtilsService.getTenantId(anyString())).thenReturn(TEST_TENANT_ID);
    when(mailService.getUserName(any())).thenReturn(caller);
    when(manageDatabase.getRolesPermissionsPerTenant(TEST_TENANT_ID)).thenReturn(roles);
    when(handleDbRequests.updateUser(any())).thenReturn(ApiResultStatus.SUCCESS.value);

    ApiResponse apiResponse = usersTeamsControllerService.updateUser(targetUpdate);

    // BUG: should be TEAMS_ERR_102, but currently SUCCESS because privilege check used
    // existing USER role (no FULL_ACCESS) instead of the destination POWERADMIN role.
    assertThat(apiResponse.isSuccess()).isTrue();
    assertThat(apiResponse.getMessage()).isEqualTo(ApiResultStatus.SUCCESS.value);
    verify(handleDbRequests, times(1)).updateUser(any());
  }

  @Test
  public void updateUser_assignLiteralSuperAdmin_stillBlocked() throws KlawException {
    final String caller = "teamadmin";
    UserInfoModel targetUpdate = utilMethods.getUserInfoMock();
    targetUpdate.setRole(SUPERADMIN_ROLE);

    UserInfo existing = utilMethods.getUserInfoMockDao();
    existing.setUsername(targetUpdate.getUsername());

    Map<String, Set<String>> roles = new HashMap<>();
    roles.put("USER", Set.of(PermissionType.VIEW_TOPICS.name()));
    roles.put("TEAMADMIN", Set.of(PermissionType.ADD_EDIT_DELETE_USERS.name()));

    when(commonUtilsService.isNotAuthorizedUser(caller, PermissionType.ADD_EDIT_DELETE_USERS))
        .thenReturn(false);
    when(handleDbRequests.getUsersInfo(targetUpdate.getUsername())).thenReturn(existing);
    when(commonUtilsService.getTenantId(anyString())).thenReturn(TEST_TENANT_ID);
    when(mailService.getUserName(any())).thenReturn(caller);
    when(manageDatabase.getRolesPermissionsPerTenant(TEST_TENANT_ID)).thenReturn(roles);

    ApiResponse apiResponse = usersTeamsControllerService.updateUser(targetUpdate);
    assertThat(apiResponse.getMessage()).isEqualTo(TEAMS_ERR_102);
    verify(handleDbRequests, never()).updateUser(any());
  }

  @Test
  public void addNewUser_customPrivilegedRole_correctlyBlocked() throws KlawException {
    // Contrast: addNewUser looks up permissions of the NEW role and blocks correctly.
    final String caller = "teamadmin";
    UserInfoModel newUser = utilMethods.getUserInfoMock();
    newUser.setUsername("brandnewuser");
    newUser.setRole("POWERADMIN");

    Map<String, Set<String>> roles = new HashMap<>();
    roles.put("USER", Set.of(PermissionType.VIEW_TOPICS.name()));
    roles.put("TEAMADMIN", Set.of(PermissionType.ADD_EDIT_DELETE_USERS.name()));
    roles.put(
        "POWERADMIN",
        Set.of(PermissionType.FULL_ACCESS_USERS_TEAMS_ROLES.name()));

    when(commonUtilsService.isNotAuthorizedUser(any(), any(PermissionType.class))).thenReturn(true);
    when(commonUtilsService.isNotAuthorizedUser(caller, PermissionType.ADD_EDIT_DELETE_USERS))
        .thenReturn(false);
    when(commonUtilsService.getTenantId(anyString())).thenReturn(TEST_TENANT_ID);
    when(mailService.getUserName(any())).thenReturn(caller);
    when(manageDatabase.getRolesPermissionsPerTenant(TEST_TENANT_ID)).thenReturn(roles);

    ApiResponse apiResponse = usersTeamsControllerService.addNewUser(newUser, false);
    assertThat(apiResponse.getMessage()).isEqualTo(TEAMS_ERR_102);
    verify(handleDbRequests, never()).addNewUser(any());
  }

