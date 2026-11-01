  @PermissionAllowed(
      permissionAllowed = {
        PermissionType.ADD_EDIT_DELETE_TEAMS,
        PermissionType.FULL_ACCESS_USERS_TEAMS_ROLES
      })
  @PostMapping(
      value = "/updateUser",
      produces = {MediaType.APPLICATION_JSON_VALUE})
  public ResponseEntity<ApiResponse> updateUser(
      @Valid @RequestBody UserUpdateInfoModel updateUserObj) throws KlawException {
    UserInfoModel userInfoObj = new UserInfoModel();
    copyProperties(updateUserObj, userInfoObj);
    return new ResponseEntity<>(usersTeamsControllerService.updateUser(userInfoObj), HttpStatus.OK);
  }
