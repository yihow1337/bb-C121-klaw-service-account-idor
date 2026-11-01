@Test
  @Order(27)
  public void getAivenServiceAccountDetails_rejectsWrongTeam() throws KlawException {
    // NEGATIVE CONTROL: ACL owned by a different team → empty response, cluster API never called.
    String reqNo = "101";
    stubUserInfo();
    mockKafkaFlavor();

    Acl foreignAcl = new Acl();
    foreignAcl.setTopicname("victim-topic");
    foreignAcl.setEnvironment("1");
    foreignAcl.setAclssl("victim-service-account");
    foreignAcl.setTeamId(999); // not caller's team
    foreignAcl.setAclType(AclType.PRODUCER.value);

    when(commonUtilsService.getTenantId(userDetails.getUsername())).thenReturn(1);
    when(commonUtilsService.getTeamId(anyString())).thenReturn(TENANT_ID); // 101
    when(handleDbRequests.getSyncAclsFromReqNo(anyInt(), anyInt())).thenReturn(foreignAcl);

    ServiceAccountDetails resultResp =
        aclControllerService.getAivenServiceAccountDetails(
            "1", "victim-topic", "victim-service-account", reqNo);

    assertThat(resultResp.isAccountFound()).isFalse();
    assertThat(resultResp.getPassword()).isNull();
    verify(clusterApiService, times(0))
        .getAivenServiceAccountDetails(anyString(), anyString(), anyString(), anyInt());
  }

  @Test
  @Order(27)
  public void getAivenServiceAccountDetails_idorAllowsAnyServiceAccountOnOwnAcl()
      throws KlawException {
    // EXPLOIT: ACL owned by caller, but requested serviceAccount is a DIFFERENT principal
    // than acl.aclssl. Missing binding → cluster API is invoked with attacker-supplied username
    // and returns that account's password.
    String reqNo = "101";
    stubUserInfo();
    mockKafkaFlavor();

    Acl ownAcl = new Acl();
    ownAcl.setTopicname("own-topic");
    ownAcl.setEnvironment("1");
    ownAcl.setAclssl("attacker-own-service-account");
    ownAcl.setTeamId(TENANT_ID); // caller's team
    ownAcl.setAclType(AclType.PRODUCER.value);

    ServiceAccountDetails leaked = new ServiceAccountDetails();
    leaked.setUsername("victim-service-account");
    leaked.setPassword("VICTIM_SECRET_PASSWORD");
    leaked.setAccountFound(true);

    when(commonUtilsService.getTenantId(userDetails.getUsername())).thenReturn(1);
    when(commonUtilsService.getTeamId(anyString())).thenReturn(TENANT_ID);
    when(handleDbRequests.getSyncAclsFromReqNo(anyInt(), anyInt())).thenReturn(ownAcl);
    when(clusterApiService.getAivenServiceAccountDetails(
            anyString(), anyString(), eq("victim-service-account"), anyInt()))
        .thenReturn(leaked);

    ServiceAccountDetails resultResp =
        aclControllerService.getAivenServiceAccountDetails(
            "1", "own-topic", "victim-service-account", reqNo);

    assertThat(resultResp.isAccountFound()).isTrue();
    assertThat(resultResp.getUsername()).isEqualTo("victim-service-account");
    assertThat(resultResp.getPassword()).isEqualTo("VICTIM_SECRET_PASSWORD");
    // Prove the unbound request param is forwarded as-is (IDOR).
    verify(clusterApiService, times(1))
        .getAivenServiceAccountDetails(
            anyString(), anyString(), eq("victim-service-account"), anyInt());
  }

  @Test
  