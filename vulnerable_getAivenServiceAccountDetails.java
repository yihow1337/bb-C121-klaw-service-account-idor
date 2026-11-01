  public ServiceAccountDetails getAivenServiceAccountDetails(
      String envId, String topicName, String serviceAccount, String aclReqNo) {
    String loggedInUser = getCurrentUserName();
    int tenantId = commonUtilsService.getTenantId(loggedInUser);
    log.info(
        "Retrieving service account details for topic {} serviceAccount {}",
        topicName,
        serviceAccount);
    try {
      HandleDbRequests dbHandle = manageDatabase.getHandleDbRequests();
      Acl acl =
          dbHandle.getSyncAclsFromReqNo(
              Integer.parseInt(aclReqNo), commonUtilsService.getTenantId(loggedInUser));

      // Verify if loggedInUser belongs to the same team as the Subscription owner team
      if (!Objects.equals(acl.getTeamId(), commonUtilsService.getTeamId(loggedInUser))) {
        return new ServiceAccountDetails();
      }

      // Get details from Cluster Api
      KwClusters kwClusters =
          manageDatabase
              .getClusters(KafkaClustersType.KAFKA, tenantId)
              .get(commonUtilsService.getEnvDetails(envId, tenantId).getClusterId());
      return clusterApiService.getAivenServiceAccountDetails(
          kwClusters.getProjectName(), kwClusters.getServiceName(), serviceAccount, tenantId);
    } catch (Exception e) {
      log.error("Ignoring error while retrieving service account credentials {} ", e.toString());
    }
    return new ServiceAccountDetails();
  }
