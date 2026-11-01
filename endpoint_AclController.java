  @RequestMapping(
      value = "/getAivenServiceAccount",
      method = RequestMethod.GET,
      produces = {MediaType.APPLICATION_JSON_VALUE})
  public ResponseEntity<ServiceAccountDetails> getAivenServiceAccountDetails(
      @RequestParam("env") String envId,
      @RequestParam("topicName") String topicName,
      @RequestParam(value = "userName") String userName,
      @RequestParam(value = "aclReqNo") String aclReqNo) {
    return new ResponseEntity<>(
        aclControllerService.getAivenServiceAccountDetails(envId, topicName, userName, aclReqNo),
        HttpStatus.OK);
  }
