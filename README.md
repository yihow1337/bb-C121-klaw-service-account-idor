# PRIVATE REPORT DRAFT — C121 / R29-A
## Klaw: Cross-team Aiven service-account password IDOR via unbound `userName` on `/getAivenServiceAccount`

**Status:** CONFIRMED locally. NOT submitted. NOT disclosed. No public GitHub repo created yet.
**Program:** Bugcrowd — Aiven Managed Bug Bounty (`aiven-mbb-og`), public + paid (max $25,000).
**In-scope asset:** `github.com/Aiven-Open` → `https://github.com/Aiven-Open/klaw`
**Exact release/commit verified:** `f1c24b9d3c8a079dba0a54e7713a09fdd43a974b` (`v2.10.6-1-gf1c24b9`, Asia/Taipei 2026-11-02). Also present on tagged `v2.10.6`.
**Severity (researcher estimate):** High / Bugcrowd VRT ≈ **P2** — Broken Access Control › Privilege Escalation / Sensitive Data Exposure (password disclosure) enabling cross-team Kafka credential theft on Aiven-for-Kafka clusters managed by Klaw.
**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key) / CWE-863 (Incorrect Authorization) / CWE-200 (Exposure of Sensitive Information).

---

### Summary
`GET /getAivenServiceAccount` lets any authenticated user who owns **any** ACL subscription retrieve the **password of an arbitrary Aiven service account** on that environment’s Kafka cluster. The handler only checks that the supplied `aclReqNo` belongs to the caller’s team; it never binds the attacker-controlled `userName` (service-account principal) to `Acl.aclssl` (or to the ACL’s topic/env). Topic Overview already exposes other teams’ `acl_ssl` principals to any user with env access, so victim account names are enumerable without guessing.

### Fingerprint
| Field | Value |
|---|---|
| TARGET | Aiven-Open/klaw (Bugcrowd aiven-mbb-og) |
| COMPONENT | `AclControllerService.getAivenServiceAccountDetails` + `AclController.getAivenServiceAccountDetails` |
| ENTRY POINT | `GET /getAivenServiceAccount?env=&topicName=&userName=&aclReqNo=` (authenticated session) |
| SINK | `ClusterApiService.getAivenServiceAccountDetails` → cluster-api → Aiven `ServiceUser` credentials API → returns `{username,password}` |
| ROOT CAUSE | Authorization checks `acl.teamId == caller.teamId` only; request `userName`/`serviceAccount` is forwarded unbound; `topicName`/`env` also unbound to the ACL row |
| CWE | CWE-639 / CWE-863 / CWE-200 |
| IMPACT | Cross-team disclosure of Aiven Kafka service-account passwords → produce/consume as victim principal; multi-tenant tenant isolation break for Aiven-flavor clusters |
| PREREQUISITES | (1) Authenticated Klaw user; (2) at least one ACL row owned by caller’s team (`aclReqNo`); (3) env with Aiven-for-Apache-Kafka cluster wired to cluster-api; (4) knowledge of victim SA name (from `getTopicOverview` ACL list or other visibility) |

### Vulnerable code (exact)
`core/src/main/java/io/aiven/klaw/service/AclControllerService.java` (commit `f1c24b9…`):

```java
public ServiceAccountDetails getAivenServiceAccountDetails(
    String envId, String topicName, String serviceAccount, String aclReqNo) {
  ...
  Acl acl = dbHandle.getSyncAclsFromReqNo(Integer.parseInt(aclReqNo), tenantId);
  // ONLY check: same team as ACL row
  if (!Objects.equals(acl.getTeamId(), commonUtilsService.getTeamId(loggedInUser))) {
    return new ServiceAccountDetails();
  }
  KwClusters kwClusters = ... getEnvDetails(envId, tenantId).getClusterId() ...;
  // BUG: `serviceAccount` is the attacker-supplied request param, NOT acl.getAclssl()
  return clusterApiService.getAivenServiceAccountDetails(
      kwClusters.getProjectName(), kwClusters.getServiceName(), serviceAccount, tenantId);
}
```

Controller (`AclController.java`):

```java
@RequestMapping(value = "/getAivenServiceAccount", method = RequestMethod.GET, ...)
public ResponseEntity<ServiceAccountDetails> getAivenServiceAccountDetails(
    @RequestParam("env") String envId,
    @RequestParam("topicName") String topicName,
    @RequestParam(value = "userName") String userName,   // attacker-controlled
    @RequestParam(value = "aclReqNo") String aclReqNo) {
  return new ResponseEntity<>(
      aclControllerService.getAivenServiceAccountDetails(envId, topicName, userName, aclReqNo),
      HttpStatus.OK);
}
```

Trust-boundary failure: UI (`TopicSubscriptionsDetailsModal.tsx`) honestly passes the row’s `acl_ssl`, but the server treats `userName` as authoritative and never re-binds it to the authorized ACL object.

### Attack chain (harmless / synthetic)
1. Attacker (Team A) browses a topic owned by Team B via `GET /getTopicOverview?topicName=…` → reads Team B’s subscription `acl_ssl` = `victim-sa`.
2. Attacker uses any of Team A’s own ACL `req_no` as `aclReqNo`.
3. `GET /getAivenServiceAccount?env=<shared>&topicName=<anything>&userName=victim-sa&aclReqNo=<own>` → response includes `password` for `victim-sa`.
4. Attacker authenticates to the Aiven Kafka service as `victim-sa` and accesses topics authorized to that principal.

No destructive payload; synthetic passwords only in local unit PoC.

### Local proof (deterministic)
JDK Temurin 21.0.13+9. Two JUnit tests added under `AclControllerServiceTest`:

| Test | Expected | Result |
|---|---|---|
| `getAivenServiceAccountDetails_rejectsWrongTeam` (NEGATIVE) | Foreign-team ACL → empty details; cluster API **never** called | PASS |
| `getAivenServiceAccountDetails_idorAllowsAnyServiceAccountOnOwnAcl` (EXPLOIT) | Own-team ACL + **unrelated** `userName=victim-service-account` → cluster API called with that username; password `VICTIM_SECRET_PASSWORD` returned | PASS |

```
Tests run: 2, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

Command: see `poc_e2e.sh`. Artifacts: `surefire_result.txt`, PoC snippet, vulnerable method dump, `VERSIONS.txt`.

### Suggested fix
After the team check, bind the request principal (and ideally topic/env) to the ACL:

```java
if (!Objects.equals(serviceAccount, acl.getAclssl())
    && (acl.getAclssl() == null || !Set.of(acl.getAclssl().split(",")).contains(serviceAccount))) {
  return new ServiceAccountDetails(); // or 403
}
if (!Objects.equals(topicName, acl.getTopicname())
    || !Objects.equals(envId, acl.getEnvironment())) {
  return new ServiceAccountDetails();
}
```

Prefer always using `acl.getAclssl()` server-side and dropping the client `userName` parameter (issue #1673 only renames it — it does **not** fix authorization).

### Novelty gate
| Source | Result |
|---|---|
| GitHub Security Advisories for Aiven-Open/klaw | GHSA-rp26-qv9w-xr5q (`/resetMemoryCache`), GHSA-v7m7-fr8v-hpx2 (pwd hash disclosure), GHSA-75rx-m9vh-mm9p (case lockout) — **none** cover this endpoint |
| NVD / CVE search for Klaw service-account IDOR | No matching CVE |
| GitHub issues/PRs | #1673 (open) asks only to **rename** `userName`→`serviceAccountName`; does not discuss authz/IDOR. #1246/#1113 discuss assignment/sync of SAs, not password IDOR. |
| Web search | No public writeup of this IDOR |

**Verdict:** genuinely unknown / undiscovered relative to public sources as of 2026-11-02 (Asia/Taipei).

### Out of scope / not claimed
- Unauthenticated access (endpoint requires session; `/cache/**` etc. unrelated).
- Non-Aiven Kafka flavors (sink is Aiven Service User credentials API).
- Cluster-api itself (trusted backend; bug is core’s authorization).

### Researcher notes for submission (when approved)
- Bugcrowd VRT suggestion: Broken Access Control › Privilege Escalation (or Sensitive Data Exposure › Password Disclosure) — P2.
- Attach evidence tarball; do not include real Aiven customer credentials (none used).
- Do not open a public issue/PR until coordinated disclosure / program rules allow.

