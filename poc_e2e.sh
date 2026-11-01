#!/usr/bin/env bash
# Local e2e for C121 — Klaw getAivenServiceAccountDetails IDOR
# Requires JDK 17+ and network for Maven deps. Run from klaw repo root.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../src/klaw-r29" && pwd)"
export JAVA_HOME="${JAVA_HOME:-/workspace/bounty-research/tools/jdk-21.0.13+9}"
export PATH="$JAVA_HOME/bin:$PATH"
cd "$ROOT"
# Tests already patched into AclControllerServiceTest in this research checkout.
./mvnw -pl core -Dexec.skip=true \
  -Dtest=AclControllerServiceTest#getAivenServiceAccountDetails_idorAllowsAnyServiceAccountOnOwnAcl+getAivenServiceAccountDetails_rejectsWrongTeam \
  test
