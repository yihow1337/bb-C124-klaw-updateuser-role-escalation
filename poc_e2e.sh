#!/usr/bin/env bash
# Local e2e for C124 — Klaw updateUser role privilege escalation
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../src/klaw-r29" && pwd)"
export JAVA_HOME="${JAVA_HOME:-/workspace/bounty-research/tools/jdk-21.0.13+9}"
export PATH="$JAVA_HOME/bin:$PATH"
cd "$ROOT"
./mvnw -pl core -Dspotless.check.skip=true -Dexec.skip=true \
  -Dtest=UsersTeamsControllerServiceTest#updateUser_privEscalationViaCustomPrivilegedRole_succeedsBug+updateUser_assignLiteralSuperAdmin_stillBlocked+addNewUser_customPrivilegedRole_correctlyBlocked \
  test
