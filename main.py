from fastapi import FastAPI
import re

app = FastAPI()

SHA40 = re.compile(r"^[0-9a-f]{40}$")


@app.post("/release-gate")
def release_gate(payload: dict):
    violations = []

    workflow = payload.get("workflow", {})
    image = payload.get("image", {})

    # Permissions
    required_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none"
    }

    if workflow.get("permissions", {}) != required_permissions:
        violations.append("EXCESS_PERMISSION")

    # Pull request trigger
    if payload.get("event") == "pull_request":
        if workflow.get("trigger") != "pull_request":
            violations.append("UNSAFE_PR_TRIGGER")

    # Tests
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # Actions
    for action in workflow.get("actions", []):
        if action.get("owner") == "actions":
            continue

        ref = action.get("ref", "")

        if not SHA40.fullmatch(ref):
            violations.append("MUTABLE_ACTION")
            break

    # Image
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    if image.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # Production
    if payload.get("target") == "production":

        if (
            payload.get("event") != "push"
            or workflow.get("trigger") != "push"
            or payload.get("ref") != "refs/heads/main"
        ):
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    violations = list(dict.fromkeys(violations))

    return {
        "decision": "promote" if not violations else "block",
        "violations": violations
    }