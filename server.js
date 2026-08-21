const express = require("express");

const app = express();

app.use(express.json());

/*
 * POST /release-gate
 *
 * Receives release metadata and returns:
 *
 * {
 *   "decision": "promote | block",
 *   "violations": ["CODE", "..."]
 * }
 */
app.post("/release-gate", (req, res) => {
  const {
    target,
    event,
    ref,
    workflow = {},
    image = {}
  } = req.body;

  const violations = [];

  // ==================================================
  // 1. PERMISSIONS
  //
  // Must be EXACTLY:
  // contents: read
  // packages: write
  // id-token: none
  // ==================================================

  const expectedPermissions = {
    contents: "read",
    packages: "write",
    "id-token": "none"
  };

  const actualPermissions = workflow.permissions || {};

  const actualKeys = Object.keys(actualPermissions);
  const expectedKeys = Object.keys(expectedPermissions);

  const permissionsAreCorrect =
    actualKeys.length === expectedKeys.length &&
    expectedKeys.every(
      (key) => actualPermissions[key] === expectedPermissions[key]
    );

  if (!permissionsAreCorrect) {
    violations.push("EXCESS_PERMISSION");
  }

  // ==================================================
  // 2. PULL REQUEST TRIGGER
  //
  // A pull request must use:
  // pull_request
  //
  // It must NOT use:
  // pull_request_target
  // ==================================================

  if (
    event === "pull_request" &&
    workflow.trigger !== "pull_request"
  ) {
    violations.push("UNSAFE_PR_TRIGGER");
  }

  // ==================================================
  // 3. TESTS
  //
  // Tests must pass.
  // Complete matrix must finish.
  // failFast must be false.
  // ==================================================

  if (
    workflow.testsPassed !== true ||
    workflow.matrixComplete !== true ||
    workflow.failFast !== false
  ) {
    violations.push("TESTS_INCOMPLETE");
  }

  // ==================================================
  // 4. ACTION PINNING
  //
  // Actions owned by "actions" may use tags.
  //
  // Every other action must use a full 40-character
  // lowercase hexadecimal commit SHA.
  // ==================================================

  const fullSha = /^[0-9a-f]{40}$/;

  for (const action of workflow.actions || []) {
    if (
      action.owner !== "actions" &&
      !fullSha.test(action.ref || "")
    ) {
      violations.push("MUTABLE_ACTION");
      break;
    }
  }

  // ==================================================
  // 5. DOCKER IMAGE
  // ==================================================

  // Must be multi-stage.
  if (image.multiStage !== true) {
    violations.push("SINGLE_STAGE_IMAGE");
  }

  // Must NOT run as root.
  if (image.runsAsRoot !== false) {
    violations.push("ROOT_RUNTIME");
  }

  // Only "none" or "buildkit" are allowed.
  if (!["none", "buildkit"].includes(image.secretMode)) {
    violations.push("SECRET_IN_LAYER");
  }

  // Must have zero critical vulnerabilities.
  if (image.criticalVulnerabilities !== 0) {
    violations.push("CRITICAL_CVE");
  }

  // Image must be referenced by digest.
  if (image.digestPinned !== true) {
    violations.push("UNPINNED_IMAGE");
  }

  // ==================================================
  // 6. PRODUCTION
  //
  // Production requires:
  //
  // event = push
  // ref = refs/heads/main
  // environmentApproval = true
  // ==================================================

  if (target === "production") {
    if (
      event !== "push" ||
      ref !== "refs/heads/main"
    ) {
      violations.push("INVALID_PRODUCTION_REF");
    }

    if (workflow.environmentApproval !== true) {
      violations.push("APPROVAL_REQUIRED");
    }
  }

  // ==================================================
  // 7. FINAL DECISION
  // ==================================================

  const decision =
    violations.length === 0
      ? "promote"
      : "block";

  res.json({
    decision,
    violations
  });
});


// ====================================================
// HEALTH CHECK
// ====================================================

app.get("/", (req, res) => {
  res.json({
    service: "TDS GA7 Release Gate",
    status: "ok"
  });
});


// ====================================================
// START SERVER
// ====================================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Release gate running on port ${PORT}`);
});
