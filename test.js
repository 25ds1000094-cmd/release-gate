const assert = require("assert");


// ====================================================
// SAFE BASE REQUEST
// ====================================================

const SAFE_REQUEST = {
  target: "preview",
  event: "pull_request",
  ref: "refs/heads/feature/test",

  workflow: {
    trigger: "pull_request",

    permissions: {
      contents: "read",
      packages: "write",
      "id-token": "none"
    },

    testsPassed: true,
    matrixComplete: true,
    failFast: false,

    actions: [
      {
        owner: "actions",
        name: "checkout",
        ref: "v4"
      }
    ]
  },

  image: {
    multiStage: true,
    runsAsRoot: false,
    secretMode: "none",
    criticalVulnerabilities: 0,
    digestPinned: true
  }
};


// ====================================================
// COPY OBJECT
// ====================================================

function clone(object) {
  return JSON.parse(JSON.stringify(object));
}


// ====================================================
// POLICY FUNCTION
//
// This is the same policy used by the server.
// ====================================================

function evaluatePolicy(body) {
  const {
    target,
    event,
    ref,
    workflow = {},
    image = {}
  } = body;

  const violations = [];


  // Permissions

  const expectedPermissions = {
    contents: "read",
    packages: "write",
    "id-token": "none"
  };

  const actualPermissions = workflow.permissions || {};

  const permissionsCorrect =
    Object.keys(actualPermissions).length === 3 &&
    actualPermissions.contents === "read" &&
    actualPermissions.packages === "write" &&
    actualPermissions["id-token"] === "none";

  if (!permissionsCorrect) {
    violations.push("EXCESS_PERMISSION");
  }


  // Pull request trigger

  if (
    event === "pull_request" &&
    workflow.trigger !== "pull_request"
  ) {
    violations.push("UNSAFE_PR_TRIGGER");
  }


  // Tests

  if (
    workflow.testsPassed !== true ||
    workflow.matrixComplete !== true ||
    workflow.failFast !== false
  ) {
    violations.push("TESTS_INCOMPLETE");
  }


  // Actions

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


  // Image

  if (image.multiStage !== true) {
    violations.push("SINGLE_STAGE_IMAGE");
  }

  if (image.runsAsRoot !== false) {
    violations.push("ROOT_RUNTIME");
  }

  if (!["none", "buildkit"].includes(image.secretMode)) {
    violations.push("SECRET_IN_LAYER");
  }

  if (image.criticalVulnerabilities !== 0) {
    violations.push("CRITICAL_CVE");
  }

  if (image.digestPinned !== true) {
    violations.push("UNPINNED_IMAGE");
  }


  // Production

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


  return {
    decision: violations.length === 0
      ? "promote"
      : "block",

    violations
  };
}


// ====================================================
// TEST 1: SAFE REQUEST
// ====================================================

let result = evaluatePolicy(
  clone(SAFE_REQUEST)
);

assert.strictEqual(
  result.decision,
  "promote"
);

assert.deepStrictEqual(
  result.violations,
  []
);


// ====================================================
// TEST 2: EXTRA PERMISSION
// ====================================================

let test = clone(SAFE_REQUEST);

test.workflow.permissions.admin = "write";

result = evaluatePolicy(test);

assert.strictEqual(
  result.decision,
  "block"
);

assert(
  result.violations.includes("EXCESS_PERMISSION")
);


// ====================================================
// TEST 3: UNSAFE PR TRIGGER
// ====================================================

test = clone(SAFE_REQUEST);

test.workflow.trigger = "pull_request_target";

result = evaluatePolicy(test);

assert(
  result.violations.includes("UNSAFE_PR_TRIGGER")
);


// ====================================================
// TEST 4: TESTS FAILED
// ====================================================

test = clone(SAFE_REQUEST);

test.workflow.testsPassed = false;

result = evaluatePolicy(test);

assert(
  result.violations.includes("TESTS_INCOMPLETE")
);


// ====================================================
// TEST 5: MATRIX INCOMPLETE
// ====================================================

test = clone(SAFE_REQUEST);

test.workflow.matrixComplete = false;

result = evaluatePolicy(test);

assert(
  result.violations.includes("TESTS_INCOMPLETE")
);


// ====================================================
// TEST 6: FAIL FAST TRUE
// ====================================================

test = clone(SAFE_REQUEST);

test.workflow.failFast = true;

result = evaluatePolicy(test);

assert(
  result.violations.includes("TESTS_INCOMPLETE")
);


// ====================================================
// TEST 7: MUTABLE THIRD-PARTY ACTION
// ====================================================

test = clone(SAFE_REQUEST);

test.workflow.actions = [
  {
    owner: "docker",
    name: "build-push-action",
    ref: "v6"
  }
];

result = evaluatePolicy(test);

assert(
  result.violations.includes("MUTABLE_ACTION")
);


// ====================================================
// TEST 8: SINGLE-STAGE IMAGE
// ====================================================

test = clone(SAFE_REQUEST);

test.image.multiStage = false;

result = evaluatePolicy(test);

assert(
  result.violations.includes("SINGLE_STAGE_IMAGE")
);


// ====================================================
// TEST 9: ROOT RUNTIME
// ====================================================

test = clone(SAFE_REQUEST);

test.image.runsAsRoot = true;

result = evaluatePolicy(test);

assert(
  result.violations.includes("ROOT_RUNTIME")
);


// ====================================================
// TEST 10: SECRET IN IMAGE
// ====================================================

test = clone(SAFE_REQUEST);

test.image.secretMode = "copy";

result = evaluatePolicy(test);

assert(
  result.violations.includes("SECRET_IN_LAYER")
);


// ====================================================
// TEST 11: CRITICAL CVE
// ====================================================

test = clone(SAFE_REQUEST);

test.image.criticalVulnerabilities = 1;

result = evaluatePolicy(test);

assert(
  result.violations.includes("CRITICAL_CVE")
);


// ====================================================
// TEST 12: UNPINNED IMAGE
// ====================================================

test = clone(SAFE_REQUEST);

test.image.digestPinned = false;

result = evaluatePolicy(test);

assert(
  result.violations.includes("UNPINNED_IMAGE")
);


// ====================================================
// TEST 13: INVALID PRODUCTION REF
// ====================================================

test = clone(SAFE_REQUEST);

test.target = "production";
test.event = "push";
test.ref = "refs/heads/develop";
test.workflow.trigger = "push";
test.workflow.environmentApproval = true;

result = evaluatePolicy(test);

assert(
  result.violations.includes("INVALID_PRODUCTION_REF")
);


// ====================================================
// TEST 14: APPROVAL REQUIRED
// ====================================================

test = clone(SAFE_REQUEST);

test.target = "production";
test.event = "push";
test.ref = "refs/heads/main";
test.workflow.trigger = "push";

result = evaluatePolicy(test);

assert(
  result.violations.includes("APPROVAL_REQUIRED")
);


// ====================================================
// TEST 15: MULTIPLE FAILURES
// ====================================================

test = clone(SAFE_REQUEST);

test.workflow.permissions.extra = "write";
test.workflow.trigger = "pull_request_target";
test.workflow.testsPassed = false;

test.image.multiStage = false;
test.image.runsAsRoot = true;
test.image.secretMode = "copy";
test.image.criticalVulnerabilities = 2;
test.image.digestPinned = false;

result = evaluatePolicy(test);

assert(
  result.violations.includes("EXCESS_PERMISSION")
);

assert(
  result.violations.includes("UNSAFE_PR_TRIGGER")
);

assert(
  result.violations.includes("TESTS_INCOMPLETE")
);

assert(
  result.violations.includes("SINGLE_STAGE_IMAGE")
);

assert(
  result.violations.includes("ROOT_RUNTIME")
);

assert(
  result.violations.includes("SECRET_IN_LAYER")
);

assert(
  result.violations.includes("CRITICAL_CVE")
);

assert(
  result.violations.includes("UNPINNED_IMAGE")
);


// ====================================================
// ALL TESTS PASSED
// ====================================================

console.log("====================================");
console.log("ALL RELEASE-GATE TESTS PASSED");
console.log("====================================");
