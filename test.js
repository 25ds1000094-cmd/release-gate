const assert = require("assert");
const http = require("http");

const PORT = 3456;

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

function request(body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);

    const req = http.request(
      {
        hostname: "127.0.0.1",
        port: PORT,
        path: "/release-gate",
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(data)
        }
      },
      (res) => {
        let response = "";

        res.on("data", (chunk) => {
          response += chunk;
        });

        res.on("end", () => {
          resolve({
            status: res.statusCode,
            body: JSON.parse(response)
          });
        });
      }
    );

    req.on("error", reject);

    req.write(data);
    req.end();
  });
}

function startServer() {
  return new Promise((resolve) => {
    process.env.PORT = PORT;

    const server = require("./server");

    setTimeout(() => resolve(server), 500);
  });
}

function clone(object) {
  return JSON.parse(JSON.stringify(object));
}

async function main() {
  const server = await startServer();

  try {
    // ------------------------------------------
    // Safe request
    // ------------------------------------------

    let result = await request(SAFE_REQUEST);

    assert.strictEqual(result.status, 200);
    assert.strictEqual(result.body.decision, "promote");
    assert.deepStrictEqual(result.body.violations, []);

    // ------------------------------------------
    // Extra permission
    // ------------------------------------------

    let test = clone(SAFE_REQUEST);
    test.workflow.permissions.admin = "write";

    result = await request(test);

    assert.strictEqual(result.body.decision, "block");
    assert(result.body.violations.includes("EXCESS_PERMISSION"));

    // ------------------------------------------
    // Unsafe PR trigger
    // ------------------------------------------

    test = clone(SAFE_REQUEST);
    test.workflow.trigger = "pull_request_target";

    result = await request(test);

    assert(result.body.violations.includes("UNSAFE_PR_TRIGGER"));

    // ------------------------------------------
    // Tests incomplete
    // ------------------------------------------

    test = clone(SAFE_REQUEST);
    test.workflow.testsPassed = false;

    result = await request(test);

    assert(result.body.violations.includes("TESTS_INCOMPLETE"));

    // ------------------------------------------
    // Mutable third-party action
    // ------------------------------------------

    test = clone(SAFE_REQUEST);
    test.workflow.actions = [
      {
        owner: "docker",
        name: "build-push-action",
        ref: "v6"
      }
    ];

    result = await request(test);

    assert(result.body.violations.includes("MUTABLE_ACTION"));

    // ------------------------------------------
    // Single-stage image
    // ------------------------------------------

    test = clone(SAFE_REQUEST);
    test.image.multiStage = false;

    result = await request(test);

    assert(result.body.violations.includes("SINGLE_STAGE_IMAGE"));

    // ------------------------------------------
    // Root runtime
    // ------------------------------------------

    test = clone(SAFE_REQUEST);
    test.image.runsAsRoot = true;

    result = await request(test);

    assert(result.body.violations.includes("ROOT_RUNTIME"));

    // ------------------------------------------
    // Secret in image
    // ------------------------------------------

    test = clone(SAFE_REQUEST);
    test.image.secretMode = "copy";

    result = await request(test);

    assert(result.body.violations.includes("SECRET_IN_LAYER"));

    // ------------------------------------------
    // Critical vulnerability
    // ------------------------------------------

    test = clone(SAFE_REQUEST);
    test.image.criticalVulnerabilities = 1;

    result = await request(test);

    assert(result.body.violations.includes("CRITICAL_CVE"));

    // ------------------------------------------
    // Unpinned image
    // ------------------------------------------

    test = clone(SAFE_REQUEST);
    test.image.digestPinned = false;

    result = await request(test);

    assert(result.body.violations.includes("UNPINNED_IMAGE"));

    // ------------------------------------------
    // Production wrong branch
    // ------------------------------------------

    test = clone(SAFE_REQUEST);
    test.target = "production";
    test.event = "push";
    test.ref = "refs/heads/develop";
    test.workflow.trigger = "push";
    test.workflow.environmentApproval = true;

    result = await request(test);

    assert(result.body.violations.includes("INVALID_PRODUCTION_REF"));

    // ------------------------------------------
    // Production approval
    // ------------------------------------------

    test = clone(SAFE_REQUEST);
    test.target = "production";
    test.event = "push";
    test.ref = "refs/heads/main";
    test.workflow.trigger = "push";

    result = await request(test);

    assert(result.body.violations.includes("APPROVAL_REQUIRED"));

    // ------------------------------------------
    // Multiple failures
    // ------------------------------------------

    test = clone(SAFE_REQUEST);

    test.workflow.permissions.extra = "write";
    test.workflow.trigger = "pull_request_target";
    test.workflow.testsPassed = false;

    test.image.multiStage = false;
    test.image.runsAsRoot = true;
    test.image.secretMode = "copy";
    test.image.criticalVulnerabilities = 2;
    test.image.digestPinned = false;

    result = await request(test);

    const violations = result.body.violations;

    assert(violations.includes("EXCESS_PERMISSION"));
    assert(violations.includes("UNSAFE_PR_TRIGGER"));
    assert(violations.includes("TESTS_INCOMPLETE"));
    assert(violations.includes("SINGLE_STAGE_IMAGE"));
    assert(violations.includes("ROOT_RUNTIME"));
    assert(violations.includes("SECRET_IN_LAYER"));
    assert(violations.includes("CRITICAL_CVE"));
    assert(violations.includes("UNPINNED_IMAGE"));

    console.log("ALL RELEASE-GATE TESTS PASSED");
  } finally {
    server.close();
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});

