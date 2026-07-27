"use strict";

const fs = require("fs");
const path = require("path");
const https = require("https");

const RUNTIME_DOCS_URL = "https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html";
const REPO_ROOT = path.resolve(__dirname, "..");
const STATE_FILE = path.join(REPO_ROOT, ".github", "lambda-runtime.json");

const TARGET_FILES = [
  {
    file: path.join(REPO_ROOT, ".github", "workflows", "test-audit.yml"),
    replacers: [
      {
        pattern: /\b24\.x\b/g,
        replacement: (major) => `${major}.x`
      }
    ]
  },
  {
    file: path.join(REPO_ROOT, ".github", "workflows", "auto-deps-update.yml"),
    replacers: [
      {
        pattern: /\b24\.x\b/g,
        replacement: (major) => `${major}.x`
      }
    ]
  }
];

function writeGitHubOutput(key, value) {
  if (!process.env.GITHUB_OUTPUT) {
    return;
  }

  fs.appendFileSync(process.env.GITHUB_OUTPUT, `${key}=${value}\n`);
}

function requestWithRedirects(url, maxRedirects = 5) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, {
      timeout: 15000,
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; cwe-collector-runtime-sync/1.0)",
        Accept: "text/html,application/xhtml+xml"
      }
    }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        if (maxRedirects <= 0) {
          reject(new Error("Too many redirects while fetching Lambda runtime docs"));
          return;
        }
        const redirectedUrl = new URL(res.headers.location, url).toString();
        resolve(requestWithRedirects(redirectedUrl, maxRedirects - 1));
        return;
      }

      if (res.statusCode !== 200) {
        reject(new Error(`Unexpected HTTP status ${res.statusCode}`));
        return;
      }

      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        body += chunk;
      });
      res.on("end", () => resolve(body));
    });

    req.on("timeout", () => {
      req.destroy(new Error("Request timed out"));
    });
    req.on("error", reject);
  });
}

async function fetchHtmlWithRetry(url, attempts = 3) {
  let lastError;
  for (let i = 1; i <= attempts; i += 1) {
    try {
      return await requestWithRedirects(url);
    } catch (error) {
      lastError = error;
      if (i === attempts) {
        break;
      }
    }
  }
  throw lastError;
}

function parseHighestNodeRuntimeMajor(html) {
  const regex = /\bnodejs(\d+)\.x\b/gi;
  const majors = new Set();
  let match = regex.exec(html);

  while (match !== null) {
    const major = Number(match[1]);
    if (Number.isInteger(major) && major >= 10) {
      majors.add(major);
    }
    match = regex.exec(html);
  }

  if (majors.size === 0) {
    throw new Error("No Lambda Node.js runtimes were parsed from AWS docs");
  }

  return Math.max(...majors);
}

function readStateMajor() {
  if (!fs.existsSync(STATE_FILE)) {
    return null;
  }

  const raw = fs.readFileSync(STATE_FILE, "utf8");
  const state = JSON.parse(raw);
  return Number(state.major);
}

function writeStateMajor(major) {
  const payload = {
    major,
    runtime: `nodejs${major}.x`,
    updatedAt: new Date().toISOString()
  };
  fs.writeFileSync(STATE_FILE, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
}

function updateTargetFiles(targetMajor) {
  const changed = [];

  for (const item of TARGET_FILES) {
    const original = fs.readFileSync(item.file, "utf8");
    let next = original;

    for (const replacer of item.replacers) {
      next = next.replace(replacer.pattern, replacer.replacement(targetMajor));
    }

    if (next !== original) {
      fs.writeFileSync(item.file, next, "utf8");
      changed.push(path.relative(REPO_ROOT, item.file));
    }
  }

  return changed;
}

async function main() {
  try {
    const html = await fetchHtmlWithRetry(RUNTIME_DOCS_URL);
    const targetMajor = parseHighestNodeRuntimeMajor(html);
    const targetRuntime = `nodejs${targetMajor}.x`;
    const currentMajor = readStateMajor();

    const shouldUpdate = currentMajor !== targetMajor;
    let changedFiles = [];

    if (shouldUpdate) {
      changedFiles = updateTargetFiles(targetMajor);
      writeStateMajor(targetMajor);
      changedFiles.push(path.relative(REPO_ROOT, STATE_FILE));
    }

    console.log(JSON.stringify({
      currentMajor,
      targetMajor,
      targetRuntime,
      changed: shouldUpdate,
      changedFiles
    }, null, 2));

    writeGitHubOutput("changed", shouldUpdate ? "true" : "false");
    writeGitHubOutput("target_major", String(targetMajor));
    writeGitHubOutput("target_runtime", targetRuntime);
    writeGitHubOutput("changed_files", changedFiles.join(","));
  } catch (error) {
    console.error(`::error::${error.message}`);
    process.exit(1);
  }
}

main();