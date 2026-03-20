#!/usr/bin/env node
// Unified entry point for the Uxarion CLI.

import { spawn, spawnSync } from "node:child_process";
import {
  createWriteStream,
  existsSync,
  mkdirSync,
  renameSync,
  unlinkSync,
} from "node:fs";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import path from "path";
import { pipeline } from "node:stream/promises";
import { Readable } from "node:stream";
import { fileURLToPath } from "url";

// __dirname equivalent in ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const require = createRequire(import.meta.url);
const packageMetadata = require("../package.json");

const PLATFORM_PACKAGE_BY_TARGET = {
  "x86_64-unknown-linux-musl": "uxarion-linux-x64",
  "aarch64-unknown-linux-musl": "uxarion-linux-arm64",
  "x86_64-apple-darwin": "uxarion-darwin-x64",
  "aarch64-apple-darwin": "uxarion-darwin-arm64",
  "x86_64-pc-windows-msvc": "uxarion-win32-x64",
  "aarch64-pc-windows-msvc": "uxarion-win32-arm64",
};

const RUNTIME_ARTIFACT_BY_TARGET = {
  "x86_64-unknown-linux-musl": {
    archiveName: `uxarion-${packageMetadata.version}-linux-x64.tar.xz`,
    platformName: "linux-x64",
  },
};

const UXARION_DOWNLOAD_BASE_URL =
  process.env.UXARION_DOWNLOAD_BASE_URL ||
  "https://github.com/rachidlaad/uxarion-downloads/releases/download";

const { platform, arch } = process;

let targetTriple = null;
switch (platform) {
  case "linux":
  case "android":
    switch (arch) {
      case "x64":
        targetTriple = "x86_64-unknown-linux-musl";
        break;
      case "arm64":
        targetTriple = "aarch64-unknown-linux-musl";
        break;
      default:
        break;
    }
    break;
  case "darwin":
    switch (arch) {
      case "x64":
        targetTriple = "x86_64-apple-darwin";
        break;
      case "arm64":
        targetTriple = "aarch64-apple-darwin";
        break;
      default:
        break;
    }
    break;
  case "win32":
    switch (arch) {
      case "x64":
        targetTriple = "x86_64-pc-windows-msvc";
        break;
      case "arm64":
        targetTriple = "aarch64-pc-windows-msvc";
        break;
      default:
        break;
    }
    break;
  default:
    break;
}

if (!targetTriple) {
  throw new Error(`Unsupported platform: ${platform} (${arch})`);
}

const platformPackage = PLATFORM_PACKAGE_BY_TARGET[targetTriple];
if (!platformPackage) {
  throw new Error(`Unsupported target triple: ${targetTriple}`);
}

const codexBinaryName = process.platform === "win32" ? "codex.exe" : "codex";
const localVendorRoot = path.join(__dirname, "..", "vendor");
const localBinaryPath = path.join(
  localVendorRoot,
  targetTriple,
  "codex",
  codexBinaryName,
);

// Use an asynchronous spawn instead of spawnSync so that Node is able to
// respond to signals (e.g. Ctrl-C / SIGINT) while the native binary is
// executing. This allows us to forward those signals to the child process
// and guarantees that when either the child terminates or the parent
// receives a fatal signal, both processes exit in a predictable manner.

function getUpdatedPath(newDirs) {
  const pathSep = process.platform === "win32" ? ";" : ":";
  const existingPath = process.env.PATH || "";
  const updatedPath = [
    ...newDirs,
    ...existingPath.split(pathSep).filter(Boolean),
  ].join(pathSep);
  return updatedPath;
}

function getUxarionCacheRoot() {
  const xdgCacheHome = process.env.XDG_CACHE_HOME;
  if (xdgCacheHome) {
    return path.join(xdgCacheHome, "uxarion");
  }
  return path.join(homedir(), ".cache", "uxarion");
}

/**
 * Use heuristics to detect the package manager that was used to install Uxarion
 * in order to give the user a hint about how to update it.
 */
function detectPackageManager() {
  const userAgent = process.env.npm_config_user_agent || "";
  if (/\bbun\//.test(userAgent)) {
    return "bun";
  }

  const execPath = process.env.npm_execpath || "";
  if (execPath.includes("bun")) {
    return "bun";
  }

  if (
    __dirname.includes(".bun/install/global") ||
    __dirname.includes(".bun\\install\\global")
  ) {
    return "bun";
  }

  return userAgent ? "npm" : null;
}

function getReinstallMessage() {
  const packageManager = detectPackageManager();
  const updateCommand =
    packageManager === "bun"
      ? "bun install -g uxarion@latest"
      : "npm install -g uxarion@latest";
  return `Missing optional dependency ${platformPackage}. Reinstall Uxarion: ${updateCommand}`;
}

async function downloadRuntimeVendorRoot() {
  const runtimeArtifact = RUNTIME_ARTIFACT_BY_TARGET[targetTriple];
  if (!runtimeArtifact) {
    return null;
  }

  const runtimeRoot = path.join(
    getUxarionCacheRoot(),
    "runtime",
    packageMetadata.version,
    targetTriple,
  );
  const vendorRoot = path.join(runtimeRoot, "package", "vendor");
  const cachedBinaryPath = path.join(
    vendorRoot,
    targetTriple,
    "codex",
    codexBinaryName,
  );
  if (existsSync(cachedBinaryPath)) {
    return vendorRoot;
  }

  mkdirSync(runtimeRoot, { recursive: true });
  const archivePath = path.join(runtimeRoot, runtimeArtifact.archiveName);
  if (!existsSync(archivePath)) {
    const archiveUrl = `${UXARION_DOWNLOAD_BASE_URL}/v${packageMetadata.version}/${runtimeArtifact.archiveName}`;
    // eslint-disable-next-line no-console
    console.error(
      `Downloading Uxarion runtime ${packageMetadata.version} for ${runtimeArtifact.platformName}...`,
    );
    const response = await fetch(archiveUrl);
    if (!response.ok || !response.body) {
      throw new Error(
        `Failed to download ${runtimeArtifact.archiveName} (${response.status} ${response.statusText})`,
      );
    }

    const partialArchivePath = `${archivePath}.partial`;
    try {
      await pipeline(
        Readable.fromWeb(response.body),
        createWriteStream(partialArchivePath),
      );
      renameSync(partialArchivePath, archivePath);
    } catch (error) {
      if (existsSync(partialArchivePath)) {
        unlinkSync(partialArchivePath);
      }
      throw error;
    }
  }

  const extractResult = spawnSync("tar", ["-xJf", archivePath, "-C", runtimeRoot], {
    stdio: "inherit",
  });
  if (extractResult.status !== 0) {
    throw new Error(
      `Failed to extract ${runtimeArtifact.archiveName} into ${runtimeRoot}`,
    );
  }
  if (!existsSync(cachedBinaryPath)) {
    throw new Error(`Downloaded runtime is missing ${cachedBinaryPath}`);
  }
  return vendorRoot;
}

let vendorRoot;
try {
  const packageJsonPath = require.resolve(`${platformPackage}/package.json`);
  vendorRoot = path.join(path.dirname(packageJsonPath), "vendor");
} catch {
  if (existsSync(localBinaryPath)) {
    vendorRoot = localVendorRoot;
  } else {
    vendorRoot = await downloadRuntimeVendorRoot();
  }
}

if (!vendorRoot) {
  throw new Error(getReinstallMessage());
}

const archRoot = path.join(vendorRoot, targetTriple);
const binaryPath = path.join(archRoot, "codex", codexBinaryName);

const additionalDirs = [];
const pathDir = path.join(archRoot, "path");
if (existsSync(pathDir)) {
  additionalDirs.push(pathDir);
}
const updatedPath = getUpdatedPath(additionalDirs);

const env = { ...process.env, PATH: updatedPath };
const packageManagerEnvVar =
  detectPackageManager() === "bun"
    ? "UXARION_MANAGED_BY_BUN"
    : "UXARION_MANAGED_BY_NPM";
env[packageManagerEnvVar] = "1";

const child = spawn(binaryPath, process.argv.slice(2), {
  stdio: "inherit",
  env,
});

child.on("error", (err) => {
  // Typically triggered when the binary is missing or not executable.
  // Re-throwing here will terminate the parent with a non-zero exit code
  // while still printing a helpful stack trace.
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});

// Forward common termination signals to the child so that it shuts down
// gracefully. In the handler we temporarily disable the default behavior of
// exiting immediately; once the child has been signaled we simply wait for
// its exit event which will in turn terminate the parent (see below).
const forwardSignal = (signal) => {
  if (child.killed) {
    return;
  }
  try {
    child.kill(signal);
  } catch {
    /* ignore */
  }
};

["SIGINT", "SIGTERM", "SIGHUP"].forEach((sig) => {
  process.on(sig, () => forwardSignal(sig));
});

// When the child exits, mirror its termination reason in the parent so that
// shell scripts and other tooling observe the correct exit status.
// Wrap the lifetime of the child process in a Promise so that we can await
// its termination in a structured way. The Promise resolves with an object
// describing how the child exited: either via exit code or due to a signal.
const childResult = await new Promise((resolve) => {
  child.on("exit", (code, signal) => {
    if (signal) {
      resolve({ type: "signal", signal });
    } else {
      resolve({ type: "code", exitCode: code ?? 1 });
    }
  });
});

if (childResult.type === "signal") {
  // Re-emit the same signal so that the parent terminates with the expected
  // semantics (this also sets the correct exit code of 128 + n).
  process.kill(process.pid, childResult.signal);
} else {
  process.exit(childResult.exitCode);
}
