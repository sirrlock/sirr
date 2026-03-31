#!/usr/bin/env node
// Downloads the sirr CLI binary for the current platform at npm postinstall time.

import { createWriteStream, mkdirSync, chmodSync, existsSync, unlinkSync } from "fs";
import { pipeline } from "stream/promises";
import { execFileSync } from "child_process";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = "sirrlock/sirr";

const PLATFORM_MAP = {
  darwin: "darwin",
  linux: "linux",
  win32: "windows",
};

const ARCH_MAP = {
  x64: "x64",
  arm64: "arm64",
};

async function main() {
  const os = PLATFORM_MAP[process.platform];
  const arch = ARCH_MAP[process.arch];

  if (!os || !arch) {
    console.error(`Unsupported platform: ${process.platform}-${process.arch}`);
    process.exit(1);
  }

  // Resolve latest version from GitHub
  const version =
    process.env.SIRR_VERSION ||
    (await fetch(`https://api.github.com/repos/${REPO}/releases/latest`)
      .then((r) => r.json())
      .then((d) => d.tag_name));

  if (!version) {
    console.error("Could not determine latest version");
    process.exit(1);
  }

  const isWindows = os === "windows";
  const binaryName = isWindows ? "sirr.exe" : "sirr";
  const ext = isWindows ? "zip" : "tar.gz";
  const archive = `sirr-${os}-${arch}.${ext}`;
  const url = `https://github.com/${REPO}/releases/download/${version}/${archive}`;

  console.log(`Downloading sirr ${version} for ${os}-${arch}...`);

  const binDir = join(__dirname, "bin");
  mkdirSync(binDir, { recursive: true });

  const archivePath = join(binDir, archive);

  // Download
  const res = await fetch(url);
  if (!res.ok) {
    console.error(`Failed to download: ${url} (${res.status})`);
    process.exit(1);
  }

  const fileStream = createWriteStream(archivePath);
  await pipeline(res.body, fileStream);

  // Extract — using execFileSync to avoid shell injection
  if (isWindows) {
    execFileSync("powershell", [
      "-Command",
      `Expand-Archive -Force '${archivePath}' '${binDir}'`,
    ], { stdio: "inherit" });
  } else {
    execFileSync("tar", ["xzf", archivePath, "-C", binDir], {
      stdio: "inherit",
    });
  }

  // Clean up archive
  try { unlinkSync(archivePath); } catch {}

  // Ensure binary is executable
  const binaryPath = join(binDir, binaryName);
  if (existsSync(binaryPath) && !isWindows) {
    chmodSync(binaryPath, 0o755);
  }

  console.log(`Installed sirr to ${binaryPath}`);
}

main().catch((err) => {
  console.error("Installation failed:", err.message);
  process.exit(1);
});
