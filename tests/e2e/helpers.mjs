import { $ } from "zx";

$.verbose = false;

const RUNNER_KEY = process.env.RUNNER_KEY;
if (!RUNNER_KEY) throw new Error("RUNNER_KEY env var not set");

const SSH_OPTS = [
  "-o", "StrictHostKeyChecking=no",
  "-o", "UserKnownHostsFile=/dev/null",
  "-o", "ConnectTimeout=15",
  "-o", "ServerAliveInterval=10",
  "-o", "LogLevel=ERROR",
  "-o", "IdentitiesOnly=yes",
  "-i", RUNNER_KEY,
];

const FW_JUMP_PROXY = [
  "ssh", ...SSH_OPTS, "-p", "2223", "-W", "%h:%p", "root@127.0.0.1",
].join(" ");

export async function fw(cmd) {
  const r = await $`ssh ${SSH_OPTS} -o ${`ProxyCommand=${FW_JUMP_PROXY}`} root@192.168.1.1 ${cmd}`;
  return r.stdout.trim();
}

export async function cl(cmd) {
  const r = await $`ssh ${SSH_OPTS} -p 2223 root@127.0.0.1 ${cmd}`;
  return r.stdout.trim();
}

export async function up(cmd) {
  const r = await $`ssh ${SSH_OPTS} -p 2224 root@127.0.0.1 ${cmd}`;
  return r.stdout.trim();
}

export async function fwOk(cmd) {
  try {
    await fw(cmd);
    return true;
  } catch {
    return false;
  }
}

export async function clOk(cmd) {
  try {
    await cl(cmd);
    return true;
  } catch {
    return false;
  }
}

export async function upOk(cmd) {
  try {
    await up(cmd);
    return true;
  } catch {
    return false;
  }
}

export function sleep(seconds) {
  return new Promise((resolve) => setTimeout(resolve, seconds * 1000));
}

export async function waitFor(fn, { timeout = 180, interval = 5, label = "" } = {}) {
  const deadline = Date.now() + timeout * 1000;
  while (Date.now() < deadline) {
    if (await fn()) return true;
    await sleep(interval);
  }
  return false;
}
