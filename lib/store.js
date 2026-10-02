import fs from "node:fs";
import { rm } from "node:fs/promises";
import { Client } from "ssh2";
import git from "isomorphic-git";

const DIR = "/tmp/or-desk-repo";
const FILE = `${DIR}/store.json`;
const REPO_URL = "https://github.com/thane-eng/or-assessment-store.git";
const REPO = "thane-eng/or-assessment-store.git";
const HOST_FP = "f83898df0bef57a4ee24985ba598ac17fccb0c0d333cc4af1dd92be14bc23aa5";

let chain = Promise.resolve();

function locked(fn) {
  const run = chain.then(fn, fn);
  chain = run.then(
    () => {},
    () => {},
  );
  return run;
}

function privateKey() {
  const key = process.env.OR_DEPLOY_KEY || "";
  if (!key.includes("OPENSSH PRIVATE KEY")) throw new Error("Storage is not connected yet.");
  return key.includes("\\n") ? key.replace(/\\n/g, "\n") : key;
}

function flushEnd(buffer) {
  let offset = 0;
  while (buffer.length - offset >= 4) {
    const len = Number.parseInt(buffer.toString("utf8", offset, offset + 4), 16);
    if (!Number.isFinite(len)) return -1;
    if (len === 0) return offset + 4;
    if (len < 4 || buffer.length - offset < len) return -1;
    offset += len;
  }
  return -1;
}

function openChannel(stream) {
  let buf = Buffer.alloc(0);
  let ended = false;
  let error = null;
  const readers = [];
  function kick() {
    while (readers.length) {
      const taken = readers[0](buf, ended, error);
      if (taken == null) return;
      buf = buf.subarray(taken);
      readers.shift();
    }
  }
  stream.on("data", (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    kick();
  });
  stream.on("error", (err) => {
    error = err;
    ended = true;
    kick();
  });
  stream.on("close", () => {
    ended = true;
    kick();
  });
  return {
    advertisement() {
      return new Promise((resolve, reject) => {
        readers.push((buffer, end, err) => {
          if (err) {
            reject(err);
            return buffer.length;
          }
          const endAt = flushEnd(buffer);
          if (endAt < 0) {
            if (end) {
              reject(new Error("Git remote closed before the advertisement finished."));
              return buffer.length;
            }
            return null;
          }
          resolve(buffer.subarray(0, endAt));
          return endAt;
        });
        kick();
      });
    },
    rest() {
      return new Promise((resolve, reject) => {
        readers.push((buffer, end, err) => {
          if (err) {
            reject(err);
            return buffer.length;
          }
          if (!end) return null;
          resolve(buffer);
          return buffer.length;
        });
        kick();
      });
    },
  };
}

function sshGit(service, body) {
  const key = privateKey();
  return new Promise((resolve, reject) => {
    const conn = new Client();
    const timer = setTimeout(() => {
      conn.end();
      reject(new Error("Git storage timed out."));
    }, 20000);
    const finish = (err, value) => {
      clearTimeout(timer);
      conn.end();
      if (err) reject(err);
      else resolve(value);
    };
    conn
      .on("ready", () => {
        conn.exec(`${service} '${REPO}'`, (err, stream) => {
          if (err) return finish(err);
          const stderr = [];
          stream.stderr.on("data", (chunk) => stderr.push(chunk));
          const channel = openChannel(stream);
          channel.advertisement().then(async (ad) => {
            if (!body) {
              stream.end();
              const line = `# service=${service}\n`;
              const len = (line.length + 4).toString(16).padStart(4, "0");
              finish(null, Buffer.concat([Buffer.from(`${len}${line}0000`), ad]));
              return;
            }
            const rest = channel.rest();
            if (!stream.write(body)) await new Promise((done) => stream.once("drain", done));
            stream.end();
            finish(null, await rest);
          }).catch((error) => {
            const detail = Buffer.concat(stderr).toString("utf8").trim();
            finish(new Error(detail || error.message));
          });
        });
      })
      .on("error", (err) => finish(err))
      .connect({
        host: "github.com",
        port: 22,
        username: "git",
        privateKey: key,
        readyTimeout: 15000,
        hostHash: "sha256",
        hostVerifier(fingerprint) {
          return String(fingerprint).toLowerCase() === HOST_FP;
        },
      });
  });
}

async function collectBody(body) {
  if (!body) return Buffer.alloc(0);
  if (Buffer.isBuffer(body)) return body;
  if (body instanceof Uint8Array) return Buffer.from(body);
  if (Array.isArray(body)) return Buffer.concat(body.map((part) => Buffer.from(part)));
  const parts = [];
  for await (const part of body) parts.push(Buffer.from(part));
  return Buffer.concat(parts);
}

async function* oneChunk(buffer) {
  yield buffer;
}

const gitHttp = {
  async request({ url, method = "GET", body }) {
    const parsed = new URL(url);
    const service = parsed.searchParams.get("service")
      || (parsed.pathname.endsWith("git-receive-pack") ? "git-receive-pack" : "git-upload-pack");
    const payload = method === "GET" ? null : await collectBody(body);
    const bytes = await sshGit(service, payload);
    const kind = method === "GET" ? "advertisement" : "result";
    return {
      url,
      method,
      statusCode: 200,
      statusMessage: "OK",
      headers: { "content-type": `application/x-${service}-${kind}` },
      body: oneChunk(bytes),
    };
  },
};

async function refresh() {
  await rm(DIR, { recursive: true, force: true });
  await git.clone({
    fs,
    http: gitHttp,
    dir: DIR,
    url: REPO_URL,
    ref: "main",
    singleBranch: true,
    depth: 1,
  });
}

function strip(data) {
  return {
    lock: data.lock || null,
    engagements: Array.isArray(data.engagements) ? data.engagements : [],
    rev: data.rev || 0,
  };
}

function merge(remote, local) {
  const byId = new Map();
  for (const row of remote.engagements || []) byId.set(row.id, structuredClone(row));
  for (const row of local.engagements || []) {
    const prev = byId.get(row.id);
    if (!prev) {
      byId.set(row.id, structuredClone(row));
      continue;
    }
    const raters = new Map((prev.raters || []).map((rater) => [rater.id, structuredClone(rater)]));
    for (const rater of row.raters || []) {
      const old = raters.get(rater.id);
      if (!old || (rater.submittedAt && (!old.submittedAt || rater.submittedAt >= old.submittedAt))) {
        raters.set(rater.id, structuredClone(rater));
      }
    }
    prev.raters = [...raters.values()];
    prev.subjectName = row.subjectName || prev.subjectName;
    prev.subjectRole = row.subjectRole || prev.subjectRole;
    prev.site = row.site || prev.site;
  }
  const seen = new Set();
  const ordered = [];
  for (const row of [...(local.engagements || []), ...(remote.engagements || [])]) {
    if (seen.has(row.id) || !byId.has(row.id)) continue;
    seen.add(row.id);
    ordered.push(byId.get(row.id));
  }
  return {
    lock: remote.lock || local.lock || null,
    engagements: ordered,
    rev: Math.max(remote.rev || 0, local.rev || 0) + 1,
  };
}

async function readFresh() {
  await refresh();
  const data = JSON.parse(await fs.promises.readFile(FILE, "utf8"));
  data._sha = await git.resolveRef({ fs, dir: DIR, ref: "HEAD" });
  if (!Array.isArray(data.engagements)) data.engagements = [];
  if (!("lock" in data)) data.lock = null;
  return data;
}

async function writeFresh(desired, baseSha, mustMerge) {
  await refresh();
  const head = await git.resolveRef({ fs, dir: DIR, ref: "HEAD" });
  const remote = JSON.parse(await fs.promises.readFile(FILE, "utf8"));
  const next = mustMerge || (baseSha && baseSha !== head) ? merge(remote, desired) : { ...strip(desired), rev: (remote.rev || 0) + 1 };
  await fs.promises.writeFile(FILE, JSON.stringify(next));
  await git.add({ fs, dir: DIR, filepath: "store.json" });
  let sha = head;
  try {
    sha = await git.commit({
      fs,
      dir: DIR,
      message: "Update OR assessment store",
      author: { name: "OR Desk", email: "assessments@thecourageeconomy.net" },
    });
  } catch (err) {
    if (!/No changes|empty commit/i.test(err.message || "")) throw err;
    next._sha = head;
    return next;
  }
  await git.push({ fs, http: gitHttp, dir: DIR, remote: "origin", ref: "main" });
  next._sha = sha;
  return next;
}

export function loadStore() {
  return locked(() => readFresh());
}

export function saveStore(incoming) {
  const desired = strip(incoming);
  const baseSha = incoming._sha || null;
  return locked(async () => {
    let intent = desired;
    let mustMerge = false;
    let sha = baseSha;
    for (let attempt = 0; attempt < 5; attempt++) {
      try {
        return await writeFresh(intent, sha, mustMerge);
      } catch (err) {
        const retry = err.code === "PushRejectedError" || /not-fast-forward|rejected/i.test(err.message || "");
        if (!retry || attempt === 4) throw err;
        mustMerge = true;
        intent = strip(intent);
        sha = null;
      }
    }
    throw new Error("Could not save.");
  });
}
