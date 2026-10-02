import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { loadStore, saveStore } from "../lib/store.js";

const COOKIE = "or_desk";

const CATS = [
  { id: "slt-feedback", name: "Effectiveness of Feedback to SLT", short: "SLT Feedback", theme: "Value-added, timely, consistent, clear, actionable, simple." },
  { id: "svp-plant", name: "Quality of relationships with SVP / Plant Manager", short: "SVP / Plant Manager", theme: "Healthy pushback, structured time, verbal and written line up." },
  { id: "directors-mlm", name: "Quality of relationships with Directors and MLMs", short: "Directors & MLMs", theme: "Feedback valued and acted on; enough time; not only when convenient." },
  { id: "fleet", name: "Fleet Collaboration", short: "Fleet", theme: "Best practices across the fleet; strong ties to HR, Comms, Employee Concerns." },
];

const ITEMS = [
  ["s1", "slt-feedback", "Raises issues and observations the SLT would not have seen on its own."],
  ["s2", "slt-feedback", "Raises the issue while leadership can still change course."],
  ["s3", "slt-feedback", "Gives SLT feedback as a regular practice, not only when there is an emergent issue."],
  ["s4", "slt-feedback", "Describes issues clearly with actionable next steps."],
  ["p1", "svp-plant", "Discussions have healthy conflict from both sides to broaden perspectives and increase understanding."],
  ["p2", "svp-plant", "Puts time on the calendar for feedback."],
  ["p3", "svp-plant", "Challenges leaders to match what they say vs. what they put in writing."],
  ["p4", "svp-plant", "Keeps challenge about the work, not about status, saving face, or who won."],
  ["d1", "directors-mlm", "Spends enough time with Directors and mid-level managers to build working relationships."],
  ["d2", "directors-mlm", "Provides feedback when it is uncomfortable, not only when it is easy."],
  ["d3", "directors-mlm", "Directors and mid-level managers find the feedback useful rather than something to endure."],
  ["d4", "directors-mlm", "Leaders take action from the feedback."],
  ["f1", "fleet", "Brings practices and lessons from across the fleet."],
  ["f2", "fleet", "Makes what they learn usable for other sites."],
  ["f3", "fleet", "Relationships with HR, Communications, and Employee Concerns are developed and effective."],
].map(([id, categoryId, text]) => ({ id, categoryId, text }));

const VANTAGES = [
  "SLT member",
  "SVP / Plant Manager",
  "Director",
  "Mid-level manager",
  "HR / Communications / Employee Concerns",
  "Peer at another site",
  "Other",
];

function empty() {
  return { lock: null, engagements: [] };
}

function clean(value, max) {
  return String(value ?? "").trim().slice(0, max);
}

function token() {
  return randomBytes(24).toString("base64url");
}

function hashPassword(password, salt) {
  return createHash("sha256").update(`${salt}\n${password}`).digest("hex");
}

function sign(cookieKey) {
  return createHmac("sha256", cookieKey).update("ok").digest("hex");
}

function same(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && timingSafeEqual(left, right);
}

function readCookie(req) {
  const raw = req.headers.cookie || "";
  for (const part of raw.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === COOKIE) return decodeURIComponent(rest.join("="));
  }
  return "";
}

function originOf(req) {
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  const proto = req.headers["x-forwarded-proto"] || "https";
  return `${proto}://${host}`;
}

async function load() {
  const data = await loadStore();
  if (!data || !Array.isArray(data.engagements)) return empty();
  return data;
}

async function save(data) {
  const stored = await saveStore(data);
  data.lock = stored.lock;
  data.engagements = stored.engagements;
  data.rev = stored.rev;
  data._sha = stored._sha;
  return stored;
}

function authed(data, req) {
  if (!data.lock) return false;
  return same(readCookie(req), sign(data.lock.cookieKey));
}

function setSession(res, cookieKey) {
  const secure = process.env.VERCEL ? "; Secure" : "";
  res.setHeader(
    "Set-Cookie",
    `${COOKIE}=${sign(cookieKey)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=1209600${secure}`,
  );
}

function clearSession(res) {
  res.setHeader("Set-Cookie", `${COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`);
}

function send(res, status, body) {
  res.status(status).json(body);
}

async function readBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const text = Buffer.concat(chunks).toString("utf8");
  if (!text) return {};
  return JSON.parse(text);
}

export default async function handler(req, res) {
  const op = clean(req.query?.op, 40);
  try {
    const data = await load();
    if (req.method === "GET" && op === "status") {
      return send(res, 200, {
        needsSetup: !data.lock,
        authed: authed(data, req),
        mailReady: Boolean(process.env.RESEND_API_KEY),
        categories: CATS,
        items: ITEMS,
        vantages: VANTAGES,
      });
    }
    if (req.method === "POST" && op === "setup") {
      const body = await readBody(req);
      const password = clean(body.password, 200);
      if (data.lock) return send(res, 400, { error: "A desk password is already set." });
      if (password.length < 8) return send(res, 400, { error: "Use at least 8 characters." });
      const salt = randomBytes(16).toString("base64url");
      const cookieKey = randomBytes(32).toString("base64url");
      data.lock = { salt, passwordHash: hashPassword(password, salt), cookieKey };
      const stored = await save(data);
      if (!stored.lock || stored.lock.cookieKey !== cookieKey) {
        return send(res, 400, { error: "A desk password is already set." });
      }
      setSession(res, cookieKey);
      return send(res, 200, { ok: true });
    }
    if (req.method === "POST" && op === "login") {
      const body = await readBody(req);
      const password = clean(body.password, 200);
      if (!data.lock) return send(res, 400, { error: "Choose a desk password first." });
      const hash = hashPassword(password, data.lock.salt);
      if (!same(hash, data.lock.passwordHash)) return send(res, 401, { error: "That password is not right." });
      setSession(res, data.lock.cookieKey);
      return send(res, 200, { ok: true });
    }
    if (req.method === "POST" && op === "logout") {
      clearSession(res);
      return send(res, 200, { ok: true });
    }
    if (req.method === "GET" && op === "form") {
      const raterToken = clean(req.query.token, 120);
      for (const engagement of data.engagements) {
        const rater = engagement.raters.find((row) => row.token === raterToken);
        if (!rater) continue;
        return send(res, 200, {
          found: true,
          name: rater.name,
          vantage: rater.vantage,
          submitted: Boolean(rater.submittedAt),
          subjectName: engagement.subjectName,
          subjectRole: engagement.subjectRole,
          site: engagement.site,
        });
      }
      return send(res, 200, { found: false });
    }
    if (req.method === "POST" && op === "submit") {
      const body = await readBody(req);
      const raterToken = clean(body.token, 120);
      for (const engagement of data.engagements) {
        const rater = engagement.raters.find((row) => row.token === raterToken);
        if (!rater) continue;
        if (rater.submittedAt) return send(res, 400, { error: "This assessment was already submitted." });
        const answers = {};
        for (const item of ITEMS) {
          const value = Number(body.answers?.[item.id]);
          if (!Number.isInteger(value) || value < 0 || value > 5) {
            return send(res, 400, { error: "Answer every item before submitting." });
          }
          answers[item.id] = value;
        }
        const comments = {};
        for (const cat of CATS) comments[cat.id] = clean(body.comments?.[cat.id], 4000);
        rater.answers = answers;
        rater.comments = comments;
        rater.submittedAt = new Date().toISOString();
        await save(data);
        return send(res, 200, { ok: true });
      }
      return send(res, 404, { error: "This link is not valid." });
    }
    if (req.method === "GET" && op === "report") {
      const reportToken = clean(req.query.token, 120);
      const engagement = data.engagements.find((row) => row.reportToken === reportToken);
      if (!engagement) return send(res, 200, { found: false });
      const done = engagement.raters.filter((row) => row.submittedAt);
      return send(res, 200, {
        found: true,
        subjectName: engagement.subjectName,
        subjectRole: engagement.subjectRole,
        site: engagement.site,
        invited: engagement.raters.length,
        done: done.length,
        ratings: done.flatMap((row) =>
          ITEMS.map((item) => ({ itemKey: item.id, value: Number(row.answers?.[item.id] ?? 0) })),
        ),
        comments: done.flatMap((row) =>
          CATS.map((cat) => ({ categoryId: cat.id, body: row.comments?.[cat.id] || "" })).filter((row) => row.body.trim()),
        ),
        vantages: Object.entries(
          done.reduce((acc, row) => {
            acc[row.vantage] = (acc[row.vantage] || 0) + 1;
            return acc;
          }, {}),
        ).map(([vantage, n]) => ({ vantage, n })),
      });
    }
    if (!authed(data, req)) return send(res, 401, { error: "Open the desk first." });
    if (req.method === "GET" && op === "engagements") {
      const base = originOf(req);
      return send(res, 200, {
        engagements: data.engagements.map((row) => ({
          id: row.id,
          subjectName: row.subjectName,
          subjectRole: row.subjectRole,
          site: row.site,
          reportLink: `${base}/?report=${row.reportToken}`,
          raterCount: row.raters.length,
          doneCount: row.raters.filter((rater) => rater.submittedAt).length,
          raters: row.raters.map((rater) => ({
            id: rater.id,
            name: rater.name,
            email: rater.email,
            vantage: rater.vantage,
            sentAt: rater.sentAt,
            submittedAt: rater.submittedAt,
            link: `${base}/?r=${rater.token}`,
          })),
        })),
      });
    }
    if (req.method === "POST" && op === "create") {
      const body = await readBody(req);
      const subjectName = clean(body.subjectName, 160);
      if (!subjectName) return send(res, 400, { error: "Name the person or role being rated." });
      data.engagements.unshift({
        id: randomBytes(12).toString("base64url"),
        subjectName,
        subjectRole: clean(body.subjectRole, 160),
        site: clean(body.site, 160),
        reportToken: token(),
        createdAt: new Date().toISOString(),
        raters: [],
      });
      await save(data);
      return send(res, 200, { id: data.engagements[0].id });
    }
    if (req.method === "POST" && op === "rater") {
      const body = await readBody(req);
      const engagement = data.engagements.find((row) => row.id === clean(body.engagementId, 80));
      if (!engagement) return send(res, 404, { error: "Engagement not found." });
      const name = clean(body.name, 160);
      const email = clean(body.email, 200).toLowerCase();
      const vantage = clean(body.vantage, 80);
      if (!name || !email.includes("@") || !VANTAGES.includes(vantage)) {
        return send(res, 400, { error: "Name, email, and vantage point are required." });
      }
      if (engagement.raters.some((row) => row.email === email)) {
        return send(res, 400, { error: "That email is already on this engagement." });
      }
      const raterToken = token();
      engagement.raters.push({
        id: randomBytes(12).toString("base64url"),
        name,
        email,
        vantage,
        token: raterToken,
        sentAt: null,
        submittedAt: null,
        answers: {},
        comments: {},
      });
      await save(data);
      return send(res, 200, { link: `${originOf(req)}/?r=${raterToken}` });
    }
    if (req.method === "POST" && op === "send") {
      const body = await readBody(req);
      let rater = null;
      let engagement = null;
      for (const row of data.engagements) {
        const found = row.raters.find((item) => item.id === clean(body.raterId, 80));
        if (found) {
          rater = found;
          engagement = row;
        }
      }
      if (!rater || !engagement) return send(res, 404, { error: "Rater not found." });
      if (rater.submittedAt) return send(res, 400, { error: "This rater already finished." });
      const link = `${originOf(req)}/?r=${rater.token}`;
      const who = [engagement.subjectName, engagement.subjectRole, engagement.site].filter(Boolean).join(", ");
      const key = process.env.RESEND_API_KEY;
      if (!key) return send(res, 200, { sent: false, reason: "Mail is not configured yet. Copy the link.", link });
      const text = [
        `${rater.name},`,
        "",
        `You have been asked to rate ${who} on the OR Influence and Collaboration Assessment.`,
        `It is 15 items and takes about 6 to 8 minutes. Rate only what you have actually observed.`,
        "",
        "Your link is private:",
        link,
        "",
        "Bellomo Leadership",
      ].join("\n");
      const mail = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          from: "Bellomo Leadership <assessments@thecourageeconomy.net>",
          to: [rater.email],
          subject: `Please rate ${engagement.subjectName} — OR Influence and Collaboration`,
          text,
        }),
      });
      if (!mail.ok) {
        const detail = await mail.text();
        return send(res, 200, { sent: false, reason: detail.slice(0, 240) || "Mail was rejected.", link });
      }
      rater.sentAt = new Date().toISOString();
      await save(data);
      return send(res, 200, { sent: true, reason: "", link });
    }
    return send(res, 404, { error: "Unknown request." });
  } catch (err) {
    return send(res, 500, { error: err instanceof Error ? err.message : "Something went wrong." });
  }
}
