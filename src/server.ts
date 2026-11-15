import "dotenv/config";
import express, { Request, Response, NextFunction } from "express";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import { Pool } from "pg";
import helmet from "helmet";
import { PrismaClient } from "@prisma/client";
import { z } from "zod";
import { getPermissions, hasPermission, PERMISSIONS } from "./permissions";
import { startDiscordGateway, getDiscordStatus, getDiscordSnapshot } from "./discord";
import crypto from "node:crypto";

const db = new PrismaClient();
const app = express();
const port = Number(process.env.PORT || 10000);
const baseUrl = process.env.APP_BASE_URL || "http://localhost:10000";
const guildId = process.env.DISCORD_GUILD_ID || "";
if (process.env.NODE_ENV === "production" && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) throw new Error("SESSION_SECRET must be at least 32 characters in production.");
const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const PgSession = connectPgSimple(session);
// node-postgres 8.16+ interprets sslmode=require as certificate-verifying by default.
// Aiven documents uselibpqcompat=true to preserve PostgreSQL/libpq SSL semantics for require.
const sessionDatabaseUrl = process.env.DATABASE_URL ? new URL(process.env.DATABASE_URL) : null;
if (sessionDatabaseUrl && process.env.NODE_ENV === "production") sessionDatabaseUrl.searchParams.set("uselibpqcompat", "true");
const pool = new Pool({ connectionString: sessionDatabaseUrl?.toString() || process.env.DATABASE_URL });

declare module "express-session" { interface SessionData { userId?: string; oauthState?: string } }
type AuthedRequest = Request & { portalUser?: Awaited<ReturnType<typeof db.user.findUnique>> };

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"], fontSrc: ["'self'", "https://fonts.gstatic.com"], scriptSrc: ["'self'"], imgSrc: ["'self'", "https://cdn.discordapp.com", "data:"], connectSrc: ["'self'"] } } }));
app.use(express.urlencoded({ extended: true, limit: "32kb" }));
app.use(express.json({ limit: "32kb" }));
app.use((req, res, next) => {
  if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) {
    const origin = req.get("origin");
    const referer = req.get("referer");
    let source = origin || "";
    if (!source && referer) { try { source = new URL(referer).origin; } catch { return res.status(403).send("Invalid request origin."); } }
    if (source && source !== new URL(baseUrl).origin) return res.status(403).send("Cross-origin request blocked.");
  }
  next();
});
app.use(session({
  store: new PgSession({ pool, tableName: "portal_sessions", createTableIfMissing: true }),
  name: "okg.portal.sid",
  secret: sessionSecret,
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax", maxAge: 1000 * 60 * 60 * 24 * 7 }
}));
app.use("/assets", express.static("public", { maxAge: "1h" }));

function shell(title: string, content: string, user?: any) {
  const nav = user ? `<nav><a href="/dashboard">Overview</a><a href="/members">Members</a><a href="/server">Server</a><a href="/moderation">Moderation</a><a href="/bot">Bot</a><a href="/control">Control Center</a><a href="/applications">Applications</a><a href="/settings">Settings</a><a href="/audit">Audit</a><a href="/logout">Sign out</a></nav>` : "";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#080b14"><title>${title} · OKG Portal</title><link rel="stylesheet" href="/assets/style.css"></head><body><div class="ambient"></div><header class="topbar"><a class="brand" href="/"><span class="brand-mark">O</span><span>ONE KID GAMING<small>OFFICIAL PORTAL</small></span></a>${nav}<div class="top-right">${user ? `<span class="user-chip">${escapeHtml(user.displayName || user.username)}</span>` : '<a class="button button-quiet" href="/auth/discord">Sign in</a>'}</div></header><main>${content}</main><footer>ONE KID GAMING <span>·</span> Official community platform</footer></body></html>`;
}
function escapeHtml(value: unknown): string { return String(value ?? "").replace(/[&<>"']/g, c => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[c]!)); }
function page(res: Response, title: string, content: string, user?: any) { res.type("html").send(shell(title, content, user)); }
async function auth(req: Request, res: Response, next: NextFunction) {
  const sessionUser = req.session.userId ? await db.user.findUnique({ where: { id: req.session.userId } }) : null;
  const user = sessionUser?.discordId === process.env.OWNER_DISCORD_USER_ID ? sessionUser : null;
  if (!user || !user.isGuildMember || user.discordId !== process.env.OWNER_DISCORD_USER_ID) {
    if (req.session.userId) req.session.destroy(() => {});
    return page(res, "Portal access restricted", '<section class="panel narrow"><span class="eyebrow">PRIVATE OWNER ACCESS</span><h1>OKG Portal is currently private.</h1><p>Only the platform owner can use an account right now. Any previous non-owner sessions have been signed out.</p><a class="button" href="/">Return home</a></section>');
  }
  (req as AuthedRequest).portalUser = user;
  next();
}
function requirePermission(permission: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = (req as AuthedRequest).portalUser!;
    const permissions = await getPermissions(db, user);
    if (!hasPermission(permissions, permission)) return page(res, "Access restricted", '<section class="panel narrow"><span class="eyebrow">403 · ACCESS RESTRICTED</span><h1>You do not have access to this area.</h1><p>Your portal permissions are synchronized from your OKG Discord roles.</p><a class="button" href="/dashboard">Back to portal</a></section>', user);
    next();
  };
}
function requireOwner(req: Request, res: Response, next: NextFunction) {
  const user = (req as AuthedRequest).portalUser!;
  if (!user || user.discordId !== process.env.OWNER_DISCORD_USER_ID) {
    return page(res, "Owner access required", '<section class="panel narrow"><span class="eyebrow">OWNER ONLY</span><h1>This area is reserved for the OKG platform owner.</h1><p>Role-based staff permissions cannot grant access to platform-wide security settings.</p><a class="button" href="/dashboard">Back to portal</a></section>', user);
  }
  next();
}
function audit(actorId: string, action: string, subject?: string, details?: object) {
  return db.auditEvent.create({ data: { actorId, action, subject, details: details as any } });
}

app.get("/health", (_req, res) => res.json({ ok: true, service: "okg-portal" }));
app.get("/", async (req, res) => {
  const sessionUser = req.session.userId ? await db.user.findUnique({ where: { id: req.session.userId } }) : null;
  const user = sessionUser?.discordId === process.env.OWNER_DISCORD_USER_ID ? sessionUser : null;
  const bannerSetting = await db.portalSetting.findUnique({ where: { key: "site_banner" } });
  const banner = (bannerSetting?.value || {}) as { enabled?: boolean; message?: string };
  const bannerHtml = banner.enabled && banner.message ? '<div class="panel narrow"><span class="eyebrow">OFFICIAL OKG UPDATE</span><p>'+escapeHtml(banner.message)+'</p></div>' : '';
  page(res, "Home", `${bannerHtml}<section class="hero"><div class="hero-copy"><span class="eyebrow"><i></i> THE OFFICIAL OKG PLATFORM</span><h1>One community.<br><em>One place.</em></h1><p>Your central destination for OKG membership, staff applications, updates and community services.</p><div class="actions"><a class="button" href="${user ? "/dashboard" : "/auth/discord"}">${user ? "Open your portal" : "Continue with Discord"} <b>↗</b></a><a class="button button-quiet" href="https://discord.gg/nePR9dnuYm" target="_blank" rel="noreferrer">Join the community</a></div><div class="trust-row"><span>● Discord-connected identity</span><span>● Role-synced access</span><span>● Official OKG</span></div></div><div class="hero-art"><div class="orbit orbit-one"></div><div class="orbit orbit-two"></div><div class="core"><span>OKG</span><small>COMMUNITY</small></div><div class="float-card card-top"><span class="pulse"></span> ROLE SYNC <b>LIVE</b></div><div class="float-card card-bottom"><small>YOUR COMMUNITY</small><strong>ONE KID GAMING</strong><span>MEMBERS · STAFF · LEADERSHIP</span></div></div></section><section class="feature-grid"><article class="feature"><span class="feature-icon">01</span><h3>One connected identity</h3><p>Sign in with Discord and use your verified OKG membership across the portal.</p></article><article class="feature"><span class="feature-icon">02</span><h3>Applications, organized</h3><p>Submit applications and follow their progress through a central workflow.</p></article><article class="feature"><span class="feature-icon">03</span><h3>Permissions that follow you</h3><p>Portal access updates automatically when your mapped Discord roles change.</p></article></section>`, user);
});
// ... Existing route handlers remain unchanged in this file.
