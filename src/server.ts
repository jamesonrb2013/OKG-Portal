import "dotenv/config";
import express, { Request, Response, NextFunction } from "express";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import { Pool } from "pg";
import helmet from "helmet";
import { PrismaClient } from "@prisma/client";
import { z } from "zod";
import { getPermissions, hasPermission, PERMISSIONS } from "./permissions";
import { startDiscordGateway } from "./discord";
import crypto from "node:crypto";

const db = new PrismaClient();
const app = express();
const port = Number(process.env.PORT || 10000);
const baseUrl = process.env.APP_BASE_URL || "http://localhost:10000";
const guildId = process.env.DISCORD_GUILD_ID || "";
if (process.env.NODE_ENV === "production" && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) throw new Error("SESSION_SECRET must be at least 32 characters in production.");
const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const PgSession = connectPgSimple(session);
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : undefined });

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
    const source = origin || (referer ? new URL(referer).origin : "");
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
  const nav = user ? `<nav><a href="/dashboard">Overview</a><a href="/apply">Applications</a><a href="/applications">Review queue</a><a href="/settings">Role settings</a><a href="/logout">Sign out</a></nav>` : "";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#080b14"><title>${title} · OKG Portal</title><link rel="stylesheet" href="/assets/style.css"></head><body><div class="ambient"></div><header class="topbar"><a class="brand" href="/"><span class="brand-mark">O</span><span>ONE KID GAMING<small>OFFICIAL PORTAL</small></span></a>${nav}<div class="top-right">${user ? `<span class="user-chip">${escapeHtml(user.displayName || user.username)}</span>` : '<a class="button button-quiet" href="/auth/discord">Sign in</a>'}</div></header><main>${content}</main><footer>ONE KID GAMING <span>·</span> Official community platform</footer></body></html>`;
}
function escapeHtml(value: unknown): string { return String(value ?? "").replace(/[&<>"']/g, c => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[c]!)); }
function page(res: Response, title: string, content: string, user?: any) { res.type("html").send(shell(title, content, user)); }
async function auth(req: Request, res: Response, next: NextFunction) {
  const user = req.session.userId ? await db.user.findUnique({ where: { id: req.session.userId } }) : null;
  if (!user || !user.isGuildMember) {
    if (req.session.userId) req.session.destroy(() => {});
    return res.redirect("/?signin=1");
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
function audit(actorId: string, action: string, subject?: string, details?: object) {
  return db.auditEvent.create({ data: { actorId, action, subject, details: details as any } });
}

app.get("/health", (_req, res) => res.json({ ok: true, service: "okg-portal" }));
app.get("/", async (req, res) => {
  const user = req.session.userId ? await db.user.findUnique({ where: { id: req.session.userId } }) : null;
  page(res, "Home", `<section class="hero"><div class="hero-copy"><span class="eyebrow"><i></i> THE OFFICIAL OKG PLATFORM</span><h1>One community.<br><em>One place.</em></h1><p>Your central destination for OKG membership, staff applications, updates and community services.</p><div class="actions"><a class="button" href="${user ? "/dashboard" : "/auth/discord"}">${user ? "Open your portal" : "Continue with Discord"} <b>↗</b></a><a class="button button-quiet" href="https://discord.gg/nePR9dnuYm" target="_blank" rel="noreferrer">Join the community</a></div><div class="trust-row"><span>● Discord-connected identity</span><span>● Role-synced access</span><span>● Official OKG</span></div></div><div class="hero-art"><div class="orbit orbit-one"></div><div class="orbit orbit-two"></div><div class="core"><span>OKG</span><small>COMMUNITY</small></div><div class="float-card card-top"><span class="pulse"></span> ROLE SYNC <b>LIVE</b></div><div class="float-card card-bottom"><small>YOUR COMMUNITY</small><strong>ONE KID GAMING</strong><span>MEMBERS · STAFF · LEADERSHIP</span></div></div></section><section class="feature-grid"><article class="feature"><span class="feature-icon">01</span><h3>One connected identity</h3><p>Sign in with Discord and use your verified OKG membership across the portal.</p></article><article class="feature"><span class="feature-icon">02</span><h3>Applications, organized</h3><p>Submit applications and follow their progress through a central workflow.</p></article><article class="feature"><span class="feature-icon">03</span><h3>Permissions that follow you</h3><p>Portal access updates automatically when your mapped Discord roles change.</p></article></section>`, user);
});
app.get("/auth/discord", (req, res) => {
  const clientId = process.env.DISCORD_CLIENT_ID;
  if (!clientId || !process.env.DISCORD_CLIENT_SECRET || !process.env.DISCORD_BOT_TOKEN || !guildId) return page(res, "Setup required", '<section class="panel narrow"><span class="eyebrow">INITIAL SETUP</span><h1>Discord connection is being configured.</h1><p>The portal is online, but its Discord application, bot and official server still need to be connected by the administrator.</p></section>');
  const state = crypto.randomBytes(24).toString("hex");
  req.session.oauthState = state;
  const params = new URLSearchParams({ client_id: clientId, redirect_uri: process.env.DISCORD_REDIRECT_URI || baseUrl + "/auth/discord/callback", response_type: "code", scope: "identify", state });
  res.redirect("https://discord.com/oauth2/authorize?" + params.toString());
});
app.get("/auth/discord/callback", async (req, res) => {
  try {
    const code = String(req.query.code || "");
    const state = String(req.query.state || "");
    if (!code || !state || !req.session.oauthState || state !== req.session.oauthState) return res.status(400).send("Invalid OAuth state. Please try again.");
    delete req.session.oauthState;
    const tokenResponse = await fetch("https://discord.com/api/oauth2/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ client_id: process.env.DISCORD_CLIENT_ID!, client_secret: process.env.DISCORD_CLIENT_SECRET!, grant_type: "authorization_code", code, redirect_uri: process.env.DISCORD_REDIRECT_URI || baseUrl + "/auth/discord/callback" }) });
    if (!tokenResponse.ok) throw new Error("Discord token exchange failed");
    const token = await tokenResponse.json() as { access_token: string };
    const profileResponse = await fetch("https://discord.com/api/users/@me", { headers: { Authorization: "Bearer " + token.access_token } });
    if (!profileResponse.ok) throw new Error("Could not retrieve Discord profile");
    const profile = await profileResponse.json() as { id: string; username: string; global_name?: string; avatar?: string };
    const memberResponse = await fetch(`https://discord.com/api/v10/guilds/${guildId}/members/${profile.id}`, { headers: { Authorization: "Bot " + process.env.DISCORD_BOT_TOKEN } });
    if (!memberResponse.ok) return page(res, "Server membership required", '<section class="panel narrow"><span class="eyebrow">MEMBERSHIP CHECK</span><h1>Join the official OKG Discord first.</h1><p>We could not verify your membership in the official server. Join OKG, then sign in again.</p><a class="button" href="https://discord.gg/nePR9dnuYm">Join OKG Discord</a></section>');
    const member = await memberResponse.json() as { roles: string[] };
    const owner = profile.id === process.env.OWNER_DISCORD_USER_ID;
    const user = await db.user.upsert({
      where: { discordId: profile.id },
      create: { discordId: profile.id, username: profile.username, displayName: profile.global_name, avatar: profile.avatar, isOwner: owner, isGuildMember: true },
      update: { username: profile.username, displayName: profile.global_name, avatar: profile.avatar, isOwner: owner, isGuildMember: true, lastLoginAt: new Date() }
    });
    await db.$transaction([
      db.memberRole.deleteMany({ where: { userId: user.id, guildId } }),
      ...(member.roles.length ? [db.memberRole.createMany({ data: member.roles.map(discordRoleId => ({ userId: user.id, guildId, discordRoleId })), skipDuplicates: true })] : [])
    ]);
    await audit(user.id, "auth.discord.login", profile.id);
    req.session.userId = user.id;
    res.redirect("/dashboard");
  } catch (error) {
    console.error("Discord OAuth error", error);
    page(res, "Sign-in error", '<section class="panel narrow"><h1>We could not complete sign-in.</h1><p>Please try again. If this continues, contact OKG support.</p><a class="button" href="/">Return home</a></section>');
  }
});
app.get("/logout", (req, res) => req.session.destroy(() => res.redirect("/")));
app.get("/dashboard", auth, async (req, res) => {
  const user = (req as AuthedRequest).portalUser!;
  const permissions = await getPermissions(db, user);
  const apps = await db.application.findMany({ where: { userId: user.id }, orderBy: { submittedAt: "desc" }, take: 5 });
  const cards = apps.map(a => `<div class="list-row"><span><b>${escapeHtml(a.type)} application</b><small>Submitted ${a.submittedAt.toLocaleDateString()}</small></span><span class="status">${escapeHtml(a.status)}</span></div>`).join("") || '<p class="muted">You have not submitted an application yet.</p>';
  page(res, "Dashboard", `<section class="page-heading"><span class="eyebrow">MEMBER DASHBOARD</span><h1>Welcome back, ${escapeHtml(user.displayName || user.username)}.</h1><p>Your OKG account, applications and access in one place.</p></section><section class="stat-grid"><article class="stat"><small>ACCOUNT</small><strong>Connected</strong><span>Discord identity verified</span></article><article class="stat"><small>PORTAL ACCESS</small><strong>${user.discordId === process.env.OWNER_DISCORD_USER_ID ? "Platform Owner" : permissions.size + " permissions"}</strong><span>Live role-based access</span></article><article class="stat"><small>APPLICATIONS</small><strong>${apps.length}</strong><span>Recent submissions</span></article></section><section class="content-grid"><article class="panel"><div class="panel-head"><div><span class="eyebrow">YOUR ACTIVITY</span><h2>Recent applications</h2></div><a href="/apply">New application ↗</a></div>${cards}</article><article class="panel"><span class="eyebrow">ACCOUNT STATUS</span><h2>You're connected.</h2><p>Your portal access is checked against your verified OKG Discord roles. When a mapped role changes, access is recalculated automatically.</p><div class="status-line"><span class="pulse"></span> Discord account linked</div><div class="status-line"><span class="pulse"></span> Official server membership verified</div></article></section>`, user);
});
app.get("/apply", auth, (req, res) => {
 const user=(req as AuthedRequest).portalUser!;
 page(res,"Applications",`<section class="page-heading"><span class="eyebrow">JOIN THE TEAM</span><h1>Make your mark at OKG.</h1><p>Tell us about yourself and the way you'd contribute to the community.</p></section><form class="panel form-panel" method="post" action="/apply"><label>Application type<select name="type"><option value="staff">Staff application</option><option value="helper">Helper application</option><option value="partner">Partnership inquiry</option></select></label><label>Why are you interested?<textarea name="motivation" required minlength="30" maxlength="3000" rows="5" placeholder="Share what motivates you..."></textarea></label><label>What experience or strengths would you bring?<textarea name="experience" required minlength="20" maxlength="3000" rows="5" placeholder="Tell us about your experience..."></textarea></label><label>Anything else we should know?<textarea name="additional" maxlength="2000" rows="3" placeholder="Optional"></textarea></label><button class="button" type="submit">Submit application <b>↗</b></button><p class="muted small">Applications are visible only to authorized OKG application reviewers.</p></form>`,user);
});
app.post("/apply", auth, async (req,res) => {
 const user=(req as AuthedRequest).portalUser!;
 const parsed=z.object({type:z.enum(["staff","helper","partner"]),motivation:z.string().min(30).max(3000),experience:z.string().min(20).max(3000),additional:z.string().max(2000).optional()}).safeParse(req.body);
 if(!parsed.success) return page(res,"Check your application",'<section class="panel narrow"><h1>Please check your answers.</h1><p>Required answers need a little more detail. Go back and try again.</p><a class="button" href="/apply">Back to application</a></section>',user);
 const application=await db.application.create({data:{userId:user.id,type:parsed.data.type,answers:parsed.data}});
 await audit(user.id,"application.submitted",application.id,{type:parsed.data.type});
 res.redirect("/dashboard");
});
app.get("/applications", auth, requirePermission("applications:view"), async (req,res) => {
 const user=(req as AuthedRequest).portalUser!;
 const apps=await db.application.findMany({orderBy:{submittedAt:"desc"},take:100});
 const applicants=await db.user.findMany({where:{id:{in:[...new Set(apps.map(a=>a.userId))]}}});
 const applicantById=new Map(applicants.map(applicant=>[applicant.id,applicant]));
 const rows=apps.map(a=>`<tr><td><b>${escapeHtml(applicantById.get(a.userId)?.displayName||applicantById.get(a.userId)?.username||"Unknown user")}</b><small>${escapeHtml(applicantById.get(a.userId)?.discordId||"")}</small></td><td>${escapeHtml(a.type)}</td><td><span class="status">${escapeHtml(a.status)}</span></td><td>${a.submittedAt.toLocaleDateString()}</td><td><a href="/applications/${a.id}">Open →</a></td></tr>`).join("");
 page(res,"Application review",`<section class="page-heading"><span class="eyebrow">STAFF WORKSPACE</span><h1>Application review.</h1><p>Private queue for authorized application staff.</p></section><section class="panel table-panel"><table><thead><tr><th>Applicant</th><th>Type</th><th>Status</th><th>Submitted</th><th></th></tr></thead><tbody>${rows||'<tr><td colspan="5">No applications yet.</td></tr>'}</tbody></table></section>`,user);
});
app.get("/applications/:id", auth, requirePermission("applications:review"), async (req,res) => {
 const user=(req as AuthedRequest).portalUser!;
 const applicationId=String(req.params.id);
 const a=await db.application.findUnique({where:{id:applicationId}});
 if(!a) return res.status(404).send("Application not found");
 const applicant=await db.user.findUnique({where:{id:a.userId}});
 if(!applicant) return res.status(404).send("Applicant not found");
 const answers=a.answers as Record<string,string>;
 page(res,"Review application",`<section class="page-heading"><span class="eyebrow">APPLICATION DETAIL</span><h1>${escapeHtml(a.type)} application</h1><p>Submitted by ${escapeHtml(applicant.displayName||applicant.username)} · ${a.submittedAt.toLocaleString()}</p></section><section class="panel"><h2>Applicant responses</h2><h3>Motivation</h3><p class="answer">${escapeHtml(answers.motivation)}</p><h3>Experience</h3><p class="answer">${escapeHtml(answers.experience)}</p><h3>Additional information</h3><p class="answer">${escapeHtml(answers.additional||"Not provided")}</p><form method="post" action="/applications/${applicationId}/status" class="inline-form"><label>Decision<select name="status"><option value="submitted">Submitted</option><option value="reviewing">Reviewing</option><option value="accepted">Accepted</option><option value="declined">Declined</option></select></label><button class="button" type="submit">Update status</button></form></section>`,user);
});
app.post("/applications/:id/status", auth, requirePermission("applications:review"), async (req,res) => {
 const user=(req as AuthedRequest).portalUser!;
 const applicationId=String(req.params.id);
 const status=z.enum(["submitted","reviewing","accepted","declined"]).safeParse(req.body.status);
 if(!status.success) return res.status(400).send("Invalid status");
 await db.application.update({where:{id:applicationId},data:{status:status.data}});
 await audit(user.id,"application.status.updated",applicationId,{status:status.data});
 res.redirect("/applications/"+applicationId);
});
app.get("/settings", auth, requirePermission("roles:manage"), async (req,res) => {
 const user=(req as AuthedRequest).portalUser!;
 const mappings=await db.roleMapping.findMany({where:{guildId},orderBy:{permission:"asc"}});
 const rows=mappings.map(m=>`<tr><td><code>${escapeHtml(m.discordRoleId)}</code></td><td>${escapeHtml(m.permission)}</td><td><form method="post" action="/settings/roles/${m.id}/delete"><button class="text-button">Remove</button></form></td></tr>`).join("");
 const options=PERMISSIONS.map(p=>`<option value="${p}">${p}</option>`).join("");
 page(res,"Portal settings",`<section class="page-heading"><span class="eyebrow">PLATFORM OWNER</span><h1>Role synchronization.</h1><p>Map Discord role IDs to portal permissions. Changes take effect as soon as Discord role updates are received.</p></section><section class="panel"><div class="panel-head"><div><span class="eyebrow">OFFICIAL SERVER</span><h2>Role mappings</h2></div><span class="status">${mappings.length} mappings</span></div><form class="mapping-form" method="post" action="/settings/roles"><label>Discord role ID<input name="discordRoleId" required inputmode="numeric" pattern="[0-9]{15,22}" placeholder="123456789012345678"></label><label>Portal permission<select name="permission">${options}</select></label><button class="button" type="submit">Add mapping</button></form><div class="table-wrap"><table><thead><tr><th>Discord role ID</th><th>Portal permission</th><th></th></tr></thead><tbody>${rows||'<tr><td colspan="3">No mappings configured yet.</td></tr>'}</tbody></table></div><p class="muted small">Use Discord Developer Mode to copy role IDs. A role ID can have multiple permission mappings. Platform Owner access is never granted through this table.</p></section>`,user);
});
app.post("/settings/roles", auth, requirePermission("roles:manage"), async (req,res) => {
 const user=(req as AuthedRequest).portalUser!;
 const parsed=z.object({discordRoleId:z.string().regex(/^\d{15,22}$/),permission:z.enum(PERMISSIONS)}).safeParse(req.body);
 if(!parsed.success) return res.status(400).send("Invalid role ID or permission.");
 await db.roleMapping.upsert({where:{guildId_discordRoleId_permission:{guildId,discordRoleId:parsed.data.discordRoleId,permission:parsed.data.permission}},create:{guildId,discordRoleId:parsed.data.discordRoleId,permission:parsed.data.permission},update:{}});
 await audit(user.id,"role_mapping.created",parsed.data.discordRoleId,{permission:parsed.data.permission});
 res.redirect("/settings");
});
app.post("/settings/roles/:id/delete", auth, requirePermission("roles:manage"), async (req,res) => {
 const user=(req as AuthedRequest).portalUser!;
 const mappingId=String(req.params.id);
 const mapping=await db.roleMapping.findFirst({where:{id:mappingId,guildId}});
 if(mapping){await db.roleMapping.delete({where:{id:mapping.id}});await audit(user.id,"role_mapping.deleted",mapping.discordRoleId,{permission:mapping.permission});}
 res.redirect("/settings");
});
app.get("/audit", auth, requirePermission("audit:view"), async (req,res) => {
 const user=(req as AuthedRequest).portalUser!;
 const events=await db.auditEvent.findMany({include:{actor:true},orderBy:{createdAt:"desc"},take:100});
 const rows=events.map(e=>`<tr><td>${e.createdAt.toLocaleString()}</td><td>${escapeHtml(e.actor?.displayName||e.actor?.username||"System")}</td><td>${escapeHtml(e.action)}</td><td>${escapeHtml(e.subject||"—")}</td></tr>`).join("");
 page(res,"Audit log",`<section class="page-heading"><span class="eyebrow">SECURITY & ACCOUNTABILITY</span><h1>Audit log.</h1><p>Recent administrative and account events.</p></section><section class="panel table-panel"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Subject</th></tr></thead><tbody>${rows}</tbody></table></section>`,user);
});
app.use((err: unknown,_req:Request,res:Response,_next:NextFunction)=>{console.error(err);res.status(500).send("Something went wrong. Please try again.");});
async function main(){
 if(!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required.");
 if(process.env.NODE_ENV === "production" && (!process.env.DISCORD_CLIENT_ID || !process.env.DISCORD_CLIENT_SECRET || !process.env.DISCORD_BOT_TOKEN || !guildId || !process.env.OWNER_DISCORD_USER_ID)) throw new Error("Discord OAuth, bot, guild and owner environment variables must be configured before production startup.");
 await startDiscordGateway(db);
 app.listen(port,()=>console.log(`OKG Portal listening on ${port}`));
}
main().catch(error=>{console.error(error);process.exit(1);});
