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
    // Temporary closed beta: only the configured platform owner may create or use a portal account.
    // This check runs before membership lookup or any database account write.
    if (!process.env.OWNER_DISCORD_USER_ID || profile.id !== process.env.OWNER_DISCORD_USER_ID) {
      return page(res, "Portal access restricted", '<section class="panel narrow"><span class="eyebrow">PRIVATE OWNER ACCESS</span><h1>OKG Portal is currently private.</h1><p>Account registration and sign-in are temporarily restricted to the platform owner. Please check back when access opens.</p><a class="button" href="/">Return home</a></section>');
    }
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
app.get("/dashboard", auth, requireOwner, async (req, res) => {
  const user = (req as AuthedRequest).portalUser!;
  const [members,applications,openCases,queued,failed,recentApps] = await Promise.all([
    db.user.count({where:{isGuildMember:true}}), db.application.count(),
    db.moderationCase.count({where:{guildId,active:true}}),
    db.discordAction.count({where:{status:"queued"}}), db.discordAction.count({where:{status:"failed"}}),
    db.application.findMany({where:{userId:user.id},orderBy:{submittedAt:"desc"},take:5})
  ]);
  const cards=recentApps.map(a=>'<div class="list-row"><span><b>'+escapeHtml(a.type)+' application</b><small>Submitted '+a.submittedAt.toLocaleDateString()+'</small></span><span class="status">'+escapeHtml(a.status)+'</span></div>').join("")||'<p class="muted">No applications have been submitted from this account.</p>';
  const bot=getDiscordStatus();
  const html='<section class="page-heading"><span class="eyebrow">PLATFORM OWNER · COMMAND CENTER</span><h1>Welcome back, '+escapeHtml(user.displayName||user.username)+'.</h1><p>Your central overview of One Kid Gaming operations, community systems and administration.</p></section>'+
  '<section class="stat-grid"><article class="stat"><small>VERIFIED MEMBERS</small><strong>'+members+'</strong><span>Portal-linked Discord members</span></article><article class="stat"><small>APPLICATIONS</small><strong>'+applications+'</strong><span>All submitted applications</span></article><article class="stat"><small>ACTIVE CASES</small><strong>'+openCases+'</strong><span>Moderation records marked active</span></article></section>'+
  '<section class="stat-grid"><article class="stat"><small>DISCORD BOT</small><strong>'+(bot.online?'Online':'Offline')+'</strong><span>'+(bot.ping===null?'No heartbeat':bot.ping+' ms latency')+'</span></article><article class="stat"><small>QUEUED ACTIONS</small><strong>'+queued+'</strong><span>Waiting for Discord worker</span></article><article class="stat"><small>FAILED ACTIONS</small><strong>'+failed+'</strong><span>Review in Bot Operations</span></article></section>'+
  '<section class="content-grid"><article class="panel"><div class="panel-head"><div><span class="eyebrow">APPLICATIONS</span><h2>Recent submissions</h2></div><a href="/applications">Open queue ↗</a></div>'+cards+'</article><article class="panel"><span class="eyebrow">QUICK ACCESS</span><h2>Platform modules</h2><div class="list-row"><a href="/server">Server management →</a></div><div class="list-row"><a href="/members">Member directory →</a></div><div class="list-row"><a href="/moderation">Moderation center →</a></div><div class="list-row"><a href="/bot">Bot operations →</a></div><div class="list-row"><a href="/control">Discord Control Center →</a></div><div class="list-row"><a href="/settings">Platform settings →</a></div><div class="list-row"><a href="/audit">Security audit log →</a></div></article></section>';
  page(res,"Owner dashboard",html,user);
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
app.get("/applications/:id", auth, requireOwner, async (req,res) => {
 const user=(req as AuthedRequest).portalUser!;
 const applicationId=String(req.params.id);
 const a=await db.application.findUnique({where:{id:applicationId}});
 if(!a) return res.status(404).send("Application not found");
 const applicant=await db.user.findUnique({where:{id:a.userId}});
 if(!applicant) return res.status(404).send("Applicant not found");
 const notes=await db.applicationNote.findMany({where:{applicationId},orderBy:{createdAt:"asc"}});
 const answers=a.answers as Record<string,string>;
 const noteRows=notes.map(n=>'<div class="list-row"><span>'+escapeHtml(n.body)+'<small>'+n.createdAt.toLocaleString()+'</small></span></div>').join("");
 page(res,"Review application",'<section class="page-heading"><span class="eyebrow">APPLICATION DETAIL</span><h1>'+escapeHtml(a.type)+' application.</h1><p>Submitted by '+escapeHtml(applicant.displayName||applicant.username)+' · '+a.submittedAt.toLocaleString()+'</p></section><section class="panel"><h2>Applicant responses</h2><h3>Motivation</h3><p class="answer">'+escapeHtml(answers.motivation)+'</p><h3>Experience</h3><p class="answer">'+escapeHtml(answers.experience)+'</p><h3>Additional information</h3><p class="answer">'+escapeHtml(answers.additional||"Not provided")+'</p><form method="post" action="/applications/'+applicationId+'/status" class="inline-form"><label>Decision<select name="status"><option value="submitted">Submitted</option><option value="reviewing">Reviewing</option><option value="accepted">Accepted</option><option value="declined">Declined</option></select></label><button class="button" type="submit">Update status</button></form></section><section class="panel"><h2>Internal review notes</h2>'+(noteRows||'<p class="muted">No internal notes yet.</p>')+'<form method="post" action="/applications/'+applicationId+'/notes"><label>Add a note<textarea name="body" required maxlength="2000" rows="3"></textarea></label><button class="button">Save internal note</button></form></section>',user);
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
app.get("/settings", auth, requireOwner, async (req,res) => {
 const user=(req as AuthedRequest).portalUser!;
 const [mappings,bannerSetting]=await Promise.all([
  db.roleMapping.findMany({where:{guildId},orderBy:{permission:"asc"}}),
  db.portalSetting.findUnique({where:{key:"site_banner"}})
 ]);
 const rows=mappings.map(m=>'<tr><td><code>'+escapeHtml(m.discordRoleId)+'</code></td><td>'+escapeHtml(m.permission)+'</td><td><form method="post" action="/settings/roles/'+m.id+'/delete"><button class="text-button">Remove</button></form></td></tr>').join("");
 const options=PERMISSIONS.map(p=>'<option value="'+p+'">'+p+'</option>').join("");
 const banner=(bannerSetting?.value||{}) as {enabled?:boolean;message?:string};
 const status=getDiscordStatus();
 const html='<section class="page-heading"><span class="eyebrow">PLATFORM OWNER</span><h1>Platform settings.</h1><p>Manage portal presentation, role synchronization and access configuration.</p></section>'+
 '<section class="content-grid"><article class="panel"><span class="eyebrow">PORTAL ANNOUNCEMENT</span><h2>Homepage banner</h2><form method="post" action="/settings/portal"><label>Banner message<textarea name="message" maxlength="300" rows="3">'+escapeHtml(banner.message||"")+'</textarea></label><label><input style="display:inline;width:auto;margin-right:8px" type="checkbox" name="enabled" value="yes" '+(banner.enabled?'checked':'')+'>Show banner on homepage</label><button class="button">Save portal settings</button></form></article><article class="panel"><span class="eyebrow">CONNECTED SYSTEMS</span><h2>Discord connection</h2><p>Bot status: <b>'+(status.online?'Online':'Offline')+'</b></p><p>Slash commands: <b>'+(status.commandsRegistered?'Registered':'Pending')+'</b></p><p class="muted small">The platform owner ID is enforced by the server and cannot be changed through role mappings.</p><a href="/bot">Open bot operations →</a></article></section>'+
 '<section class="panel"><div class="panel-head"><div><span class="eyebrow">OFFICIAL SERVER</span><h2>Discord role mappings</h2></div><span class="status">'+mappings.length+' mappings</span></div><form class="mapping-form" method="post" action="/settings/roles"><label>Discord role ID<input name="discordRoleId" required inputmode="numeric" pattern="[0-9]{15,22}" placeholder="123456789012345678"></label><label>Portal permission<select name="permission">'+options+'</select></label><button class="button" type="submit">Add mapping</button></form><div class="table-wrap"><table><thead><tr><th>Discord role ID</th><th>Portal permission</th><th></th></tr></thead><tbody>'+(rows||'<tr><td colspan="3">No mappings configured yet.</td></tr>')+'</tbody></table></div><p class="muted small">Role mappings are retained for future staff access. While the private beta is active, only the configured platform owner can access the portal.</p></section>';
 page(res,"Portal settings",html,user);
});
app.post("/settings/portal", auth, requireOwner, async (req,res) => {
 const user=(req as AuthedRequest).portalUser!;
 const parsed=z.object({message:z.string().max(300).optional(),enabled:z.enum(["yes"]).optional()}).safeParse(req.body);
 if(!parsed.success)return res.status(400).send("Invalid portal settings.");
 await db.portalSetting.upsert({where:{key:"site_banner"},create:{key:"site_banner",value:{message:parsed.data.message||"",enabled:parsed.data.enabled==="yes"}},update:{value:{message:parsed.data.message||"",enabled:parsed.data.enabled==="yes"}}});
 await audit(user.id,"portal.banner.updated",undefined,{enabled:parsed.data.enabled==="yes"});
 res.redirect("/settings");
});
app.post("/settings/roles", auth, requireOwner, async (req,res) => {
 const user=(req as AuthedRequest).portalUser!;
 const parsed=z.object({discordRoleId:z.string().regex(/^\d{15,22}$/),permission:z.enum(PERMISSIONS)}).safeParse(req.body);
 if(!parsed.success) return res.status(400).send("Invalid role ID or permission.");
 await db.roleMapping.upsert({where:{guildId_discordRoleId_permission:{guildId,discordRoleId:parsed.data.discordRoleId,permission:parsed.data.permission}},create:{guildId,discordRoleId:parsed.data.discordRoleId,permission:parsed.data.permission},update:{}});
 await audit(user.id,"role_mapping.created",parsed.data.discordRoleId,{permission:parsed.data.permission});
 res.redirect("/settings");
});
app.post("/settings/roles/:id/delete", auth, requireOwner, async (req,res) => {
 const user=(req as AuthedRequest).portalUser!;
 const mappingId=String(req.params.id);
 const mapping=await db.roleMapping.findFirst({where:{id:mappingId,guildId}});
 if(mapping){await db.roleMapping.delete({where:{id:mapping.id}});await audit(user.id,"role_mapping.deleted",mapping.discordRoleId,{permission:mapping.permission});}
 res.redirect("/settings");
});
app.get("/members", auth, requirePermission("members:view"), async (req,res) => {
 const user=(req as AuthedRequest).portalUser!;
 const q=String(req.query.q||"").trim().slice(0,80);
 const members=await db.user.findMany({where:{isGuildMember:true,...(q?{OR:[{username:{contains:q,mode:"insensitive"}},{displayName:{contains:q,mode:"insensitive"}},{discordId:{contains:q}}]}:{})},orderBy:{username:"asc"},take:100,include:{memberRoles:{where:{guildId}}}});
 const rows=members.map(m=>"<tr><td><b><a href=\"/members/"+escapeHtml(m.discordId)+"\">"+escapeHtml(m.displayName||m.username)+"</a></b><small>@"+escapeHtml(m.username)+"</small></td><td><code>"+escapeHtml(m.discordId)+"</code></td><td>"+(m.isOwner?"Platform Owner":m.memberRoles.length+" synced roles")+"</td><td>"+m.lastLoginAt.toLocaleDateString()+"</td></tr>").join("");
 const html="<section class=\"page-heading\"><span class=\"eyebrow\">OFFICIAL COMMUNITY</span><h1>Member directory.</h1><p>Verified members of the official OKG Discord server. Directory access is controlled by Discord role permissions.</p></section><section class=\"panel table-panel\"><form method=\"get\" action=\"/members\" class=\"mapping-form\"><label>Search members<input name=\"q\" value=\""+escapeHtml(q)+"\" placeholder=\"Name, username or Discord ID\"></label><button class=\"button\" type=\"submit\">Search</button><a class=\"button button-quiet\" href=\"/members\">Clear</a></form><div class=\"table-wrap\"><table><thead><tr><th>Member</th><th>Discord ID</th><th>Portal roles</th><th>Last login</th></tr></thead><tbody>"+(rows||"<tr><td colspan=\"4\">No matching members found.</td></tr>")+"</tbody></table></div><p class=\"muted small\">Showing up to 100 matching verified members.</p></section>";
 page(res,"Member directory",html,user);
});

app.get("/control", auth, requireOwner, async (req,res) => {
 const user=(req as AuthedRequest).portalUser!;
 const jobs=await db.discordAction.findMany({orderBy:{createdAt:"desc"},take:40});
 const rows=jobs.map(j=>"<tr><td>"+j.createdAt.toLocaleString()+"</td><td>"+escapeHtml(j.type)+"</td><td>"+escapeHtml(j.status)+"</td><td>"+escapeHtml(j.result||"Waiting for bot...")+"</td></tr>").join("");
 const id='<label>Discord user ID<input name="userId" required pattern="[0-9]{15,22}"></label>';
 const reason='<label>Reason<input name="reason" maxlength="500" value="Requested through OKG Portal"></label>';
 const html='<section class="page-heading"><span class="eyebrow">PLATFORM OWNER · DISCORD OPERATIONS</span><h1>OKG Control Center.</h1><p>Manage messages, members, roles and server structure through the connected bot.</p></section>'+
 '<section class="content-grid"><article class="panel"><span class="eyebrow">COMMUNICATION</span><h2>Send a channel message</h2><form method="post" action="/control/actions"><input type="hidden" name="type" value="send_message"><label>Channel ID<input name="channelId" required pattern="[0-9]{15,22}"></label><label>Message<textarea name="message" required maxlength="1900" rows="4"></textarea></label><button class="button">Send message</button></form></article><article class="panel"><span class="eyebrow">DIRECT MESSAGE</span><h2>Message a member</h2><form method="post" action="/control/actions"><input type="hidden" name="type" value="send_dm">'+id+'<label>Message<textarea name="message" required maxlength="1900" rows="4"></textarea></label><button class="button">Send DM</button></form></article></section>'+
 '<section class="content-grid"><article class="panel"><h2>Member roles</h2><form method="post" action="/control/actions"><label>Action<select name="type"><option value="add_role">Add role</option><option value="remove_role">Remove role</option></select></label>'+id+'<label>Role ID<input name="roleId" required pattern="[0-9]{15,22}"></label><button class="button">Apply role change</button></form></article><article class="panel"><h2>Nickname</h2><form method="post" action="/control/actions"><input type="hidden" name="type" value="set_nickname">'+id+'<label>New nickname<input name="nickname" maxlength="32" placeholder="Leave blank to reset"></label><button class="button">Update nickname</button></form></article></section>'+
 '<section class="content-grid"><article class="panel"><h2>Moderation</h2><form method="post" action="/control/actions"><label>Action<select name="type"><option value="warn_member">Warn</option><option value="timeout_member">Timeout</option><option value="clear_timeout">Clear timeout</option><option value="kick_member">Kick</option><option value="ban_member">Ban</option><option value="unban_member">Unban</option></select></label>'+id+'<label>Timeout (minutes)<input type="number" name="minutes" min="1" max="40320" value="60"></label>'+reason+'<button class="button">Run moderation action</button></form></article><article class="panel"><h2>Message cleanup</h2><form method="post" action="/control/actions"><label>Action<select name="type"><option value="purge_messages">Bulk delete recent messages</option><option value="delete_message">Delete one message</option></select></label><label>Channel ID<input name="channelId" required pattern="[0-9]{15,22}"></label><label>Message ID (single delete only)<input name="messageId" pattern="[0-9]{15,22}"></label><label>Count (bulk delete only)<input name="count" type="number" min="2" max="100" value="10"></label><button class="button">Queue cleanup</button></form><p class="muted small">Discord bulk deletion cannot remove messages older than 14 days.</p></article></section>'+
 '<section class="panel"><h2>Recent action jobs</h2><div class="table-wrap"><table><thead><tr><th>Requested</th><th>Action</th><th>Status</th><th>Result</th></tr></thead><tbody>'+(rows||"<tr><td colspan=\"4\">No actions submitted yet.</td></tr>")+'</tbody></table></div><p class="muted small">Queued actions are executed by the bot worker. Failed jobs include the Discord permission or hierarchy error returned by Discord.</p></section>';
 page(res,"OKG Control Center",html,user);
});
app.post("/control/actions", auth, requireOwner, async (req,res) => {
 const user=(req as AuthedRequest).portalUser!;
 const type=z.enum(["send_message","send_dm","add_role","remove_role","set_nickname","warn_member","timeout_member","clear_timeout","kick_member","ban_member","unban_member","create_channel","delete_channel","create_role","delete_role","delete_message","purge_messages"]).safeParse(req.body.type);
 if(!type.success) return res.status(400).send("Unsupported action.");
 const id=z.string().regex(/^\d{15,22}$/);
 const reason=z.string().trim().max(500).optional();
 let payload:any={moderatorDiscordId:user.discordId};
 const parsedType=type.data;
 if(parsedType==="send_message"){
  const v=z.object({channelId:id,message:z.string().trim().min(1).max(1900)}).safeParse(req.body);if(!v.success)return res.status(400).send("Invalid channel ID or message.");payload=v.data;
 } else if(parsedType==="send_dm"){
  const v=z.object({userId:id,message:z.string().trim().min(1).max(1900)}).safeParse(req.body);if(!v.success)return res.status(400).send("Invalid member ID or message.");payload=v.data;
 } else if(parsedType==="add_role"||parsedType==="remove_role"){
  const v=z.object({userId:id,roleId:id}).safeParse(req.body);if(!v.success)return res.status(400).send("Invalid member or role ID.");payload={...v.data,moderatorDiscordId:user.discordId};
 } else if(parsedType==="set_nickname"){
  const v=z.object({userId:id,nickname:z.string().max(32).optional()}).safeParse(req.body);if(!v.success)return res.status(400).send("Invalid member ID or nickname.");payload={...v.data,moderatorDiscordId:user.discordId};
 } else if(["warn_member","timeout_member","clear_timeout","kick_member","ban_member","unban_member"].includes(parsedType)){
  const v=z.object({userId:id,reason:z.string().trim().min(1).max(500).optional(),minutes:z.coerce.number().int().min(1).max(40320).optional()}).safeParse(req.body);
  if(!v.success)return res.status(400).send("Invalid member ID, reason or timeout duration.");
  payload={userId:v.data.userId,reason:v.data.reason||"No reason supplied.",moderatorDiscordId:user.discordId};
  if(parsedType==="timeout_member"){if(!v.data.minutes)return res.status(400).send("Enter a timeout duration.");payload.durationSeconds=v.data.minutes*60;}
 } else if(parsedType==="create_channel"){
  const v=z.object({name:z.string().trim().min(1).max(90).regex(/^[a-z0-9_-]+$/),channelType:z.enum(["text","voice"]),topic:z.string().max(1024).optional()}).safeParse(req.body);
  if(!v.success)return res.status(400).send("Invalid channel name or type.");payload=v.data;
 } else if(parsedType==="delete_channel"){
  const v=z.object({channelId:id}).safeParse(req.body);if(!v.success)return res.status(400).send("Invalid channel ID.");payload=v.data;
 } else if(parsedType==="create_role"){
  const v=z.object({name:z.string().trim().min(1).max(100),color:z.string().regex(/^#[0-9a-fA-F]{6}$/).optional().or(z.literal(""))}).safeParse(req.body);
  if(!v.success)return res.status(400).send("Invalid role name or color.");payload={name:v.data.name,color:v.data.color||undefined};
 } else if(parsedType==="delete_role"){
  const v=z.object({roleId:id}).safeParse(req.body);if(!v.success)return res.status(400).send("Invalid role ID.");payload=v.data;
 } else if(parsedType==="delete_message"){
  const v=z.object({channelId:id,messageId:id}).safeParse(req.body);if(!v.success)return res.status(400).send("Both channel ID and message ID are required.");payload=v.data;
 } else if(parsedType==="purge_messages"){
  const v=z.object({channelId:id,count:z.coerce.number().int().min(2).max(100)}).safeParse(req.body);if(!v.success)return res.status(400).send("Purge count must be between 2 and 100.");payload=v.data;
 }
 const job=await db.discordAction.create({data:{type:parsedType,payload,requestedBy:user.id}});
 await audit(user.id,"discord.action.queued",job.id,{type:parsedType});
 res.redirect(parsedType.includes("member")||["warn_member","timeout_member","clear_timeout","kick_member","ban_member","unban_member"].includes(parsedType)?"/moderation":"/control");
});
app.get("/audit", auth, requirePermission("audit:view"), async (req,res) => {
 const user=(req as AuthedRequest).portalUser!;
 const events=await db.auditEvent.findMany({include:{actor:true},orderBy:{createdAt:"desc"},take:100});
 const rows=events.map(e=>`<tr><td>${e.createdAt.toLocaleString()}</td><td>${escapeHtml(e.actor?.displayName||e.actor?.username||"System")}</td><td>${escapeHtml(e.action)}</td><td>${escapeHtml(e.subject||"—")}</td></tr>`).join("");
 page(res,"Audit log",`<section class="page-heading"><span class="eyebrow">SECURITY & ACCOUNTABILITY</span><h1>Audit log.</h1><p>Recent administrative and account events.</p></section><section class="panel table-panel"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Subject</th></tr></thead><tbody>${rows}</tbody></table></section>`,user);
});

function actionForm(title: string, type: string, fields: string) {
 return '<section class="panel"><span class="eyebrow">DISCORD OPERATIONS</span><h2>'+escapeHtml(title)+'</h2><form method="post" action="/control/actions"><input type="hidden" name="type" value="'+escapeHtml(type)+'">'+fields+'<button class="button" type="submit">Queue action</button></form></section>';
}
app.get("/bot", auth, requireOwner, async (req,res) => {
 const user=(req as AuthedRequest).portalUser!;
 const status=getDiscordStatus();
 const jobs=await db.discordAction.findMany({orderBy:{createdAt:"desc"},take:12});
 const counts=await db.discordAction.groupBy({by:["status"],_count:{_all:true}});
 const count=(key:string)=>counts.find(x=>x.status===key)?._count._all||0;
 const rows=jobs.map(j=>'<tr><td>'+j.createdAt.toLocaleString()+'</td><td>'+escapeHtml(j.type)+'</td><td>'+escapeHtml(j.status)+'</td><td>'+escapeHtml(j.result||"Waiting for worker")+'</td><td>'+(j.status==="failed"?'<form method="post" action="/bot/actions/'+j.id+'/retry"><button class="text-button">Retry</button></form>':j.status==="queued"?'<form method="post" action="/bot/actions/'+j.id+'/cancel"><button class="text-button">Cancel</button></form>':'—')+'</td></tr>').join("");
 const html='<section class="page-heading"><span class="eyebrow">SYSTEMS · DISCORD GATEWAY</span><h1>Bot operations.</h1><p>Live connection state, command registration and action worker activity.</p></section>'+
 '<section class="stat-grid"><article class="stat"><small>GATEWAY</small><strong>'+(status.online?'Online':'Offline')+'</strong><span>'+(status.username?escapeHtml(status.username):'No active bot session')+'</span></article><article class="stat"><small>LATENCY</small><strong>'+(status.ping===null?'—':status.ping+' ms')+'</strong><span>Discord WebSocket heartbeat</span></article><article class="stat"><small>SLASH COMMANDS</small><strong>'+(status.commandsRegistered?'Registered':'Not registered')+'</strong><span>Guild-scoped /okg command group</span></article></section>'+
 '<section class="content-grid"><article class="panel"><span class="eyebrow">WORK QUEUE</span><h2>Action worker</h2><div class="list-row"><b>Queued</b><span class="status">'+count("queued")+'</span></div><div class="list-row"><b>Processing</b><span class="status">'+count("processing")+'</span></div><div class="list-row"><b>Completed</b><span class="status">'+count("completed")+'</span></div><div class="list-row"><b>Failed</b><span class="status">'+count("failed")+'</span></div><p class="muted small">The worker runs inside the same Render service as the portal.</p></article><article class="panel"><span class="eyebrow">REGISTERED COMMANDS</span><h2>/okg</h2><p>ping · server · member · announce · role-add · role-remove · nickname · warn · timeout · clear-timeout · kick · ban · unban · sync</p><p class="muted small">Every command checks the configured owner Discord user ID on the server before executing.</p></article></section>'+
 '<section class="panel table-panel"><h2>Recent bot jobs</h2><div class="table-wrap"><table><thead><tr><th>Requested</th><th>Action</th><th>Status</th><th>Result</th><th></th></tr></thead><tbody>'+(rows||'<tr><td colspan="5">No jobs recorded.</td></tr>')+'</tbody></table></div></section>';
 page(res,"Bot operations",html,user);
});
app.post("/bot/actions/:id/retry", auth, requireOwner, async (req,res) => {
 const user=(req as AuthedRequest).portalUser!;
 const id=String(req.params.id);
 const updated=await db.discordAction.updateMany({where:{id,status:"failed"},data:{status:"queued",result:null,processedAt:null}});
 if(updated.count) await audit(user.id,"discord.action.retried",id);
 res.redirect("/bot");
});
app.post("/bot/actions/:id/cancel", auth, requireOwner, async (req,res) => {
 const user=(req as AuthedRequest).portalUser!;
 const id=String(req.params.id);
 const updated=await db.discordAction.updateMany({where:{id,status:"queued"},data:{status:"canceled",result:"Canceled by platform owner.",processedAt:new Date()}});
 if(updated.count) await audit(user.id,"discord.action.canceled",id);
 res.redirect("/bot");
});
app.get("/server", auth, requireOwner, async (req,res) => {
 const user=(req as AuthedRequest).portalUser!;
 const snapshot=await getDiscordSnapshot();
 if(!snapshot) return page(res,"Server overview",'<section class="panel narrow"><h1>Discord is not connected.</h1><p>The bot must be online before live server information can be loaded.</p><a class="button" href="/bot">View bot status</a></section>',user);
 const channels=snapshot.channels.slice().sort((a,b)=>a.name.localeCompare(b.name)).map(c=>'<tr><td>#'+escapeHtml(c.name)+'</td><td><code>'+escapeHtml(c.id)+'</code></td><td>'+escapeHtml(String(c.type))+'</td><td><form method="post" action="/control/actions"><input type="hidden" name="type" value="delete_channel"><input type="hidden" name="channelId" value="'+escapeHtml(c.id)+'"><button class="text-button">Delete</button></form></td></tr>').join("");
 const roles=snapshot.roles.slice().sort((a,b)=>b.position-a.position).map(r=>'<tr><td><b>'+escapeHtml(r.name)+'</b></td><td><code>'+escapeHtml(r.id)+'</code></td><td>'+r.position+'</td><td>'+(r.managed?'Managed':r.editable?'Editable':'Above bot')+'</td><td>'+(r.editable?'<form method="post" action="/control/actions"><input type="hidden" name="type" value="delete_role"><input type="hidden" name="roleId" value="'+escapeHtml(r.id)+'"><button class="text-button">Delete</button></form>':'—')+'</td></tr>').join("");
 const html='<section class="page-heading"><span class="eyebrow">OFFICIAL DISCORD SERVER</span><h1>'+escapeHtml(snapshot.name)+'.</h1><p>Live server inventory from the connected OKG bot.</p></section>'+
 '<section class="stat-grid"><article class="stat"><small>MEMBERS</small><strong>'+snapshot.memberCount+'</strong><span>Discord-reported count</span></article><article class="stat"><small>CHANNELS</small><strong>'+snapshot.channels.length+'</strong><span>Visible to the bot</span></article><article class="stat"><small>ROLES</small><strong>'+snapshot.roles.length+'</strong><span>Manageable role inventory</span></article></section>'+
 '<section class="content-grid"><article class="panel"><h2>Create a channel</h2><form method="post" action="/control/actions"><input type="hidden" name="type" value="create_channel"><label>Channel name<input name="name" required maxlength="90" pattern="[a-z0-9_-]+"></label><label>Channel type<select name="channelType"><option value="text">Text</option><option value="voice">Voice</option></select></label><label>Topic (optional)<input name="topic" maxlength="1024"></label><button class="button">Create channel</button></form></article><article class="panel"><h2>Create a role</h2><form method="post" action="/control/actions"><input type="hidden" name="type" value="create_role"><label>Role name<input name="name" required maxlength="100"></label><label>Hex color<input name="color" placeholder="#78a9ff" pattern="#[0-9a-fA-F]{6}"></label><button class="button">Create role</button></form><p class="muted small">Role position and permissions can only be changed within the bot’s Discord role hierarchy.</p></article></section>'+
 '<section class="panel table-panel"><h2>Channels</h2><div class="table-wrap"><table><thead><tr><th>Channel</th><th>ID</th><th>Type</th><th></th></tr></thead><tbody>'+channels+'</tbody></table></div></section>'+
 '<section class="panel table-panel"><h2>Roles</h2><div class="table-wrap"><table><thead><tr><th>Role</th><th>ID</th><th>Position</th><th>Bot access</th><th></th></tr></thead><tbody>'+roles+'</tbody></table></div></section>';
 page(res,"Server overview",html,user);
});
app.get("/moderation", auth, requireOwner, async (req,res) => {
 const user=(req as AuthedRequest).portalUser!;
 await db.moderationCase.updateMany({where:{guildId,type:"timeout",active:true,expiresAt:{lt:new Date()}},data:{active:false}});
 const cases=await db.moderationCase.findMany({where:{guildId},orderBy:{createdAt:"desc"},take:150});
 const rows=cases.map(c=>'<tr><td>'+c.createdAt.toLocaleString()+'</td><td><code>'+escapeHtml(c.targetDiscordId)+'</code></td><td>'+escapeHtml(c.type)+'</td><td>'+escapeHtml(c.reason)+'</td><td>'+(c.active?'Active':'Closed')+'</td><td>'+escapeHtml(c.moderatorDiscordId)+'</td></tr>').join("");
 const html='<section class="page-heading"><span class="eyebrow">TRUST & SAFETY</span><h1>Moderation center.</h1><p>Issue and review warnings, timeouts, kicks and bans. Actions are executed by the connected bot and written to the audit log.</p></section>'+
 '<section class="content-grid"><article class="panel"><h2>Member action</h2><form method="post" action="/moderation/actions"><label>Action<select name="type"><option value="warn_member">Warn</option><option value="timeout_member">Timeout</option><option value="clear_timeout">Clear timeout</option><option value="kick_member">Kick</option><option value="ban_member">Ban</option><option value="unban_member">Unban</option></select></label><label>Member Discord ID<input name="userId" required pattern="[0-9]{15,22}"></label><label>Timeout duration (minutes)<input name="minutes" type="number" min="1" max="40320" value="60"></label><label>Reason<textarea name="reason" required maxlength="500" rows="3"></textarea></label><button class="button">Queue moderation action</button></form></article><article class="panel"><span class="eyebrow">IMPORTANT</span><h2>Moderation safeguards</h2><p>Only the configured platform owner can access this page. The bot must hold the relevant Discord permissions and be above the target member or role in the server hierarchy.</p><p class="muted small">Warnings are stored even if a member has DMs disabled. Timeout duration is limited to Discord’s 28-day maximum.</p></article></section>'+
 '<section class="panel table-panel"><h2>Moderation history</h2><div class="table-wrap"><table><thead><tr><th>Date</th><th>Member ID</th><th>Action</th><th>Reason</th><th>Status</th><th>Moderator</th></tr></thead><tbody>'+(rows||'<tr><td colspan="6">No moderation cases recorded.</td></tr>')+'</tbody></table></div></section>';
 page(res,"Moderation center",html,user);
});
app.post("/moderation/actions", auth, requireOwner, async (req,res) => {
 const user=(req as AuthedRequest).portalUser!;
 const type=z.enum(["warn_member","timeout_member","clear_timeout","kick_member","ban_member","unban_member"]).safeParse(req.body.type);
 const userId=z.string().regex(/^\d{15,22}$/).safeParse(req.body.userId);
 const reason=z.string().trim().min(1).max(500).safeParse(req.body.reason||"No reason supplied.");
 if(!type.success||!userId.success||!reason.success) return res.status(400).send("Check the moderation action, Discord ID and reason.");
 const payload:any={userId:userId.data,reason:reason.data,moderatorDiscordId:user.discordId};
 if(type.data==="timeout_member"){
  const minutes=z.coerce.number().int().min(1).max(40320).safeParse(req.body.minutes);
  if(!minutes.success) return res.status(400).send("Timeout must be between 1 and 40,320 minutes.");
  payload.durationSeconds=minutes.data*60;
 }
 const job=await db.discordAction.create({data:{type:type.data,payload,requestedBy:user.id}});
 await audit(user.id,"moderation.action.queued",job.id,{type:type.data,target:userId.data});
 res.redirect("/moderation");
});
app.get("/members/:discordId", auth, requireOwner, async (req,res) => {
 const user=(req as AuthedRequest).portalUser!;
 const discordId=String(req.params.discordId);
 if(!/^\d{15,22}$/.test(discordId)) return res.status(400).send("Invalid Discord ID.");
 const member=await db.user.findUnique({where:{discordId},include:{memberRoles:{where:{guildId}}}});
 const cases=await db.moderationCase.findMany({where:{guildId,targetDiscordId:discordId},orderBy:{createdAt:"desc"},take:30});
 const roles=member?.memberRoles.map(r=>'<li><code>'+escapeHtml(r.discordRoleId)+'</code></li>').join("")||"";
 const history=cases.map(c=>'<tr><td>'+c.createdAt.toLocaleString()+'</td><td>'+escapeHtml(c.type)+'</td><td>'+escapeHtml(c.reason)+'</td></tr>').join("");
 const html='<section class="page-heading"><span class="eyebrow">MEMBER PROFILE</span><h1>'+escapeHtml(member?.displayName||member?.username||"Discord member")+'.</h1><p>Discord ID: <code>'+escapeHtml(discordId)+'</code></p></section>'+
 '<section class="content-grid"><article class="panel"><h2>Account</h2><p>Username: '+escapeHtml(member?.username||"Not yet linked to a portal account")+'</p><p>Membership: '+(member?.isGuildMember?'Verified':'Not verified')+'</p><p>Last portal login: '+(member?.lastLoginAt.toLocaleString()||"—")+'</p></article><article class="panel"><h2>Synced roles</h2><ul>'+roles+'</ul></article></section>'+
 '<section class="panel table-panel"><h2>Moderation history</h2><table><thead><tr><th>Date</th><th>Action</th><th>Reason</th></tr></thead><tbody>'+(history||'<tr><td colspan="3">No history.</td></tr>')+'</tbody></table></section>';
 page(res,"Member profile",html,user);
});
app.get("/api/owner/status", auth, requireOwner, async (_req,res) => {
 const [users,applications,queued,failed]=await Promise.all([
  db.user.count({where:{isGuildMember:true}}),db.application.count(),
  db.discordAction.count({where:{status:"queued"}}),db.discordAction.count({where:{status:"failed"}})
 ]);
 res.json({ok:true,users,applications,queued,failed,discord:getDiscordStatus(),time:new Date().toISOString()});
});
app.post("/applications/:id/notes", auth, requireOwner, async (req,res) => {
 const user=(req as AuthedRequest).portalUser!;
 const applicationId=String(req.params.id);
 const body=z.string().trim().min(1).max(2000).safeParse(req.body.body);
 if(!body.success) return res.status(400).send("Note must contain 1 to 2,000 characters.");
 const application=await db.application.findUnique({where:{id:applicationId}});
 if(!application) return res.status(404).send("Application not found.");
 await db.applicationNote.create({data:{applicationId,authorId:user.id,body:body.data}});
 await audit(user.id,"application.note.created",applicationId);
 res.redirect("/applications/"+applicationId);
});

app.use((err: unknown,_req:Request,res:Response,_next:NextFunction)=>{console.error(err);res.status(500).send("Something went wrong. Please try again.");});
async function main(){
 if(!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required.");
 if(process.env.NODE_ENV === "production" && (!process.env.DISCORD_CLIENT_ID || !process.env.DISCORD_CLIENT_SECRET || !process.env.DISCORD_BOT_TOKEN || !guildId || !process.env.OWNER_DISCORD_USER_ID)) throw new Error("Discord OAuth, bot, guild and owner environment variables must be configured before production startup.");
 await startDiscordGateway(db);
 app.listen(port,()=>console.log(`OKG Portal listening on ${port}`));
}
main().catch(error=>{console.error(error);process.exit(1);});
