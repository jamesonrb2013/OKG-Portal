# OKG Portal

The official One Kid Gaming community platform for members, staff and leadership.

## Portal areas

- **Member portal:** Discord-linked member profiles, XP and levels, member leaderboards, game scores, community games, giveaways, event listings and applications.
- **Staff portal:** role-gated staff workspace, assigned tasks, application review and private staff reports / handovers.
- **Executive portal:** role-permission mapping, staff task assignment, announcements, event publishing and giveaway publishing.
- **Private events:** secret events are only shown to explicitly invited, verified OKG members.
- **Audit trail:** sign-ins, profile changes, applications, staff records and management actions are logged.

## Separation from OKG Manager

The portal is not a Discord bot control panel. Portal routes for bot operations, moderation, channel management, server management, bot job queues, and the old control center are blocked. The portal's Discord integration is limited to verifying official-server membership and synchronizing Discord roles. Legacy slash commands registered by the portal bot are cleared at Gateway startup.

Use **OKG Manager** for bot and server administration. This portal is for the community experience and internal staff workflows.

## Access model

- Members sign in with Discord OAuth2 and must be verified in the official OKG Discord server.
- Staff access is granted through role-to-permission mappings stored in PostgreSQL.
- Executive access is separately permission-gated.
- The platform owner is recognized by `OWNER_DISCORD_USER_ID` and receives platform-owner permissions.
- Permissions are checked server-side on every protected route. Hiding navigation links is not used as a security boundary.

Available role permissions:
- `staff:access`, `staff:tasks`, `staff:reports`
- `applications:view`, `applications:review`
- `events:manage`, `giveaways:manage`, `announcements:manage`
- `executive:access`, `executive:manage`
- `members:view`, `audit:view`

The owner can configure role mappings in the Executive Portal.

## Stack

Node.js 20+, Express 5, TypeScript, Prisma 6, PostgreSQL, Discord.js 14.

## Environment variables

- `DATABASE_URL` — PostgreSQL connection string (Aiven is the configured provider).
- `SESSION_SECRET` — random secret of at least 32 characters in production.
- `DISCORD_CLIENT_ID`
- `DISCORD_CLIENT_SECRET`
- `DISCORD_BOT_TOKEN`
- `DISCORD_GUILD_ID`
- `DISCORD_REDIRECT_URI` — `https://portal.onekidgaming.com/auth/discord/callback`
- `OWNER_DISCORD_USER_ID` — platform owner's Discord user ID.
- `APP_BASE_URL` — `https://portal.onekidgaming.com`
- `NODE_ENV=production`

Never commit secrets, tokens, or database credentials.

## Local setup

1. Install Node.js 20 or newer.
2. Run `npm install`.
3. Copy `.env.example` to `.env` and fill in the values.
4. Run `npm run build`.
5. Apply schema changes explicitly with `npm run db:deploy` using the intended production database URL, then run `npm start`. The web service startup does not mutate the database schema.

## Discord setup

Create a dedicated Discord application and bot for portal identity verification and role synchronization. Enable **Server Members Intent** in the Developer Portal. Invite the bot to the official OKG server and keep it in the guild. It does not need Discord moderation, channel-management or message-management permissions for the portal's current features.

The bot must remain online for Gateway role synchronization. OAuth membership checks also require the bot token and official guild ID.

## Render

The existing service is **OKG-Portal** in the **Okg Portal / My Workspace** Render workspace.
- Build: `npm install && npm run build`
- Start: `npm start`
- Health check: `/health`
- Custom domain: `portal.onekidgaming.com`
- One instance is sufficient for the in-process Discord Gateway role listener.

If Render cannot clone this private GitHub repository, reconnect the GitHub integration and grant the Render installation access to `jamesonrb2013/OKG-Portal`.

## Security notes

- Session cookies are HTTP-only, secure in production, and same-site.
- State validation protects the Discord OAuth callback.
- Cross-origin state-changing requests are rejected.
- Discord roles are synchronized on join, leave, role update and sign-in.
- Secret event visibility is enforced by explicit event-invite records, not by an unlisted URL.
- Portal content and workflows do not execute Discord bot commands or moderation actions.
