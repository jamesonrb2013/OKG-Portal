# OKG Portal

The official One Kid Gaming member, staff and administration portal.

## Current foundation
- Discord OAuth2 sign-in and official-server membership verification.
- Discord Gateway role synchronization using `GuildMemberUpdate`, `GuildMemberAdd`, and `GuildMemberRemove`.
- Permission mappings based on immutable Discord role IDs.
- Protected Platform Owner identity, independent from role mappings.
- Member dashboard and staff/helper/partner application submission.
- Permission-gated application review, role mapping administration, and audit log.
- PostgreSQL-backed users, role assignments, applications, notes, and audit events.

## Stack
Node.js 20+, Express, TypeScript, Prisma, PostgreSQL, Discord.js.

## Local setup
1. Install Node.js 20 or newer.
2. Run `npm install`.
3. Copy `.env.example` to `.env` and fill in the values.
4. Create a PostgreSQL database and set `DATABASE_URL`.
5. Run `npm run db:generate` and `npm run db:deploy`.
6. Run `npm run dev`.

## Discord setup
Create an application in the Discord Developer Portal and add a bot. Enable the **Server Members Intent** under Bot > Privileged Gateway Intents. Invite the bot to the official OKG server with the minimum permissions needed to view the server and read member data. The bot token and OAuth client secret belong only in Render environment variables.

OAuth redirect URI: `https://portal.onekidgaming.com/auth/discord/callback`

Required environment variables:
- `DATABASE_URL`
- `SESSION_SECRET` (use a long random value)
- `DISCORD_CLIENT_ID`
- `DISCORD_CLIENT_SECRET`
- `DISCORD_BOT_TOKEN`
- `DISCORD_GUILD_ID`
- `DISCORD_REDIRECT_URI`
- `OWNER_DISCORD_USER_ID`
- `APP_BASE_URL`

## Render
The intended web service is `okg-portal` in the **Okg Portal** Render account / **My Workspace** workspace.
- Runtime: Node
- Build: `npm install && npm run build && npm run db:generate`
- Start: `npm run db:deploy && npm start`
- Health check: `/health`
- Custom domain: `portal.onekidgaming.com`

Do not deploy until a PostgreSQL database and all required Discord environment variables have been configured. Never commit credentials or paste tokens into chat.

## Security notes
- The server verifies guild membership directly through Discord before creating a session.
- Portal permissions are derived server-side from synchronized role IDs on each protected request.
- The Platform Owner is identified by `OWNER_DISCORD_USER_ID`; Discord role mappings cannot grant or revoke owner status.
- Session cookies are HTTP-only, secure in production, and use SameSite=Lax.
- Application content and audit events are stored server-side.
