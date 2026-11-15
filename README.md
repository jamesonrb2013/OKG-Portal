# OKG Portal

The official One Kid Gaming owner and community administration portal.

## Current platform modules

- **Owner dashboard:** live counts for linked members, applications, moderation cases, queued actions, failed actions and Discord bot state.
- **Discord identity:** OAuth2 sign-in, official-server membership verification, owner-ID allowlist and server-side session checks.
- **Member directory:** linked member search, Discord IDs, synced roles, account profile and moderation history.
- **Server management:** live channel and role inventory, create text/voice channels, create roles, delete editable channels and roles.
- **Moderation center:** warnings, timeouts, timeout clearing, kicks, bans and unbans with durable case history.
- **Discord Control Center:** channel announcements, DMs, role assignment/removal, nicknames, moderation actions, message deletion and bulk cleanup.
- **Bot operations:** Gateway state, heartbeat latency, slash-command registration, queue counts and recent job results.
- **Applications:** staff/helper/partner submissions, review status and internal reviewer notes.
- **Platform settings:** Discord role-to-permission mappings and an owner-managed homepage announcement banner.
- **Audit trail:** login, role sync, portal changes and bot action outcomes.
- **Owner API:** /api/owner/status, protected by the same owner session middleware.

## Discord slash commands

The bot registers a guild-scoped /okg command group:
- ping, server, member, sync
- announce, dm
- role-add, role-remove, role-create, role-delete
- nickname
- channel-create, channel-delete
- message-delete, purge
- warn, timeout, clear-timeout, kick, ban, unban

Every interaction checks OWNER_DISCORD_USER_ID on the server. Being a Discord administrator or holding a mapped role does not bypass that owner-ID check.

## Stack

Node.js 20+, Express 5, TypeScript, Prisma, PostgreSQL, Discord.js 14.

## Environment variables

- DATABASE_URL — Aiven PostgreSQL connection string.
- SESSION_SECRET — long random value (at least 32 characters in production).
- DISCORD_CLIENT_ID
- DISCORD_CLIENT_SECRET
- DISCORD_BOT_TOKEN
- DISCORD_GUILD_ID
- DISCORD_REDIRECT_URI — https://portal.onekidgaming.com/auth/discord/callback
- OWNER_DISCORD_USER_ID — the one permitted portal identity.
- APP_BASE_URL — https://portal.onekidgaming.com
- NODE_ENV=production

Never commit .env files, OAuth secrets, bot tokens, or database credentials.

## Local setup

1. Install Node.js 20 or newer.
2. Run npm install.
3. Copy .env.example to .env and fill in the values.
4. Create a PostgreSQL database and set DATABASE_URL.
5. Run npm run db:generate and npm run db:deploy.
6. Run npm run dev.

## Discord setup

Create a Discord application and bot. Enable the **Server Members Intent** under Bot > Privileged Gateway Intents. Invite the bot to the official OKG server with:
- View Channels
- Read Message History
- Send Messages
- Manage Messages
- Manage Roles
- Manage Nicknames
- Moderate Members
- Kick Members
- Ban Members
- Manage Channels

Only grant the permissions the portal workflows need. The bot must be placed above roles it needs to manage. Its slash commands are registered automatically when the Gateway becomes ready.

OAuth redirect URI: https://portal.onekidgaming.com/auth/discord/callback

## Render

The existing service is okg-portal in the Okg Portal account / My Workspace workspace.
- Build: npm install && npm run build
- Start: npm start
- Start script: prisma db push && node dist/server.js
- Health check: /health
- Custom domain: portal.onekidgaming.com

The portal and bot Gateway/action worker run in the same Render web service. Keep the service to one instance while using its in-process action worker.

## Private beta security

- Only the exact Discord ID in OWNER_DISCORD_USER_ID can complete OAuth sign-in or use a session.
- Existing non-owner sessions are destroyed on their next protected request.
- Portal modules and the owner status API use server-side authentication; hiding a link is not treated as security.
- Role mappings cannot grant platform-owner access.
- Discord slash commands independently verify the same owner ID.
- Destructive Discord actions are queued, executed by the bot, and recorded with success/failure results.
- A worker restart marks old in-progress actions as failed for manual verification instead of blindly replaying potentially completed actions.
- PostgreSQL session connections preserve Aiven's documented sslmode=require compatibility.

## Operational limitations

Discord permissions and role hierarchy still apply. Discord may reject actions against managed roles, higher-ranked members, locked channels, or messages older than 14 days for bulk deletion. DMs may fail when a recipient blocks DMs. These failures are reported in the bot job history rather than shown as successful actions.
