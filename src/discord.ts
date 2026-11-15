import { Client, GatewayIntentBits, Events, GuildMember } from "discord.js";
import { PrismaClient } from "@prisma/client";

export async function syncMember(db: PrismaClient, member: GuildMember) {
  const guildId = process.env.DISCORD_GUILD_ID;
  if (!guildId || member.guild.id !== guildId) return;
  const user = await db.user.findUnique({ where: { discordId: member.id } });
  if (!user) return;
  await db.user.update({ where: { id: user.id }, data: { isGuildMember: true } });
  const roleIds = [...member.roles.cache.keys()].filter(id => id !== member.guild.id);
  await db.$transaction([
    db.memberRole.deleteMany({ where: { userId: user.id, guildId } }),
    ...(roleIds.length ? [db.memberRole.createMany({
      data: roleIds.map(discordRoleId => ({ userId: user.id, guildId, discordRoleId })),
      skipDuplicates: true
    })] : [])
  ]);
  await db.auditEvent.create({
    data: { actorId: user.id, action: "discord.roles.synced", subject: member.id, details: { roleCount: roleIds.length } }
  });
}

export async function startDiscordGateway(db: PrismaClient) {
  if (!process.env.DISCORD_BOT_TOKEN || !process.env.DISCORD_GUILD_ID) {
    console.warn("Discord Gateway is not configured yet; add DISCORD_BOT_TOKEN and DISCORD_GUILD_ID.");
    return;
  }
  const client = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers] });
  client.on(Events.GuildMemberUpdate, async (_before, after) => {
    try { await syncMember(db, after); } catch (error) { console.error("Role update sync failed", error); }
  });
  client.on(Events.GuildMemberAdd, async member => {
    try { await syncMember(db, member); } catch (error) { console.error("Member join sync failed", error); }
  });
  client.on(Events.GuildMemberRemove, async member => {
    try {
      const user = await db.user.findUnique({ where: { discordId: member.id } });
      if (user) await db.$transaction([
        db.memberRole.deleteMany({ where: { userId: user.id, guildId: member.guild.id } }),
        db.user.update({ where: { id: user.id }, data: { isGuildMember: false } })
      ]);
    } catch (error) { console.error("Member removal sync failed", error); }
  });
  client.once(Events.ClientReady, ready => console.log(`Discord role listener connected as ${ready.user.tag}`));
  await client.login(process.env.DISCORD_BOT_TOKEN);
  let processing = false;
  const processQueue = async () => {
    if (processing || !client.isReady()) return;
    processing = true;
    try {
      const job = await db.discordAction.findFirst({ where: { status: "queued" }, orderBy: { createdAt: "asc" } });
      if (!job) return;
      const claimed = await db.discordAction.updateMany({ where: { id: job.id, status: "queued" }, data: { status: "processing" } });
      if (!claimed.count) return;
      try {
        const payload = job.payload as Record<string, string>;
        const guild = await client.guilds.fetch(guildId);
        if (job.type === "send_message") {
          const channel = await guild.channels.fetch(payload.channelId);
          if (!channel || !channel.isTextBased() || !("send" in channel)) throw new Error("Target channel cannot receive messages.");
          await channel.send({ content: payload.message, allowedMentions: { parse: [] } });
        } else if (job.type === "add_role" || job.type === "remove_role") {
          const member = await guild.members.fetch(payload.userId);
          const role = await guild.roles.fetch(payload.roleId);
          if (!role || !role.editable) throw new Error("Role does not exist or is above the bot's highest role.");
          if (job.type === "add_role") await member.roles.add(role, "Requested through OKG Portal");
          else await member.roles.remove(role, "Requested through OKG Portal");
        } else if (job.type === "set_nickname") {
          const member = await guild.members.fetch(payload.userId);
          await member.setNickname(payload.nickname || null, "Changed through OKG Portal");
        } else {
          throw new Error("Unsupported Discord action.");
        }
        await db.discordAction.update({ where: { id: job.id }, data: { status: "completed", result: "Action completed successfully.", processedAt: new Date() } });
        await db.auditEvent.create({ data: { actorId: job.requestedBy, action: "discord.action.completed", subject: job.type, details: { jobId: job.id } } });
      } catch (error) {
        const message = error instanceof Error ? error.message.slice(0, 500) : "Unknown Discord action error.";
        await db.discordAction.update({ where: { id: job.id }, data: { status: "failed", result: message, processedAt: new Date() } });
        await db.auditEvent.create({ data: { actorId: job.requestedBy, action: "discord.action.failed", subject: job.type, details: { jobId: job.id, error: message } } });
      }
    } catch (error) {
      console.error("Discord action queue error", error);
    } finally {
      processing = false;
    }
  };
  setInterval(() => { void processQueue(); }, 2500);
}