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
}