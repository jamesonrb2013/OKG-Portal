import {
  Client, GatewayIntentBits, Events, GuildMember, REST, Routes,
  SlashCommandBuilder, ChannelType, PermissionFlagsBits
} from "discord.js";
import { PrismaClient } from "@prisma/client";

let activeClient: Client | null = null;
let botStartedAt: Date | null = null;
let registeredCommands = false;

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

async function writeModerationCase(
  db: PrismaClient, guildId: string, targetDiscordId: string, moderatorDiscordId: string,
  type: string, reason: string, durationSeconds?: number
) {
  return db.moderationCase.create({
    data: {
      guildId, targetDiscordId, moderatorDiscordId, type, reason,
      durationSeconds,
      active: type === "timeout" || type === "ban",
      expiresAt: durationSeconds ? new Date(Date.now() + durationSeconds * 1000) : null
    }
  });
}

async function registerOwnerCommands(client: Client, guildId: string) {
  if (!client.application || !process.env.DISCORD_CLIENT_ID) return;
  const command = new SlashCommandBuilder()
    .setName("okg").setDescription("Official One Kid Gaming administration commands")
    .addSubcommand(s => s.setName("ping").setDescription("Check bot response and connection"))
    .addSubcommand(s => s.setName("server").setDescription("Show official server information"))
    .addSubcommand(s => s.setName("member").setDescription("Look up a server member")
      .addUserOption(o => o.setName("member").setDescription("Member to inspect").setRequired(true)))
    .addSubcommand(s => s.setName("announce").setDescription("Send an announcement")
      .addChannelOption(o => o.setName("channel").setDescription("Text channel").addChannelTypes(ChannelType.GuildText, ChannelType.GuildAnnouncement).setRequired(true))
      .addStringOption(o => o.setName("message").setDescription("Announcement text").setMaxLength(1900).setRequired(true)))
    .addSubcommand(s => s.setName("role-add").setDescription("Give a member a role")
      .addUserOption(o => o.setName("member").setDescription("Member").setRequired(true))
      .addRoleOption(o => o.setName("role").setDescription("Role to add").setRequired(true)))
    .addSubcommand(s => s.setName("role-remove").setDescription("Remove a member role")
      .addUserOption(o => o.setName("member").setDescription("Member").setRequired(true))
      .addRoleOption(o => o.setName("role").setDescription("Role to remove").setRequired(true)))
    .addSubcommand(s => s.setName("nickname").setDescription("Change a member nickname")
      .addUserOption(o => o.setName("member").setDescription("Member").setRequired(true))
      .addStringOption(o => o.setName("nickname").setDescription("New nickname (blank resets)").setMaxLength(32).setRequired(false)))
    .addSubcommand(s => s.setName("warn").setDescription("Record a member warning")
      .addUserOption(o => o.setName("member").setDescription("Member").setRequired(true))
      .addStringOption(o => o.setName("reason").setDescription("Reason").setMaxLength(500).setRequired(true)))
    .addSubcommand(s => s.setName("timeout").setDescription("Timeout a member")
      .addUserOption(o => o.setName("member").setDescription("Member").setRequired(true))
      .addIntegerOption(o => o.setName("minutes").setDescription("Duration in minutes").setMinValue(1).setMaxValue(40320).setRequired(true))
      .addStringOption(o => o.setName("reason").setDescription("Reason").setMaxLength(500).setRequired(true)))
    .addSubcommand(s => s.setName("clear-timeout").setDescription("Remove a member timeout")
      .addUserOption(o => o.setName("member").setDescription("Member").setRequired(true)))
    .addSubcommand(s => s.setName("kick").setDescription("Kick a member")
      .addUserOption(o => o.setName("member").setDescription("Member").setRequired(true))
      .addStringOption(o => o.setName("reason").setDescription("Reason").setMaxLength(500).setRequired(true)))
    .addSubcommand(s => s.setName("ban").setDescription("Ban a member")
      .addUserOption(o => o.setName("member").setDescription("Member").setRequired(true))
      .addStringOption(o => o.setName("reason").setDescription("Reason").setMaxLength(500).setRequired(true)))
    .addSubcommand(s => s.setName("unban").setDescription("Unban a Discord user")
      .addStringOption(o => o.setName("user-id").setDescription("Discord user ID").setRequired(true))
      .addStringOption(o => o.setName("reason").setDescription("Reason").setMaxLength(500).setRequired(false)))
    .addSubcommand(s => s.setName("dm").setDescription("Send a direct message to a member")
      .addUserOption(o => o.setName("member").setDescription("Member").setRequired(true))
      .addStringOption(o => o.setName("message").setDescription("Message").setMaxLength(1900).setRequired(true)))
    .addSubcommand(s => s.setName("channel-create").setDescription("Create a text or voice channel")
      .addStringOption(o => o.setName("name").setDescription("Channel name").setMaxLength(90).setRequired(true))
      .addStringOption(o => o.setName("kind").setDescription("Channel type").addChoices({name:"Text",value:"text"},{name:"Voice",value:"voice"}).setRequired(true))
      .addStringOption(o => o.setName("topic").setDescription("Optional channel topic").setMaxLength(1024).setRequired(false)))
    .addSubcommand(s => s.setName("channel-delete").setDescription("Delete a channel")
      .addChannelOption(o => o.setName("channel").setDescription("Channel to delete").setRequired(true)))
    .addSubcommand(s => s.setName("role-create").setDescription("Create a server role")
      .addStringOption(o => o.setName("name").setDescription("Role name").setMaxLength(100).setRequired(true))
      .addStringOption(o => o.setName("color").setDescription("Hex color such as #78a9ff").setRequired(false)))
    .addSubcommand(s => s.setName("role-delete").setDescription("Delete a server role")
      .addRoleOption(o => o.setName("role").setDescription("Role to delete").setRequired(true)))
    .addSubcommand(s => s.setName("purge").setDescription("Bulk-delete recent messages")
      .addChannelOption(o => o.setName("channel").setDescription("Text channel").addChannelTypes(ChannelType.GuildText).setRequired(true))
      .addIntegerOption(o => o.setName("count").setDescription("Number of messages").setMinValue(2).setMaxValue(100).setRequired(true)))
    .addSubcommand(s => s.setName("message-delete").setDescription("Delete a single message")
      .addChannelOption(o => o.setName("channel").setDescription("Text channel").addChannelTypes(ChannelType.GuildText, ChannelType.GuildAnnouncement).setRequired(true))
      .addStringOption(o => o.setName("message-id").setDescription("Message ID").setRequired(true)))
    .addSubcommand(s => s.setName("sync").setDescription("Refresh the bot's server member cache"));
  const rest = new REST({ version: "10" }).setToken(process.env.DISCORD_BOT_TOKEN!);
  await rest.put(Routes.applicationGuildCommands(process.env.DISCORD_CLIENT_ID, guildId), { body: [command.toJSON()] });
  registeredCommands = true;
  console.log("Registered " + command.name + " owner-gated slash command group.");
}

async function handleOwnerCommand(db: PrismaClient, client: Client, interaction: any) {
  if (!interaction.isChatInputCommand() || interaction.commandName !== "okg") return;
  const ownerId = process.env.OWNER_DISCORD_USER_ID;
  if (!ownerId || interaction.user.id !== ownerId) {
    await interaction.reply({ content: "This command is restricted to the OKG platform owner.", ephemeral: true });
    return;
  }
  if (interaction.guildId !== process.env.DISCORD_GUILD_ID) {
    await interaction.reply({ content: "This command is only available in the official OKG server.", ephemeral: true });
    return;
  }
  await interaction.deferReply({ ephemeral: true });
  const sub = interaction.options.getSubcommand();
  const guild = await client.guilds.fetch(process.env.DISCORD_GUILD_ID!);
  const actor = await db.user.findUnique({ where: { discordId: interaction.user.id } });
  const log = async (action: string, subject?: string, details?: object) => {
    await db.auditEvent.create({ data: { actorId: actor?.id, action, subject, details: details as any } });
  };
  if (sub === "ping") {
    await interaction.editReply("OKG bot is online. Gateway latency: " + client.ws.ping + " ms.");
    return;
  }
  if (sub === "server") {
    await interaction.editReply("**" + guild.name + "**\nMembers: " + (guild.memberCount ?? "unknown") + "\nChannels: " + guild.channels.cache.size + "\nRoles: " + guild.roles.cache.size + "\nBot latency: " + client.ws.ping + " ms.");
    return;
  }
  if (sub === "member") {
    const user = interaction.options.getUser("member", true);
    const member = await guild.members.fetch(user.id);
    await interaction.editReply("**" + user.tag + "**\nID: " + user.id + "\nJoined: " + (member.joinedAt?.toLocaleString() || "unknown") + "\nRoles: " + (member.roles.cache.filter((r: any) => r.id !== guild.id).map((r: any) => r.name).join(", ") || "None"));
    return;
  }
  if (sub === "announce") {
    const channel = interaction.options.getChannel("channel", true);
    const message = interaction.options.getString("message", true);
    if (!channel.isTextBased() || !("send" in channel)) throw new Error("That channel cannot receive messages.");
    await channel.send({ content: message, allowedMentions: { parse: [] } });
    await log("discord.slash.announce", channel.id);
    await interaction.editReply("Announcement sent to <#" + channel.id + ">.");
    return;
  }
  if (sub === "dm") {
    const user = interaction.options.getUser("member", true);
    const message = interaction.options.getString("message", true);
    await user.send({ content: message, allowedMentions: { parse: [] } });
    await log("discord.slash.dm", user.id);
    await interaction.editReply("Direct message sent to " + user.tag + ".");
    return;
  }
  if (sub === "channel-create") {
    const name = interaction.options.getString("name", true).toLowerCase();
    const kind = interaction.options.getString("kind", true);
    if (!/^[a-z0-9_-]{1,90}$/.test(name)) throw new Error("Channel names must use lowercase letters, numbers, hyphens or underscores.");
    const channel = await guild.channels.create({ name, type: kind === "voice" ? ChannelType.GuildVoice : ChannelType.GuildText, topic: interaction.options.getString("topic") || undefined });
    await log("discord.slash.channel.create", channel.id);
    await interaction.editReply("Created channel <#" + channel.id + ">.");
    return;
  }
  if (sub === "channel-delete") {
    const channel = interaction.options.getChannel("channel", true);
    await channel.delete("Deleted by OKG platform owner");
    await log("discord.slash.channel.delete", channel.id);
    await interaction.editReply("Channel deleted.");
    return;
  }
  if (sub === "role-create") {
    const name = interaction.options.getString("name", true);
    const color = interaction.options.getString("color") || undefined;
    if (color && !/^#[0-9a-fA-F]{6}$/.test(color)) throw new Error("Use a six-digit hex color such as #78a9ff.");
    const role = await guild.roles.create({ name, color, reason: "Created by OKG platform owner" });
    await log("discord.slash.role.create", role.id);
    await interaction.editReply("Created role **" + role.name + "** (" + role.id + ").");
    return;
  }
  if (sub === "role-delete") {
    const role = interaction.options.getRole("role", true);
    if (!role.editable) throw new Error("That role is above the bot's highest role or cannot be managed.");
    await role.delete("Deleted by OKG platform owner");
    await log("discord.slash.role.delete", role.id);
    await interaction.editReply("Role deleted.");
    return;
  }
  if (sub === "purge") {
    const channel = interaction.options.getChannel("channel", true);
    const count = interaction.options.getInteger("count", true);
    if (!channel.isTextBased() || !("bulkDelete" in channel)) throw new Error("That channel does not support bulk deletion.");
    const deleted = await channel.bulkDelete(count, true);
    await log("discord.slash.purge", channel.id, { count: deleted.size });
    await interaction.editReply("Deleted " + deleted.size + " recent messages. Messages older than 14 days are skipped by Discord.");
    return;
  }
  if (sub === "message-delete") {
    const channel = interaction.options.getChannel("channel", true);
    const messageId = interaction.options.getString("message-id", true);
    if (!/^\d{15,22}$/.test(messageId) || !channel.isTextBased() || !("messages" in channel)) throw new Error("Invalid message ID or channel.");
    const message = await channel.messages.fetch(messageId);
    await message.delete();
    await log("discord.slash.message.delete", messageId, { channelId: channel.id });
    await interaction.editReply("Message deleted.");
    return;
  }
  if (sub === "role-add" || sub === "role-remove") {
    const user = interaction.options.getUser("member", true);
    const role = interaction.options.getRole("role", true);
    const member = await guild.members.fetch(user.id);
    if (!role.editable) throw new Error("That role is above the bot's highest role or cannot be managed.");
    if (sub === "role-add") await member.roles.add(role, "OKG platform owner command");
    else await member.roles.remove(role, "OKG platform owner command");
    await log("discord.slash." + sub, user.id, { roleId: role.id });
    await interaction.editReply((sub === "role-add" ? "Added " : "Removed ") + role.name + " " + (sub === "role-add" ? "to " : "from ") + user.tag + ".");
    return;
  }
  if (sub === "nickname") {
    const user = interaction.options.getUser("member", true);
    const nickname = interaction.options.getString("nickname") || null;
    const member = await guild.members.fetch(user.id);
    await member.setNickname(nickname, "OKG platform owner command");
    await log("discord.slash.nickname", user.id, { nickname });
    await interaction.editReply("Nickname updated for " + user.tag + ".");
    return;
  }
  if (sub === "warn" || sub === "timeout" || sub === "clear-timeout" || sub === "kick" || sub === "ban") {
    const user = interaction.options.getUser("member", true);
    const member = await guild.members.fetch(user.id);
    const reason = interaction.options.getString("reason") || "No reason supplied.";
    if (sub === "warn") {
      await writeModerationCase(db, guild.id, user.id, interaction.user.id, "warn", reason);
      try { await user.send("You have received a warning in " + guild.name + ". Reason: " + reason); } catch {}
    } else if (sub === "timeout") {
      const minutes = interaction.options.getInteger("minutes", true);
      await member.timeout(minutes * 60 * 1000, reason);
      await writeModerationCase(db, guild.id, user.id, interaction.user.id, "timeout", reason, minutes * 60);
    } else if (sub === "clear-timeout") {
      await member.timeout(null, "Timeout cleared by OKG platform owner");
      await db.moderationCase.updateMany({ where: { guildId: guild.id, targetDiscordId: user.id, type: "timeout", active: true }, data: { active: false } });
    } else if (sub === "kick") {
      await member.kick(reason);
      await writeModerationCase(db, guild.id, user.id, interaction.user.id, "kick", reason);
    } else {
      await member.ban({ reason, deleteMessageSeconds: 0 });
      await writeModerationCase(db, guild.id, user.id, interaction.user.id, "ban", reason);
    }
    await log("discord.slash." + sub, user.id, { reason });
    await interaction.editReply(sub === "warn" ? "Warning recorded for " + user.tag + "." : sub === "clear-timeout" ? "Timeout cleared for " + user.tag + "." : sub.charAt(0).toUpperCase() + sub.slice(1) + " completed for " + user.tag + ".");
    return;
  }
  if (sub === "unban") {
    const userId = interaction.options.getString("user-id", true);
    if (!/^\d{15,22}$/.test(userId)) throw new Error("Enter a valid Discord user ID.");
    await guild.bans.remove(userId, interaction.options.getString("reason") || "Unbanned by OKG platform owner");
    await db.moderationCase.updateMany({ where: { guildId: guild.id, targetDiscordId: userId, type: "ban", active: true }, data: { active: false } });
    await log("discord.slash.unban", userId);
    await interaction.editReply("Unban completed for user ID " + userId + ".");
    return;
  }
  if (sub === "sync") {
    const members = await guild.members.fetch();
    for (const member of members.values()) await syncMember(db, member);
    await log("discord.slash.sync", guild.id, { fetchedMembers: members.size });
    await interaction.editReply("Member cache refreshed and linked member roles synchronized. Fetched " + members.size + " server members.");
  }
}

export function getDiscordStatus() {
  return {
    configured: Boolean(process.env.DISCORD_BOT_TOKEN && process.env.DISCORD_GUILD_ID),
    online: Boolean(activeClient?.isReady()),
    username: activeClient?.user?.tag || null,
    guildId: process.env.DISCORD_GUILD_ID || null,
    ping: activeClient?.ws.ping ?? null,
    uptimeSeconds: botStartedAt ? Math.floor((Date.now() - botStartedAt.getTime()) / 1000) : null,
    commandsRegistered: registeredCommands
  };
}

export async function getDiscordSnapshot() {
  if (!activeClient?.isReady() || !process.env.DISCORD_GUILD_ID) return null;
  const guild = await activeClient.guilds.fetch(process.env.DISCORD_GUILD_ID);
  const [channels, roles] = await Promise.all([guild.channels.fetch(), guild.roles.fetch()]);
  return {
    id: guild.id, name: guild.name, memberCount: guild.memberCount,
    icon: guild.iconURL({ size: 128 }),
    channels: channels.filter(Boolean).map(c => ({ id: c!.id, name: c!.name, type: c!.type, parentId: "parentId" in c! ? c!.parentId : null })),
    roles: roles.filter(r => r.id !== guild.id).map(r => ({ id: r.id, name: r.name, color: r.hexColor, position: r.position, managed: r.managed, editable: r.editable }))
  };
}

export async function startDiscordGateway(db: PrismaClient) {
  const guildId = process.env.DISCORD_GUILD_ID;
  if (!process.env.DISCORD_BOT_TOKEN || !guildId) {
    console.warn("Discord Gateway is not configured yet; add DISCORD_BOT_TOKEN and DISCORD_GUILD_ID.");
    return;
  }
  const client = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers] });
  activeClient = client;
  client.on(Events.Error, error => console.error("Discord gateway client error:", error));
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
  client.on(Events.InteractionCreate, interaction => {
    void handleOwnerCommand(db, client, interaction).catch(async error => {
      console.error("Discord command failed", error);
      if ("isRepliable" in interaction && interaction.isRepliable()) {
        const message = error instanceof Error ? error.message.slice(0, 400) : "Command failed.";
        try {
          if (interaction.deferred || interaction.replied) await interaction.editReply("Command failed: " + message);
          else await interaction.reply({ content: "Command failed: " + message, ephemeral: true });
        } catch {}
      }
    });
  });
  client.once(Events.ClientReady, async ready => {
    botStartedAt = new Date();
    console.log("Discord role listener connected as " + ready.user.tag);
    try { await registerOwnerCommands(client, guildId); }
    catch (error) { console.error("Slash command registration failed", error); }
  });
  try {
    await client.login(process.env.DISCORD_BOT_TOKEN);
  } catch (error) {
    activeClient = null;
    try { client.destroy(); } catch {}
    throw error;
  }
  await db.discordAction.updateMany({
    where: { status: "processing", createdAt: { lt: new Date(Date.now() - 10 * 60 * 1000) } },
    data: { status: "failed", result: "Worker restarted before this action completed. Verify the Discord state before retrying.", processedAt: new Date() }
  });
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
        const payload = job.payload as Record<string, any>;
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
        } else if (job.type === "kick_member") {
          const member = await guild.members.fetch(payload.userId);
          await member.kick(payload.reason || "Moderated through OKG Portal");
          await writeModerationCase(db, guildId, payload.userId, payload.moderatorDiscordId, "kick", payload.reason || "No reason supplied.");
        } else if (job.type === "ban_member") {
          const member = await guild.members.fetch(payload.userId);
          await member.ban({ reason: payload.reason || "Moderated through OKG Portal", deleteMessageSeconds: 0 });
          await writeModerationCase(db, guildId, payload.userId, payload.moderatorDiscordId, "ban", payload.reason || "No reason supplied.");
        } else if (job.type === "unban_member") {
          await guild.bans.remove(payload.userId, payload.reason || "Unbanned through OKG Portal");
          await db.moderationCase.updateMany({ where: { guildId, targetDiscordId: payload.userId, type: "ban", active: true }, data: { active: false } });
        } else if (job.type === "timeout_member") {
          const member = await guild.members.fetch(payload.userId);
          const seconds = Number(payload.durationSeconds);
          if (!Number.isInteger(seconds) || seconds < 60 || seconds > 2419200) throw new Error("Timeout must be between 1 minute and 28 days.");
          await member.timeout(seconds * 1000, payload.reason || "Timed out through OKG Portal");
          await writeModerationCase(db, guildId, payload.userId, payload.moderatorDiscordId, "timeout", payload.reason || "No reason supplied.", seconds);
        } else if (job.type === "clear_timeout") {
          const member = await guild.members.fetch(payload.userId);
          await member.timeout(null, "Timeout cleared through OKG Portal");
          await db.moderationCase.updateMany({ where: { guildId, targetDiscordId: payload.userId, type: "timeout", active: true }, data: { active: false } });
        } else if (job.type === "warn_member") {
          const user = await client.users.fetch(payload.userId);
          await writeModerationCase(db, guildId, payload.userId, payload.moderatorDiscordId, "warn", payload.reason || "No reason supplied.");
          try { await user.send("You have received a warning in " + guild.name + ". Reason: " + (payload.reason || "No reason supplied.")); } catch {}
        } else if (job.type === "send_dm") {
          const user = await client.users.fetch(payload.userId);
          await user.send({ content: payload.message, allowedMentions: { parse: [] } });
        } else if (job.type === "create_channel") {
          await guild.channels.create({ name: payload.name, type: payload.channelType === "voice" ? ChannelType.GuildVoice : ChannelType.GuildText, topic: payload.topic || undefined });
        } else if (job.type === "delete_channel") {
          const channel = await guild.channels.fetch(payload.channelId);
          if (!channel) throw new Error("Channel not found.");
          await channel.delete("Deleted through OKG Portal");
        } else if (job.type === "create_role") {
          await guild.roles.create({ name: payload.name, color: payload.color || undefined, reason: "Created through OKG Portal" });
        } else if (job.type === "delete_role") {
          const role = await guild.roles.fetch(payload.roleId);
          if (!role || !role.editable) throw new Error("Role not found or not editable by the bot.");
          await role.delete("Deleted through OKG Portal");
        } else if (job.type === "delete_message") {
          const channel = await guild.channels.fetch(payload.channelId);
          if (!channel || !channel.isTextBased() || !("messages" in channel)) throw new Error("Channel does not support message management.");
          const message = await channel.messages.fetch(payload.messageId);
          await message.delete();
        } else if (job.type === "purge_messages") {
          const channel = await guild.channels.fetch(payload.channelId);
          if (!channel || !channel.isTextBased() || !("bulkDelete" in channel)) throw new Error("Channel does not support bulk deletion.");
          const count = Number(payload.count);
          if (!Number.isInteger(count) || count < 2 || count > 100) throw new Error("Purge count must be between 2 and 100.");
          const deleted = await channel.bulkDelete(count, true);
          if (!deleted.size) throw new Error("No recent messages could be deleted. Messages older than 14 days cannot be bulk deleted.");
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
