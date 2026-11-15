import { PrismaClient, User } from "@prisma/client";

export const PERMISSIONS = [
  "portal:member",
  "applications:view",
  "applications:review",
  "members:view",
  "roles:manage",
  "audit:view",
  "discord:manage"
] as const;

export type PortalPermission = typeof PERMISSIONS[number];

export async function getPermissions(db: PrismaClient, user: User): Promise<Set<string>> {
  if (!user.isGuildMember) return new Set();
  if (user.discordId === process.env.OWNER_DISCORD_USER_ID) return new Set(["*"]);
  const guildId = process.env.DISCORD_GUILD_ID;
  if (!guildId) return new Set();
  const roles = await db.memberRole.findMany({ where: { userId: user.id, guildId }, select: { discordRoleId: true } });
  const roleIds = roles.map(role => role.discordRoleId);
  const mappings = roleIds.length ? await db.roleMapping.findMany({
    where: { guildId, discordRoleId: { in: roleIds } }, select: { permission: true }
  }) : [];
  return new Set(["portal:member", ...mappings.map(mapping => mapping.permission)]);
}

export function hasPermission(permissions: Set<string>, permission: string): boolean {
  return permissions.has("*") || permissions.has(permission);
}