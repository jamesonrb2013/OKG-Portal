import { PrismaClient, User } from "@prisma/client";

export const PERMISSIONS = [
  "portal:member",
  "applications:view", "applications:review",
  "members:view", "roles:manage", "audit:view",
  "staff:access", "staff:tasks", "staff:reports",
  "events:manage", "giveaways:manage", "announcements:manage",
  "executive:access", "executive:manage"
] as const;
export type PortalPermission = typeof PERMISSIONS[number];

export async function getPermissions(db: PrismaClient, user: User): Promise<Set<string>> {
  if (!user.isGuildMember) return new Set();
  if (user.discordId === process.env.OWNER_DISCORD_USER_ID || user.isOwner) return new Set(["*"]);
  const guildId = process.env.DISCORD_GUILD_ID;
  if (!guildId) return new Set(["portal:member"]);
  const roles = await db.memberRole.findMany({ where: { userId: user.id, guildId }, select: { discordRoleId: true } });
  const roleIds = roles.map(r => r.discordRoleId);
  const mappings = roleIds.length ? await db.roleMapping.findMany({
    where: { guildId, discordRoleId: { in: roleIds } }, select: { permission: true }
  }) : [];
  const permissions = new Set(["portal:member", ...mappings.map(m => m.permission)]);
  if (permissions.has("applications:review")) permissions.add("applications:view");
  return permissions;
}
export function hasPermission(permissions: Set<string>, permission: string): boolean {
  return permissions.has("*") || permissions.has(permission);
}
export function isStaff(permissions: Set<string>): boolean {
  return permissions.has("*") || ["staff:access","staff:tasks","staff:reports","applications:review"].some(p => permissions.has(p));
}
export function isExecutive(permissions: Set<string>): boolean {
  return permissions.has("*") || permissions.has("executive:access") || permissions.has("executive:manage");
}