import { Client, GatewayIntentBits, Events, GuildMember, REST, Routes } from "discord.js";
import { PrismaClient } from "@prisma/client";

let activeClient: Client | null = null;
let startedAt: Date | null = null;

export async function syncMember(db: PrismaClient, member: GuildMember) {
 const guildId=process.env.DISCORD_GUILD_ID;
 if(!guildId||member.guild.id!==guildId)return;
 const user=await db.user.findUnique({where:{discordId:member.id}});
 if(!user)return;
 const roleIds=[...member.roles.cache.keys()].filter(id=>id!==member.guild.id);
 await db.$transaction([
  db.user.update({where:{id:user.id},data:{isGuildMember:true}}),
  db.memberRole.deleteMany({where:{userId:user.id,guildId}}),
  ...(roleIds.length?[db.memberRole.createMany({data:roleIds.map(discordRoleId=>({userId:user.id,guildId,discordRoleId})),skipDuplicates:true})]:[])
 ]);
 await db.auditEvent.create({data:{actorId:user.id,action:"discord.roles.synced",subject:member.id,details:{roleCount:roleIds.length}}});
}

export function getDiscordStatus(){
 return {configured:Boolean(process.env.DISCORD_BOT_TOKEN&&process.env.DISCORD_GUILD_ID),online:Boolean(activeClient?.isReady()),username:activeClient?.user?.tag||null,guildId:process.env.DISCORD_GUILD_ID||null,ping:activeClient?.ws.ping??null,uptimeSeconds:startedAt?Math.floor((Date.now()-startedAt.getTime())/1000):null,commandsRegistered:false};
}
export async function getDiscordSnapshot(){
 if(!activeClient?.isReady()||!process.env.DISCORD_GUILD_ID)return null;
 const guild=await activeClient.guilds.fetch(process.env.DISCORD_GUILD_ID);
 const [channels,roles]=await Promise.all([guild.channels.fetch(),guild.roles.fetch()]);
 return {id:guild.id,name:guild.name,memberCount:guild.memberCount,icon:guild.iconURL({size:128}),channels:channels.filter(Boolean).map(c=>({id:c!.id,name:c!.name,type:c!.type,parentId:"parentId" in c!?c!.parentId:null})),roles:roles.filter(r=>r.id!==guild.id).map(r=>({id:r.id,name:r.name,color:r.hexColor,position:r.position,managed:r.managed,editable:r.editable}))};
}

export async function startDiscordGateway(db: PrismaClient){
 const guildId=process.env.DISCORD_GUILD_ID;
 if(!process.env.DISCORD_BOT_TOKEN||!guildId){console.warn("Discord role sync is not configured.");return;}
 if(activeClient?.isReady())return;
 const client=new Client({intents:[GatewayIntentBits.Guilds,GatewayIntentBits.GuildMembers]});
 activeClient=client;
 client.on(Events.Error,error=>console.error("Discord gateway error:",error));
 client.on(Events.GuildMemberUpdate,async(_before,after)=>{try{await syncMember(db,after);}catch(error){console.error("Discord role update sync failed:",error);}});
 client.on(Events.GuildMemberAdd,async member=>{try{await syncMember(db,member);}catch(error){console.error("Discord join sync failed:",error);}});
 client.on(Events.GuildMemberRemove,async member=>{try{const user=await db.user.findUnique({where:{discordId:member.id}});if(user)await db.$transaction([db.memberRole.deleteMany({where:{userId:user.id,guildId:member.guild.id}}),db.user.update({where:{id:user.id},data:{isGuildMember:false}})]);}catch(error){console.error("Discord member removal sync failed:",error);}});
 client.once(Events.ClientReady,async ready=>{startedAt=new Date();console.log("OKG Portal role-sync gateway connected as "+ready.user.tag+". No slash commands or Discord action worker are enabled.");if(process.env.DISCORD_CLIENT_ID){try{const rest=new REST({version:"10"}).setToken(process.env.DISCORD_BOT_TOKEN!);await rest.put(Routes.applicationGuildCommands(process.env.DISCORD_CLIENT_ID,guildId),{body:[]});console.log("Removed legacy OKG Portal slash commands; OKG Manager remains the bot administration system.");}catch(error){console.error("Could not clear legacy portal slash commands:",error);}}});
 try{await client.login(process.env.DISCORD_BOT_TOKEN);}catch(error){activeClient=null;try{client.destroy();}catch{}throw error;}
}
