import NextAuth from "next-auth";
import GitHub from "next-auth/providers/github";
import { DrizzleAdapter } from "@auth/drizzle-adapter";
import { createDb, Db } from "./db";
import { accounts, users, roles, userRoles } from "./schema";
import { eq } from "drizzle-orm";
import { getRequestContext } from "@cloudflare/next-on-pages";
import { Permission, hasPermission, ROLES, Role } from "./permissions";
import CredentialsProvider from "next-auth/providers/credentials";
import { hashPassword, comparePassword } from "@/lib/utils";
import { authSchema } from "@/lib/validation";
import { generateAvatarUrl } from "./avatar";
import { Account } from "next-auth"; // 导入 Account 类型

const ROLE_DESCRIPTIONS: Record<Role, string> = {
  [ROLES.EMPEROR]: "皇帝（网站所有者）",
  [ROLES.DUKE]: "公爵（超级用户）",
  [ROLES.KNIGHT]: "骑士（高级用户）",
  [ROLES.CIVILIAN]: "平民（普通用户）",
};

const getDefaultRole = async (): Promise<Role> => {
  // 确保 getRequestContext().env.SITE_CONFIG 存在，否则提供默认值或抛出错误
  const siteConfig = getRequestContext().env.SITE_CONFIG;
  if (!siteConfig) {
    console.warn("SITE_CONFIG not found in Cloudflare Pages environment. Defaulting to CIVILIAN role.");
    return ROLES.CIVILIAN;
  }
  const defaultRole = await siteConfig.get("DEFAULT_ROLE");
  return defaultRole === ROLES.KNIGHT ? ROLES.KNIGHT : ROLES.CIVILIAN;
};

async function findOrCreateRole(db: Db, roleName: Role) {
  let role = await db.query.roles.findFirst({
    where: eq(roles.name, roleName),
  });

  if (!role) {
    const [newRole] = await db.insert(roles)
      .values({
        name: roleName,
        description: ROLE_DESCRIPTIONS[roleName],
      })
      .returning();
    role = newRole;
  }

  return role;
}

export async function assignRoleToUser(db: Db, userId: string, roleId: string) {
  await db.delete(userRoles)
    .where(eq(userRoles.userId, userId));

  await db.insert(userRoles)
    .values({
      userId,
      roleId,
    });
}

export async function getUserRole(userId: string) {
  const db = createDb();
  const userRoleRecords = await db.query.userRoles.findMany({
    where: eq(userRoles.userId, userId),
    with: { role: true },
  });
  // 确保有结果再访问 [0]，防止 undefined 错误
  return userRoleRecords.length > 0 ? userRoleRecords[0].role.name : ROLES.CIVILIAN; // 提供一个默认角色以防万一
}

export async function checkPermission(permission: Permission) {
  const session = await auth();
  if (!session?.user?.id) return false;

  const db = createDb();
  const userRoleRecords = await db.query.userRoles.findMany({
    where: eq(userRoles.userId, session.user.id),
    with: { role: true },
  });

  const userRoleNames = userRoleRecords.map(ur => ur.role.name);
  // 确保 hasPermission 函数能处理空数组或者正确的角色类型
  return hasPermission(userRoleNames as Role[], permission);
}

export const {
  handlers: { GET, POST },
  auth,
  signIn,
  signOut,
} = NextAuth(() => ({
  // ✨ 确保 AUTH_SECRET 已设置，这是解决 Configuration 错误的关键之一
  secret: process.env.AUTH_SECRET, 
  adapter: DrizzleAdapter(createDb(), {
    usersTable: users,
    accountsTable: accounts,
  }),
  providers: [
    GitHub({
      // ✨ 确保 AUTH_GITHUB_ID 和 AUTH_GITHUB_SECRET 已设置
      clientId: process.env.AUTH_GITHUB_ID,
      clientSecret: process.env.AUTH_GITHUB_SECRET,
      // 修改授权端点以匹配您的自定义授权服务器
      authorization: {
        url: "https://tuttofattoincasa.eu.org/oauth/authorize",
        params: {
          // 您希望发送给授权服务器的参数
          response_type: "code",
          scope: "user.read", // 根据您的授权服务器要求设置
          // NextAuth.js 可能会自动添加 PKCE 参数 (code_challenge, code_challenge_method)
          // 和一些 OIDC 相关的 scope (openid, profile, email)。
          // 如果您的服务器严格不兼容这些，可能需要进一步定制，但这会降低安全性。
          // 通常，建议您的授权服务器支持 OIDC 和 PKCE。
        },
      },
      token: "https://tuttofattoincasa.eu.org/oauth/token",
      userinfo: {
        url: "https://tuttofattoincasa.eu.org/api/user",
        // ✨ 修正 client 的类型，确保 tokens 和 client 都被正确解构和类型化
        async request({ tokens, client }: { tokens: Account; client: any }) {
          // 这里是获取用户信息的请求
          const profile = await client.userinfo(tokens.access_token);
          // ✨ 转换用户信息的格式以匹配 NextAuth.js 的 User 接口
          return {
            id: profile.id.toString(), // id 必须是字符串
            name: profile.nickname || profile.username, // 使用 nickname 或 username 作为 name
            email: profile.email,
            image: profile.avatar_url,
            username: profile.username, // 将 username 也加入到返回中，用于 jwt 和 session 回调
          };
        },
      },
    }),
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        username: { label: "用户名", type: "text", placeholder: "请输入用户名" },
        password: { label: "密码", type: "password", placeholder: "请输入密码" },
      },
      async authorize(credentials) {
        if (!credentials) {
          throw new Error("请输入用户名和密码");
        }

        const { username, password } = credentials;

        try {
          authSchema.parse({ username, password });
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        } catch (error) {
          throw new Error("输入格式不正确");
        }

        const db = createDb();

        const user = await db.query.users.findFirst({
          where: eq(users.username, username as string),
        });

        if (!user) {
          throw new Error("用户名或密码错误");
        }

        const isValid = await comparePassword(password as string, user.password as string);
        if (!isValid) {
          throw new Error("用户名或密码错误");
        }

        return {
          ...user,
          password: undefined, // 永远不要返回密码
        };
      },
    }),
  ],
  events: {
    async signIn({ user }) {
      if (!user.id) return;

      try {
        const db = createDb();
        const existingRole = await db.query.userRoles.findFirst({
          where: eq(userRoles.userId, user.id),
        });

        if (existingRole) return;

        const defaultRole = await getDefaultRole();
        const role = await findOrCreateRole(db, defaultRole);
        await assignRoleToUser(db, user.id, role.id);
      } catch (error) {
        console.error('Error assigning role during signIn:', error);
      }
    },
  },
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        // user 对象是 Provider 返回的，现在应该包含 username 字段
        token.id = user.id;
        token.name = user.name || user.username; // 优先使用 name，否则使用 username
        token.username = user.username; // 确保 username 传递到 token
        token.image = user.image || generateAvatarUrl(token.name as string);
      }
      return token;
    },
    async session({ session, token }) {
      if (token && session.user) {
        session.user.id = token.id as string;
        session.user.name = token.name as string;
        session.user.username = token.username as string; // 从 token 传递 username 到 session
        session.user.image = token.image as string;

        const db = createDb();
        let userRoleRecords = await db.query.userRoles.findMany({
          where: eq(userRoles.userId, session.user.id),
          with: { role: true },
        });

        // 如果用户没有角色（可能是第一次登录或数据库同步问题），分配默认角色
        if (!userRoleRecords.length) {
          console.warn(`User ${session.user.id} has no assigned roles. Assigning default role.`);
          const defaultRole = await getDefaultRole();
          const role = await findOrCreateRole(db, defaultRole);
          await assignRoleToUser(db, session.user.id, role.id);
          userRoleRecords = [{
            userId: session.user.id,
            roleId: role.id,
            createdAt: new Date(),
            role: role,
          }];
        }

        session.user.roles = userRoleRecords.map(ur => ({
          name: ur.role.name,
        }));
      }

      return session;
    },
  },
  session: {
    strategy: "jwt",
  },
}));

// 注册函数
export async function register(username: string, password: string) {
  const db = createDb();

  const existing = await db.query.users.findFirst({
    where: eq(users.username, username),
  });

  if (existing) {
    throw new Error("用户名已存在");
  }

  const hashedPassword = await hashPassword(password);

  const [user] = await db.insert(users)
    .values({
      username,
      password: hashedPassword,
    })
    .returning();

  return user;
}
