import NextAuth from "next-auth"
// 引入 CredentialsProvider 是正确的，因为您还有其他认证方式
import CredentialsProvider from "next-auth/providers/credentials"
// 导入 OAuthProvider 模块
import type { OAuthConfig } from "next-auth/providers"

import { DrizzleAdapter } from "@auth/drizzle-adapter"
import { createDb, Db } from "./db"
import { accounts, users, roles, userRoles } from "./schema"
import { eq } from "drizzle-orm"
import { getRequestContext } from "@cloudflare/next-on-pages"
import { Permission, hasPermission, ROLES, Role } from "./permissions"
import { hashPassword, comparePassword } from "@/lib/utils"
import { authSchema } from "@/lib/validation"
import { generateAvatarUrl } from "./avatar"
import { getUserId } from "./apiKey"

const ROLE_DESCRIPTIONS: Record<Role, string> = {
  [ROLES.EMPEROR]: "皇帝（网站所有者）",
  [ROLES.DUKE]: "公爵（超级用户）",
  [ROLES.KNIGHT]: "骑士（高级用户）",
  [ROLES.CIVILIAN]: "平民（普通用户）",
}

// 定义您的自定义 GitHub OAuth 提供者返回的用户资料类型
// 确保这个类型与您的 'https://tuttofattoincasa.eu.org/api/user' 端点返回的 JSON 结构匹配
interface CustomGitHubProfile {
  id: string; // 必须是唯一标识符
  name?: string | null; // 用户名或显示名称
  email?: string | null; // 邮箱地址
  avatar_url?: string | null; // 头像 URL
  username?: string | null; // 如果您的系统中使用 username 字段
  // 根据您的自定义 API 返回的其他字段可以添加到这里
  // 例如：github_id: number;
}

// 定义您的自定义 OAuth 提供者
const CustomGitHubProvider: OAuthConfig<CustomGitHubProfile> = {
  id: "custom-github", // 这是此提供者的唯一 ID。例如，登录按钮上会显示 "Sign in with GitHub (Custom)"
  name: "GitHub (Custom)", // 显示在登录界面上的名称
  type: "oauth", // 指定这是一个 OAuth 提供者
  clientId: process.env.AUTH_GITHUB_ID, // 您的 GitHub OAuth 应用的 Client ID
  clientSecret: process.env.AUTH_GITHUB_SECRET, // 您的 GitHub OAuth 应用的 Client Secret

  // 指定自定义的授权、令牌和用户信息端点
  authorization: "https://tuttofattoincasa.eu.org/oauth/authorize",
  token: "https://tuttofattoincasa.eu.org/oauth/token",
  userinfo: "https://tuttofattoincasa.eu.org/api/user", // 从此端点获取用户资料

  // profile 回调函数用于将从 userinfo 端点获取到的数据映射到 NextAuth.js 的标准用户对象
  profile(profile) {
    // 确保这里的映射逻辑与您的 'https://tuttofattoincasa.eu.org/api/user' 返回的数据结构一致
    return {
      id: profile.id, // 必须是唯一标识符
      name: profile.name || profile.username, // 优先使用 name，如果没有则使用 username
      email: profile.email,
      image: profile.avatar_url, // 如果您的自定义 API 返回 avatar_url
      username: profile.username, // 如果您的用户模式中也有 username 字段
    };
  },

  // 如果您的自定义 OAuth 服务器需要特定的 Scope，您也可以在这里定义
  // 例如：
  // scope: "user:email read:user",
};

const getDefaultRole = async (): Promise<Role> => {
  const defaultRole = await getRequestContext().env.SITE_CONFIG.get("DEFAULT_ROLE")
  return defaultRole === ROLES.KNIGHT ? ROLES.KNIGHT : ROLES.CIVILIAN
}

async function findOrCreateRole(db: Db, roleName: Role) {
  let role = await db.query.roles.findFirst({
    where: eq(roles.name, roleName),
  })

  if (!role) {
    const [newRole] = await db.insert(roles)
      .values({
        name: roleName,
        description: ROLE_DESCRIPTIONS[roleName],
      })
      .returning()
    role = newRole
  }

  return role
}

export async function assignRoleToUser(db: Db, userId: string, roleId: string) {
  await db.delete(userRoles)
    .where(eq(userRoles.userId, userId))

  await db.insert(userRoles)
    .values({
      userId,
      roleId,
    })
}

export async function getUserRole(userId: string) {
  const db = createDb()
  const userRoleRecords = await db.query.userRoles.findMany({
    where: eq(userRoles.userId, userId),
    with: { role: true },
  })
  return userRoleRecords[0].role.name
}

export async function checkPermission(permission: Permission) {
  const userId = await getUserId()

  if (!userId) return false

  const db = createDb()
  const userRoleRecords = await db.query.userRoles.findMany({
    where: eq(userRoles.userId, userId),
    with: { role: true },
  })

  const userRoleNames = userRoleRecords.map(ur => ur.role.name)
  return hasPermission(userRoleNames as Role[], permission)
}

export const {
  handlers: { GET, POST },
  auth,
  signIn,
  signOut
} = NextAuth(() => ({
  secret: process.env.AUTH_SECRET,
  adapter: DrizzleAdapter(createDb(), {
    usersTable: users,
    accountsTable: accounts,
  }),
  providers: [
    CustomGitHubProvider, // <-- 这里使用了您自定义的提供者
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        username: { label: "用户名", type: "text", placeholder: "请输入用户名" },
        password: { label: "密码", type: "password", placeholder: "请输入密码" },
      },
      async authorize(credentials) {
        if (!credentials) {
          throw new Error("请输入用户名和密码")
        }

        const { username, password } = credentials

        try {
          authSchema.parse({ username, password })
          // eslint-disable-next-line @typescript-eslint/no-unused-vars
        } catch (error) {
          throw new Error("输入格式不正确")
        }

        const db = createDb()

        const user = await db.query.users.findFirst({
          where: eq(users.username, username as string),
        })

        if (!user) {
          throw new Error("用户名或密码错误")
        }

        const isValid = await comparePassword(password as string, user.password as string)
        if (!isValid) {
          throw new Error("用户名或密码错误")
        }

        return {
          ...user,
          password: undefined,
        }
      },
    }),
  ],
  events: {
    async signIn({ user }) {
      if (!user.id) return

      try {
        const db = createDb()
        const existingRole = await db.query.userRoles.findFirst({
          where: eq(userRoles.userId, user.id),
        })

        if (existingRole) return

        const defaultRole = await getDefaultRole()
        const role = await findOrCreateRole(db, defaultRole)
        await assignRoleToUser(db, user.id, role.id)
      } catch (error) {
        console.error('Error assigning role:', error)
      }
    },
  },
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.id = user.id
        token.name = user.name || user.username
        token.username = user.username
        token.image = user.image || generateAvatarUrl(token.name as string)
      }
      return token
    },
    async session({ session, token }) {
      if (token && session.user) {
        session.user.id = token.id as string
        session.user.name = token.name as string
        session.user.username = token.username as string
        session.user.image = token.image as string

        const db = createDb()
        let userRoleRecords = await db.query.userRoles.findMany({
          where: eq(userRoles.userId, session.user.id),
          with: { role: true },
        })

        if (!userRoleRecords.length) {
          const defaultRole = await getDefaultRole()
          const role = await findOrCreateRole(db, defaultRole)
          await assignRoleToUser(db, session.user.id, role.id)
          userRoleRecords = [{
            userId: session.user.id,
            roleId: role.id,
            createdAt: new Date(),
            role: role
          }]
        }

        session.user.roles = userRoleRecords.map(ur => ({
          name: ur.role.name,
        }))
      }

      return session
    },
  },
  session: {
    strategy: "jwt",
  },
}))

export async function register(username: string, password: string) {
  const db = createDb()

  const existing = await db.query.users.findFirst({
    where: eq(users.username, username)
  })

  if (existing) {
    throw new Error("用户名已存在")
  }

  const hashedPassword = await hashPassword(password)

  const [user] = await db.insert(users)
    .values({
      username,
      password: hashedPassword,
    })
    .returning()

  return user
}
