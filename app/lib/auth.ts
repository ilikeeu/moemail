import NextAuth from "next-auth"
// 引入内置的 GitHub Provider
import GitHub from "next-auth/providers/github"
import CredentialsProvider from "next-auth/providers/credentials"
// 不再需要 OAuthConfig 类型，因为我们使用内置的 GitHub 提供者并利用其特定配置

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
    GitHub({
      clientId: process.env.AUTH_GITHUB_ID,
      clientSecret: process.env.AUTH_GITHUB_SECRET,
      // 使用 `authorization`, `token`, `userinfo` 对象来指定您的自定义端点
      // 这允许您使用 GitHub Provider 的 ID (`github`) 并指向自定义 OAuth 服务器
      authorization: { url: 'https://tuttofattoincasa.eu.org/oauth/authorize' },
      token: { url: 'https://tuttofattoincasa.eu.org/oauth/token' },
      userinfo: { url: 'https://tuttofattoincasa.eu.org/api/user' },
      // 如果您的自定义 OAuth 服务器需要 'openid profile email' 这些特定的 Scope，
      // 可以在此添加。NextAuth.js 的 GitHub Provider 默认 Scope 为 'read:user' 和 'user:email'。
      // scope: "openid profile email",
    }),
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
  // --- 关键改动：指定自定义登录页面路径 ---
  pages: {
    signIn: "/login", // NextAuth.js 将重定向到您的 app/login/page.tsx
    // 您可以根据需要添加其他自定义页面
    // signOut: '/auth/signout',
    // error: '/auth/error',
    // verifyRequest: '/auth/verify-request',
    // newUser: '/auth/new-user'
  },
  // --- 结束关键改动 ---
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
