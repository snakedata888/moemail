import { createDb } from "./db"
import { apiKeys } from "./schema"
import { eq, and, gt } from "drizzle-orm"
import type { User } from "next-auth"
import { auth } from "./auth"
import { headers } from "next/headers"

async function getUserByApiKey(key: string): Promise<User | null> {
  const db = createDb()
  const apiKey = await db.query.apiKeys.findFirst({
    where: and(
      eq(apiKeys.key, key),
      eq(apiKeys.enabled, true),
      gt(apiKeys.expiresAt, new Date())
    ),
    with: {
      user: true
    }
  })

  if (!apiKey) return null

  return apiKey.user
}

export interface ApiKeyAuthResult {
  success: true
  userId: string
}

export interface ApiKeyAuthError {
  success: false
  error: string
  status: number
}

export async function handleApiKeyAuth(apiKey: string, pathname: string): Promise<ApiKeyAuthResult | ApiKeyAuthError> {
  if (!pathname.startsWith('/api/emails') && !pathname.startsWith('/api/config')) {
    return { success: false, error: "无权限查看", status: 403 }
  }

  const user = await getUserByApiKey(apiKey)
  if (!user?.id) {
    return { success: false, error: "无效的 API Key", status: 401 }
  }

  return { success: true, userId: user.id }
}

export const getUserId = async () => {
  const headersList = await headers()
  const userId = headersList.get("X-User-Id")
  
  if (userId) return userId

  const session = await auth()

  return session?.user.id
}
