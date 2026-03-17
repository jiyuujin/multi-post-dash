import type { ExecutionContext, KVNamespace, ScheduledEvent } from '@cloudflare/workers-types'
import { Hono } from 'hono'
import { html } from 'hono/html'
import { cors } from 'hono/cors'

type Bindings = {
  POST_QUEUE: KVNamespace
  MULTI_POST_DASH_USER_CONFIGS: KVNamespace
  CF_TEAM_DOMAIN: string
}

const app = new Hono<{ Bindings: Bindings }>()

app.use('/*', cors())

interface CfAccessPayload {
  email: string
  sub: string
  aud: string | string[]
  iat: number
  exp: number
}

async function verifyCfAccessJwt(
  request: Request,
  teamDomain: string,
): Promise<CfAccessPayload | null> {
  const token =
    request.headers.get('Cf-Access-Jwt-Assertion') ?? request.headers.get('cf-access-jwt-assertion')

  if (!token) return null

  const parts = token.split('.')
  if (parts.length !== 3) return null

  const [headerB64, payloadB64, signatureB64] = parts

  let payload: CfAccessPayload
  try {
    payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')))
  } catch {
    return null
  }

  if (payload.exp < Math.floor(Date.now() / 1000)) return null

  const certsUrl = `https://${teamDomain}.cloudflareaccess.com/cdn-cgi/access/certs`
  let jwks: { keys: JsonWebKey[] }
  try {
    const res = await fetch(certsUrl)
    jwks = (await res.json()) as { keys: JsonWebKey[] }
  } catch {
    return null
  }

  let kid: string | undefined
  try {
    const header = JSON.parse(atob(headerB64.replace(/-/g, '+').replace(/_/g, '/')))
    kid = header.kid
  } catch {
    return null
  }

  const jwk = kid ? jwks.keys.find((k: any) => k.kid === kid) : jwks.keys[0]
  if (!jwk) return null

  try {
    const key = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    )
    const encoder = new TextEncoder()
    const data = encoder.encode(`${headerB64}.${payloadB64}`)
    const signature = Uint8Array.from(
      atob(signatureB64.replace(/-/g, '+').replace(/_/g, '/')),
      (c) => c.charCodeAt(0),
    )
    const valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, data)
    if (!valid) return null
  } catch {
    return null
  }

  return payload
}

async function getUser(
  request: Request,
  teamDomain: string,
): Promise<{ email: string; sub: string; domain: string; isGroupMode: boolean } | null> {
  const payload = await verifyCfAccessJwt(request, teamDomain)
  if (!payload) return null
  const domain = payload.email.split('@')[1] ?? ''
  const isGroupMode = domain !== 'gmail.com' && domain !== ''
  return { email: payload.email, sub: payload.sub, domain, isGroupMode }
}

async function getGroupAdmins(domain: string, env: Bindings): Promise<string[]> {
  const raw = await env.MULTI_POST_DASH_USER_CONFIGS.get(`group:${domain}:admins`)
  if (!raw) return []
  return JSON.parse(raw)
}

async function isGroupAdmin(email: string, domain: string, env: Bindings): Promise<boolean> {
  const admins = await getGroupAdmins(domain, env)
  if (admins.length === 0) {
    await env.MULTI_POST_DASH_USER_CONFIGS.put(`group:${domain}:admins`, JSON.stringify([email]))
    return true
  }
  return admins.includes(email)
}

async function generateCodeVerifier(): Promise<string> {
  const array = new Uint8Array(32)
  crypto.getRandomValues(array)
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
}

async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(verifier)
  const digest = await crypto.subtle.digest('SHA-256', data)
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
}

async function getXOAuth2Token(
  userSub: string,
  domain: string,
  isGroupMode: boolean,
  env: Bindings,
): Promise<string | null> {
  const kvKey = isGroupMode ? `group:${domain}:x_oauth2` : `user:${userSub}:x_oauth2`
  const appKey = isGroupMode ? `group:${domain}:x_oauth2_app` : `user:${userSub}:x_oauth2_app`

  const raw = await env.MULTI_POST_DASH_USER_CONFIGS.get(kvKey)
  if (!raw) return null

  const token = JSON.parse(raw) as {
    access_token: string
    refresh_token: string
    expires_at: number
  }

  if (token.expires_at > Date.now() + 5 * 60 * 1000) {
    return token.access_token
  }

  try {
    const appRaw = await env.MULTI_POST_DASH_USER_CONFIGS.get(appKey)
    if (!appRaw) return null
    const { clientId, clientSecret } = JSON.parse(appRaw)

    const res = await fetch('https://api.twitter.com/2/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: token.refresh_token,
      }),
    })

    if (!res.ok) return null

    const newToken = (await res.json()) as any
    const updated = {
      access_token: newToken.access_token,
      refresh_token: newToken.refresh_token ?? token.refresh_token,
      expires_at: Date.now() + (newToken.expires_in ?? 7200) * 1000,
    }
    await env.MULTI_POST_DASH_USER_CONFIGS.put(kvKey, JSON.stringify(updated))
    return updated.access_token
  } catch {
    return null
  }
}

async function incrementXPostCount(userSub: string, env: Bindings): Promise<number> {
  const now = new Date(Date.now() + 9 * 60 * 60 * 1000)
  const yyyymm = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`
  const key = `user:${userSub}:x_post_count:${yyyymm}`

  const raw = await env.MULTI_POST_DASH_USER_CONFIGS.get(key)
  const next = (raw ? parseInt(raw) : 0) + 1
  await env.MULTI_POST_DASH_USER_CONFIGS.put(key, String(next))
  return next
}

app.get('/', (c) => {
  return c.html(html`
    <!DOCTYPE html>
    <html lang="ja">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Multi Post Dash</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>
          @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap');
          body {
            font-family: 'Inter', sans-serif;
            background-color: #f8fafc;
          }
          .glass {
            background: rgba(255, 255, 255, 0.9);
            backdrop-filter: blur(10px);
          }
        </style>
      </head>
      <body class="min-h-screen flex items-center justify-center p-4">
        <div class="max-w-lg w-full glass rounded-[2.5rem] shadow-2xl p-8 border border-white">
          <header class="flex justify-between items-center mb-8">
            <h1 class="text-2xl font-extrabold tracking-tight text-slate-900">Post Dash</h1>
            <div class="flex items-center gap-3">
              <div id="userBadge" class="hidden items-center gap-2">
                <span
                  id="userEmail"
                  class="text-xs font-bold text-slate-500 bg-slate-100 px-2 py-1 rounded-full"
                ></span>
                <span
                  id="userModeBadge"
                  class="text-[10px] font-bold bg-green-50 px-2 py-1 rounded-full text-green-500"
                  >✓ Workspace</span
                >
              </div>
              <button
                onclick="toggleSettings()"
                class="text-slate-400 hover:text-slate-600 transition-colors"
              >
                ⚙️
              </button>
            </div>
          </header>

          <div
            id="settings"
            class="hidden space-y-4 mb-6 p-6 bg-slate-50 rounded-3xl border border-slate-200 text-sm"
          >
            <div
              id="workspaceNotice"
              class="hidden p-3 bg-blue-50 border border-blue-200 rounded-2xl text-blue-700 text-xs font-semibold"
            >
              🏢 Google Workspace
              アカウントで認証中です。設定を保存するとサーバー側にも自動保存されます。
            </div>
            <div
              id="groupNotice"
              class="hidden p-3 bg-purple-50 border border-purple-200 rounded-2xl text-purple-700 text-xs font-semibold"
            ></div>

            <div class="pb-4 border-b border-slate-200">
              <h3 class="font-bold mb-3 text-slate-700">デフォルトで投稿するプラットフォーム</h3>
              <div class="grid grid-cols-2 gap-2">
                <label
                  class="flex items-center gap-2 cursor-pointer p-2 rounded-xl hover:bg-slate-100"
                >
                  <input type="checkbox" id="default-x" class="w-4 h-4 rounded accent-slate-900" />
                  <span class="font-semibold text-slate-600">𝕏 X</span>
                </label>
                <label
                  class="flex items-center gap-2 cursor-pointer p-2 rounded-xl hover:bg-slate-100"
                >
                  <input
                    type="checkbox"
                    id="default-bsky"
                    class="w-4 h-4 rounded accent-blue-500"
                  />
                  <span class="font-semibold text-slate-600">🦋 Bluesky</span>
                </label>
                <label
                  class="flex items-center gap-2 cursor-pointer p-2 rounded-xl hover:bg-slate-100"
                >
                  <input
                    type="checkbox"
                    id="default-threads"
                    class="w-4 h-4 rounded accent-purple-500"
                  />
                  <span class="font-semibold text-slate-600">🧵 Threads</span>
                </label>
                <label
                  class="flex items-center gap-2 cursor-pointer p-2 rounded-xl hover:bg-slate-100"
                >
                  <input
                    type="checkbox"
                    id="default-mastodon"
                    class="w-4 h-4 rounded accent-orange-400"
                  />
                  <span class="font-semibold text-slate-600">🐘 Mastodon</span>
                </label>
              </div>
            </div>

            <h3 class="font-bold border-b pb-2 mb-2 text-slate-700">API Credentials</h3>
            <div
              id="readonlyNotice"
              class="hidden p-3 bg-amber-50 border border-amber-200 rounded-2xl text-amber-700 text-xs font-semibold mb-2"
            >
              🔒 認証情報はグループ管理者のみ変更できます
            </div>
            <div class="space-y-2">
              <p class="font-semibold text-slate-500">𝕏 (Twitter)</p>

              <div id="xOAuth2Area" class="hidden p-3 bg-slate-100 rounded-xl space-y-2">
                <div class="flex items-center justify-between">
                  <span class="text-xs font-bold text-slate-600">OAuth 2.0 + PKCE</span>
                  <span id="xOAuth2Status" class="text-[10px] font-bold text-slate-400"
                    >未認証</span
                  >
                </div>
                <input
                  type="text"
                  id="xClientId"
                  class="w-full p-2 border rounded-lg text-xs"
                  placeholder="Client ID"
                />
                <input
                  type="password"
                  id="xClientSecret"
                  class="w-full p-2 border rounded-lg text-xs"
                  placeholder="Client Secret"
                />
                <p class="text-[10px] text-slate-400 px-1">
                  コールバック URL（X Developer Portal に登録）:
                  <span
                    id="xCallbackUrlDisplay"
                    class="font-mono text-slate-500 break-all select-all"
                  ></span>
                </p>
                <div class="flex gap-2">
                  <button
                    onclick="connectXOAuth2()"
                    id="xOAuth2ConnectBtn"
                    class="flex-1 py-2 text-xs font-bold bg-slate-900 text-white rounded-lg hover:bg-slate-700 transition-colors"
                  >
                    X で認証する
                  </button>
                  <button
                    onclick="disconnectXOAuth2()"
                    id="xOAuth2DisconnectBtn"
                    class="hidden py-2 px-3 text-xs font-bold text-red-400 border border-red-200 rounded-lg hover:bg-red-50 transition-colors"
                  >
                    解除
                  </button>
                </div>
                <p class="text-[10px] text-slate-400">
                  認証済みの場合、OAuth 2.0 が OAuth 1.0a より優先されます
                </p>
              </div>

              <details id="xOAuth1Details">
                <summary
                  class="text-xs font-bold text-slate-400 cursor-pointer hover:text-slate-600 select-none py-1"
                >
                  OAuth 1.0a キー入力 ▸
                </summary>
                <div class="space-y-2 mt-2">
                  <input
                    type="password"
                    id="xKey"
                    class="w-full p-2 border rounded-lg"
                    placeholder="API Key"
                  />
                  <input
                    type="password"
                    id="xSecret"
                    class="w-full p-2 border rounded-lg"
                    placeholder="API Secret"
                  />
                  <input
                    type="password"
                    id="xToken"
                    class="w-full p-2 border rounded-lg"
                    placeholder="Access Token"
                  />
                  <input
                    type="password"
                    id="xTokenSecret"
                    class="w-full p-2 border rounded-lg"
                    placeholder="Access Token Secret"
                  />
                </div>
              </details>
            </div>
            <div class="space-y-2 mt-4">
              <p class="font-semibold text-slate-500">🦋 Bluesky</p>
              <input
                type="text"
                id="bskyHandle"
                class="w-full p-2 border rounded-lg"
                placeholder="handle.bsky.social"
              />
              <input
                type="password"
                id="bskyPass"
                class="w-full p-2 border rounded-lg"
                placeholder="App Password"
              />
            </div>
            <div class="space-y-2 mt-4">
              <p class="font-semibold text-slate-500">🧵 Threads</p>
              <input
                type="text"
                id="threadsUserId"
                class="w-full p-2 border rounded-lg"
                placeholder="Threads User ID"
              />
              <input
                type="password"
                id="threadsToken"
                class="w-full p-2 border rounded-lg"
                placeholder="Access Token"
              />
            </div>
            <div class="space-y-2 mt-4 border-t pt-2">
              <p class="font-semibold text-slate-500">🐘 Mastodon</p>
              <input
                type="text"
                id="mastoInstance"
                class="w-full p-2 border rounded-lg mb-2"
                placeholder="https://fedibird.com"
              />
              <input
                type="password"
                id="mastoToken"
                class="w-full p-2 border rounded-lg"
                placeholder="Access Token"
              />
            </div>

            <div id="adminManageArea" class="hidden mt-4 border-t pt-4 space-y-2">
              <h3 class="font-bold text-slate-700">グループ管理者</h3>
              <div id="adminList" class="space-y-1"></div>
              <div class="flex gap-2 mt-2">
                <input
                  type="email"
                  id="newAdminEmail"
                  class="flex-1 p-2 border rounded-lg text-xs"
                  placeholder="追加するメールアドレス"
                />
                <button
                  onclick="addAdmin()"
                  class="py-2 px-3 text-xs font-bold bg-purple-600 text-white rounded-lg hover:bg-purple-700"
                >
                  追加
                </button>
              </div>
            </div>

            <button
              id="saveSettingsBtn"
              onclick="saveSettings()"
              class="w-full bg-slate-900 text-white p-3 rounded-xl font-bold mt-4"
            >
              設定を保存
            </button>
          </div>

          <div class="grid grid-cols-4 gap-2 mb-6 text-[10px]">
            <div class="flex flex-col items-center gap-1">
              <button
                onclick="togglePlatform('x')"
                id="card-x"
                class="platform-card w-full border-2 border-transparent bg-slate-100 p-3 rounded-2xl flex flex-col items-center text-slate-400 opacity-50"
              >
                <span class="text-xl">𝕏</span><span class="text-[10px] font-bold">X</span>
              </button>
              <div id="xPostCountBadge" class="hidden text-center w-full">
                <span id="xPostCountText" class="text-[9px] font-bold text-slate-400"></span>
                <div class="w-full bg-slate-200 rounded-full h-1 mt-0.5">
                  <div
                    id="xPostCountBar"
                    class="bg-slate-400 h-1 rounded-full transition-all"
                    style="width:0%"
                  ></div>
                </div>
              </div>
            </div>
            <button
              onclick="togglePlatform('bsky')"
              id="card-bsky"
              class="platform-card border-2 border-transparent bg-slate-100 p-3 rounded-2xl flex flex-col items-center text-slate-400 opacity-50"
            >
              <span class="text-xl">🦋</span><span class="text-[10px] font-bold">Bluesky</span>
            </button>
            <button
              onclick="togglePlatform('threads')"
              id="card-threads"
              class="platform-card border-2 border-transparent bg-slate-100 p-3 rounded-2xl flex flex-col items-center text-slate-400 opacity-50"
            >
              <span class="text-xl">🧵</span><span class="text-[10px] font-bold">Threads</span>
            </button>
            <button
              onclick="togglePlatform('mastodon')"
              id="card-mastodon"
              class="platform-card border-2 border-transparent bg-slate-100 p-2 rounded-2xl flex flex-col items-center text-slate-400 opacity-50"
            >
              <span class="text-xl">🐘</span><span class="font-bold">Mastodon</span>
            </button>
          </div>

          <div class="relative mb-6">
            <textarea
              id="mainText"
              placeholder="何を伝えますか？"
              class="w-full h-44 p-6 rounded-[2rem] bg-slate-50 border-none focus:ring-4 focus:ring-blue-100 text-lg resize-none transition-all"
              oninput="updateUI()"
            ></textarea>
            <div
              id="counter"
              class="absolute bottom-5 right-6 text-xs font-mono font-bold text-slate-400"
            >
              0 / 500
            </div>
          </div>

          <div class="mb-6 p-4 bg-slate-50 rounded-2xl border border-slate-100">
            <label class="block text-[10px] font-bold uppercase text-slate-400 mb-2 px-2"
              >配信予約（オプション）</label
            >
            <div class="flex gap-2 px-2">
              <input
                type="date"
                id="scheduleDate"
                class="flex-1 bg-white border border-slate-200 rounded-xl px-3 py-2 text-slate-700 font-semibold focus:outline-none focus:ring-2 focus:ring-blue-100 cursor-pointer text-sm"
              />
              <select
                id="scheduleTime"
                class="bg-white border border-slate-200 rounded-xl px-3 py-2 text-slate-700 font-semibold focus:outline-none focus:ring-2 focus:ring-blue-100 cursor-pointer text-sm"
              >
                <option value="">--:--</option>
              </select>
            </div>
          </div>

          <div class="grid grid-cols-2 gap-3">
            <button
              id="postBtn"
              onclick="sendPost(false)"
              class="bg-blue-600 hover:bg-blue-700 text-white py-4 rounded-2xl font-bold text-sm shadow-lg shadow-blue-200 transition-all disabled:opacity-30"
            >
              今すぐ投稿
            </button>
            <div class="relative group">
              <button
                id="scheduleBtn"
                onclick="sendPost(true)"
                class="w-full bg-slate-800 hover:bg-slate-900 text-white py-4 rounded-2xl font-bold text-sm shadow-lg shadow-slate-200 transition-all disabled:opacity-30 disabled:cursor-not-allowed"
              >
                予約する
              </button>
              <div
                id="scheduleBtnTooltip"
                class="hidden absolute bottom-full mb-2 left-1/2 -translate-x-1/2 w-48 text-center text-[10px] bg-slate-800 text-white px-3 py-2 rounded-xl shadow-lg pointer-events-none"
              >
                予約投稿は Workspace ログイン時のみ利用できます
              </div>
            </div>
          </div>

          <div class="mt-10">
            <div class="flex justify-between items-center mb-4 px-2">
              <h3 class="text-sm font-extrabold text-slate-500 uppercase tracking-widest">
                予約済みの投稿
              </h3>
              <button
                onclick="fetchQueue()"
                class="text-xs text-blue-600 font-bold hover:underline"
              >
                更新 ↻
              </button>
            </div>

            <div id="queueList" class="space-y-3">
              <p
                class="text-center py-8 text-slate-400 text-sm italic bg-slate-50/50 rounded-3xl border-2 border-dashed border-slate-100"
              >
                予約された投稿はありません
              </p>
            </div>
          </div>
        </div>

        <script>
          let platforms = []
          const limits = { x: 140, bsky: 300, threads: 500, mastodon: 500 }
          const platformColors = {
            x: 'slate-900',
            bsky: 'blue-500',
            threads: 'purple-500',
            mastodon: 'orange-400',
          }
          const platformBgs = {
            x: 'slate-50',
            bsky: 'blue-50',
            threads: 'purple-50',
            mastodon: 'orange-50',
          }
          let currentUser = null

          window.onload = async () => {
            await checkLogin()
            updateScheduleBtn()
            fetchQueue()
          }

          async function checkLogin() {
            try {
              const res = await fetch('/api/me')
              if (!res.ok) {
                loadDefaultsFromLocalStorage()
                return
              }
              const data = await res.json()
              if (data.email) {
                currentUser = data
                showUserBadge(data)
                await loadConfig()
                await checkXOAuth2Status()
                await fetchXPostCount()
                if (data.isGroupMode) await loadAdminUI()
              }
            } catch (e) {
              loadDefaultsFromLocalStorage()
            }
          }

          function showUserBadge(user) {
            document.getElementById('userBadge').classList.remove('hidden')
            document.getElementById('userBadge').classList.add('flex')
            document.getElementById('userEmail').innerText = user.email
            const badge = document.getElementById('userModeBadge')
            if (user.isGroupMode) {
              badge.textContent = \`✓ \${user.domain}\`
              badge.className =
                'text-[10px] font-bold bg-purple-50 px-2 py-1 rounded-full text-purple-500'
              document.getElementById('workspaceNotice').classList.add('hidden')
              const groupNotice = document.getElementById('groupNotice')
              groupNotice.classList.remove('hidden')
              groupNotice.textContent = \`🏢 グループモード: \${user.domain} の設定を共有しています\`
            } else {
              badge.textContent = '✓ Workspace'
              badge.className =
                'text-[10px] font-bold bg-green-50 px-2 py-1 rounded-full text-green-500'
              document.getElementById('workspaceNotice').classList.remove('hidden')
            }
          }

          async function loadConfig() {
            try {
              const endpoint = currentUser.isGroupMode ? '/api/group-config' : '/api/user-config'
              const res = await fetch(endpoint)
              if (!res.ok) {
                loadDefaultsFromLocalStorage()
                return
              }
              const config = await res.json()
              if (!config) {
                loadDefaultsFromLocalStorage()
                return
              }

              const fields = [
                'xKey',
                'xSecret',
                'xToken',
                'xTokenSecret',
                'bskyHandle',
                'bskyPass',
                'threadsUserId',
                'threadsToken',
                'mastoInstance',
                'mastoToken',
              ]
              fields.forEach((f) => {
                const el = document.getElementById(f)
                if (el && config[f]) el.value = config[f]
              })
              const defaultPlatforms =
                config.defaultPlatforms ??
                JSON.parse(localStorage.getItem('post_dash_v3') || '{}').defaultPlatforms ??
                []
              applyPlatformDefaults(defaultPlatforms)

              if (currentUser.isGroupMode && !currentUser.isAdmin) {
                setCredentialsReadonly(true)
              }
            } catch (e) {
              console.error('Config load error:', e)
              loadDefaultsFromLocalStorage()
            }
          }

          function setCredentialsReadonly(readonly) {
            const fields = [
              'xKey',
              'xSecret',
              'xToken',
              'xTokenSecret',
              'bskyHandle',
              'bskyPass',
              'threadsUserId',
              'threadsToken',
              'mastoInstance',
              'mastoToken',
              'xClientId',
              'xClientSecret',
            ]
            fields.forEach((f) => {
              const el = document.getElementById(f)
              if (el) el.readOnly = readonly
            })
            document.getElementById('readonlyNotice').classList.toggle('hidden', !readonly)
            document.getElementById('saveSettingsBtn').disabled = readonly
            if (readonly) {
              document.getElementById('xOAuth2ConnectBtn')?.classList.add('hidden')
              document.getElementById('xOAuth2DisconnectBtn')?.classList.add('hidden')
            }
          }

          async function loadAdminUI() {
            try {
              const res = await fetch('/api/group-admins')
              if (!res.ok) return
              const { admins, isAdmin } = await res.json()
              currentUser.isAdmin = isAdmin

              if (isAdmin) {
                document.getElementById('adminManageArea').classList.remove('hidden')
                renderAdminList(admins)
              }
            } catch (e) {}
          }

          function renderAdminList(admins) {
            const container = document.getElementById('adminList')
            container.innerHTML = admins
              .map(
                (email) =>
                  \`<div class="flex justify-between items-center p-2 bg-white rounded-lg border border-slate-100 text-xs">
                <span class="text-slate-600">\${email}</span>
                <button onclick="removeAdmin('\${email}')" class="text-red-400 hover:text-red-600 font-bold">削除</button>
              </div>\`,
              )
              .join('')
          }

          async function addAdmin() {
            const email = document.getElementById('newAdminEmail').value.trim()
            if (!email) return
            try {
              const res = await fetch('/api/group-admins', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email }),
              })
              if (res.ok) {
                document.getElementById('newAdminEmail').value = ''
                await loadAdminUI()
              } else {
                alert('追加に失敗しました')
              }
            } catch (e) {
              alert('エラーが発生しました')
            }
          }

          async function removeAdmin(email) {
            if (!confirm(\`\${email} を管理者から削除しますか？\`)) return
            try {
              await fetch(\`/api/group-admins/\${encodeURIComponent(email)}\`, { method: 'DELETE' })
              await loadAdminUI()
            } catch (e) {
              alert('削除に失敗しました')
            }
          }

          async function fetchXPostCount() {
            if (!currentUser) return
            try {
              const res = await fetch('/api/x-post-count')
              if (!res.ok) return
              const { count, limit } = await res.json()
              const badge = document.getElementById('xPostCountBadge')
              const text = document.getElementById('xPostCountText')
              const bar = document.getElementById('xPostCountBar')
              badge.classList.remove('hidden')
              text.textContent = \`今月 \${count} / \${limit} 件\`
              const pct = Math.min((count / limit) * 100, 100)
              bar.style.width = pct + '%'
              bar.className =
                'h-1 rounded-full transition-all ' +
                (pct >= 80 ? 'bg-red-400' : pct >= 50 ? 'bg-yellow-400' : 'bg-slate-400')
            } catch (e) {}
          }

          function loadDefaultsFromLocalStorage() {
            const saved = JSON.parse(localStorage.getItem('post_dash_v3') || '{}')
            applyPlatformDefaults(saved.defaultPlatforms ?? [])
          }

          function applyPlatformDefaults(defaultPlatforms) {
            platforms = []
            ;['x', 'bsky', 'threads', 'mastodon'].forEach((p) => setCardOff(p))
            defaultPlatforms.forEach((p) => {
              platforms.push(p)
              setCardOn(p)
            })
            ;['x', 'bsky', 'threads', 'mastodon'].forEach((p) => {
              const cb = document.getElementById('default-' + p)
              if (cb) cb.checked = defaultPlatforms.includes(p)
            })
            updateUI()
          }

          function setCardOn(p) {
            const el = document.getElementById('card-' + p)
            if (el)
              el.className = \`platform-card w-full border-2 border-\${platformColors[p]} bg-\${platformBgs[p]} p-3 rounded-2xl flex flex-col items-center\`
          }

          function setCardOff(p) {
            const el = document.getElementById('card-' + p)
            if (el)
              el.className =
                'platform-card w-full border-2 border-transparent bg-slate-100 p-3 rounded-2xl flex flex-col items-center text-slate-400 opacity-50'
          }

          function updateScheduleBtn() {
            const btn = document.getElementById('scheduleBtn')
            const tooltip = document.getElementById('scheduleBtnTooltip')
            if (!currentUser) {
              btn.disabled = true
              btn.parentElement.addEventListener('mouseenter', () =>
                tooltip.classList.remove('hidden'),
              )
              btn.parentElement.addEventListener('mouseleave', () =>
                tooltip.classList.add('hidden'),
              )
            } else {
              btn.disabled = false
            }
          }

          async function checkXOAuth2Status() {
            if (!currentUser) return
            document.getElementById('xOAuth2Area').classList.remove('hidden')

            document.getElementById('xCallbackUrlDisplay').textContent =
              window.location.origin + '/auth/x/callback'

            try {
              const res = await fetch('/auth/x/app-config')
              if (res.ok) {
                const { clientId, clientSecret } = await res.json()
                if (clientId) document.getElementById('xClientId').value = clientId
                if (clientSecret) document.getElementById('xClientSecret').value = clientSecret
              }
            } catch (e) {}

            try {
              const res = await fetch('/auth/x/status')
              if (!res.ok) return
              const { connected } = await res.json()
              if (connected) {
                document.getElementById('xOAuth2Status').textContent = '✓ 認証済み'
                document.getElementById('xOAuth2Status').className =
                  'text-[10px] font-bold text-green-500'
                document.getElementById('xOAuth2ConnectBtn').classList.add('hidden')
                document.getElementById('xOAuth2DisconnectBtn').classList.remove('hidden')
              } else {
                document.getElementById('xOAuth2Status').textContent = '未認証'
                document.getElementById('xOAuth2Status').className =
                  'text-[10px] font-bold text-slate-400'
                document.getElementById('xOAuth2ConnectBtn').classList.remove('hidden')
                document.getElementById('xOAuth2DisconnectBtn').classList.add('hidden')
              }
            } catch (e) {}
          }

          async function connectXOAuth2() {
            const clientId = document.getElementById('xClientId').value.trim()
            const clientSecret = document.getElementById('xClientSecret').value.trim()
            if (!clientId || !clientSecret) {
              alert('Client ID と Client Secret を入力してください')
              return
            }
            try {
              await fetch('/auth/x/app-config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ clientId, clientSecret }),
              })
              window.location.href = '/auth/x/login'
            } catch (e) {
              alert('保存に失敗しました')
            }
          }

          async function disconnectXOAuth2() {
            if (!confirm('X の OAuth 2.0 連携を解除しますか？')) return
            try {
              await fetch('/auth/x/token', { method: 'DELETE' })
              await checkXOAuth2Status()
            } catch (e) {
              alert('解除に失敗しました')
            }
          }

          async function saveSettings() {
            const defaultPlatforms = ['x', 'bsky', 'threads', 'mastodon'].filter(
              (p) => document.getElementById('default-' + p).checked,
            )

            const config = {
              xKey: document.getElementById('xKey').value,
              xSecret: document.getElementById('xSecret').value,
              xToken: document.getElementById('xToken').value,
              xTokenSecret: document.getElementById('xTokenSecret').value,
              bskyHandle: document.getElementById('bskyHandle').value,
              bskyPass: document.getElementById('bskyPass').value,
              threadsUserId: document.getElementById('threadsUserId').value,
              threadsToken: document.getElementById('threadsToken').value,
              mastoInstance: document.getElementById('mastoInstance').value,
              mastoToken: document.getElementById('mastoToken').value,
              defaultPlatforms,
            }

            localStorage.setItem('post_dash_v3', JSON.stringify(config))

            applyPlatformDefaults(defaultPlatforms)

            if (currentUser) {
              const endpoint = currentUser.isGroupMode ? '/api/group-config' : '/api/user-config'
              try {
                const res = await fetch(endpoint, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify(config),
                })
                alert(
                  res.ok
                    ? currentUser.isGroupMode
                      ? \`\${currentUser.domain} グループに保存しました！\`
                      : 'Workspace アカウントに保存しました！'
                    : 'LocalStorage に保存しました（サーバー保存に失敗）',
                )
              } catch (e) {
                alert('LocalStorage に保存しました（サーバー保存に失敗）')
              }
            } else {
              alert('Saved! (LocalStorage)')
            }

            toggleSettings()
          }

          function togglePlatform(p) {
            if (platforms.includes(p)) {
              platforms = platforms.filter((i) => i !== p)
              setCardOff(p)
            } else {
              platforms.push(p)
              setCardOn(p)
            }
            updateUI()
          }

          function updateUI() {
            const text = document.getElementById('mainText').value
            const activeLimits = platforms.length > 0 ? platforms.map((p) => limits[p]) : [500]
            const minLimit = Math.min(...activeLimits)
            document.getElementById('counter').innerText = \`\${text.length} / \${minLimit}\`
            document.getElementById('postBtn').disabled =
              text.length === 0 || text.length > minLimit || platforms.length === 0
          }

          function toggleSettings() {
            document.getElementById('settings').classList.toggle('hidden')
          }

          function buildTimeOptions() {
            const sel = document.getElementById('scheduleTime')
            for (let h = 0; h < 24; h++) {
              for (let m of [0, 30]) {
                const hh = String(h).padStart(2, '0')
                const mm = String(m).padStart(2, '0')
                const opt = document.createElement('option')
                opt.value = \`\${hh}:\${mm}\`
                opt.textContent = \`\${hh}:\${mm}\`
                sel.appendChild(opt)
              }
            }
          }
          buildTimeOptions()

          async function sendPost(isSchedule) {
            const text = document.getElementById('mainText').value
            const scheduleDate = document.getElementById('scheduleDate').value
            const scheduleTime = document.getElementById('scheduleTime').value

            let scheduledAtValue = null
            if (scheduleDate && scheduleTime) {
              scheduledAtValue = \`\${scheduleDate}T\${scheduleTime}:00+09:00\`
            }

            const config = {
              xKey: document.getElementById('xKey').value,
              xSecret: document.getElementById('xSecret').value,
              xToken: document.getElementById('xToken').value,
              xTokenSecret: document.getElementById('xTokenSecret').value,
              bskyHandle: document.getElementById('bskyHandle').value,
              bskyPass: document.getElementById('bskyPass').value,
              threadsUserId: document.getElementById('threadsUserId').value,
              threadsToken: document.getElementById('threadsToken').value,
              mastoInstance: document.getElementById('mastoInstance').value,
              mastoToken: document.getElementById('mastoToken').value,
            }

            if (isSchedule) {
              if (!scheduleDate || !scheduleTime) {
                alert('予約日時を選択してください')
                return
              }
              const dateCheck = new Date(scheduledAtValue)
              if (isNaN(dateCheck.getTime())) {
                alert('予約日時の形式が正しくありません')
                return
              }
              if (dateCheck <= new Date()) {
                alert('予約日時は現在より未来を選択してください')
                return
              }
            }

            const btn = isSchedule
              ? document.getElementById('scheduleBtn')
              : document.getElementById('postBtn')
            const originalText = btn.innerText

            btn.disabled = true
            btn.innerText = isSchedule ? '予約中...' : '配信中...'

            try {
              const endpoint = isSchedule ? '/api/schedule' : '/api/post'

              const res = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  text,
                  platforms,
                  config,
                  scheduledAt: isSchedule
                    ? new Date(new Date(scheduledAtValue).getTime() - 5 * 60 * 1000).toISOString()
                    : null,
                }),
              })

              if (res.ok) {
                alert(isSchedule ? '予約が完了しました！' : '配信完了！')
                document.getElementById('mainText').value = ''
                document.getElementById('scheduleDate').value = ''
                document.getElementById('scheduleTime').value = ''
                updateUI()
                fetchQueue()
                if (!isSchedule && platforms.includes('x')) await fetchXPostCount()
              } else {
                alert('エラーが発生しました')
              }
            } catch (e) {
              alert('Error: ' + e)
            } finally {
              btn.disabled = false
              btn.innerText = originalText
            }
          }

          async function fetchQueue() {
            var container = document.getElementById('queueList')

            try {
              var res = await fetch('/api/queue')
              var data = await res.json()

              if (!data || data.length === 0) {
                container.innerHTML =
                  '<p class="text-center py-8 text-slate-400 text-sm italic bg-slate-50/50 rounded-3xl border-2 border-dashed border-slate-100">予約された投稿はありません</p>'
                return
              }

              var htmlContent = ''
              for (var i = 0; i < data.length; i++) {
                var item = data[i]

                var badges = ''
                for (var j = 0; j < item.platforms.length; j++) {
                  badges +=
                    '<span class="text-[10px] bg-slate-200 px-1.5 py-0.5 rounded uppercase font-bold text-slate-600 mr-1">' +
                    item.platforms[j] +
                    '</span>'
                }

                var dateStr = new Date(item.scheduledAt).toLocaleString('ja-JP', {
                  month: 'short',
                  day: 'numeric',
                  hour: '2-digit',
                  minute: '2-digit',
                })

                htmlContent +=
                  '<div class="glass bg-white/50 p-4 rounded-2xl border border-slate-100 shadow-sm mb-3">' +
                  '<div class="flex justify-between items-start mb-2"><div class="flex gap-1">' +
                  badges +
                  '</div>' +
                  '<span class="text-[10px] font-mono font-bold text-blue-500 bg-blue-50 px-2 py-0.5 rounded-full">' +
                  dateStr +
                  '</span></div>' +
                  '<p class="text-sm text-slate-600 line-clamp-2 mb-3 px-1">' +
                  item.text +
                  '</p>' +
                  '<button onclick="deletePost(\\'' +
                  item.id +
                  '\\')" class="w-full py-1.5 text-[10px] font-bold text-red-400 hover:text-red-600 hover:bg-red-50 rounded-lg transition-colors border border-red-50">予約を取り消す</button>' +
                  '</div>'
              }
              container.innerHTML = htmlContent
            } catch (e) {
              console.error('Queue fetch error:', e)
              container.innerHTML =
                '<p class="text-center py-4 text-red-400 text-xs">読み込みに失敗しました</p>'
            }
          }

          async function deletePost(id) {
            if (!confirm('この予約を削除しますか？')) return

            try {
              await fetch(\`/api/queue/\${id}\`, { method: 'DELETE' })
              fetchQueue() // リストを再読み込み
            } catch (e) {
              alert('削除に失敗しました')
            }
          }
        </script>
      </body>
    </html>
  `)
})

app.get('/api/me', async (c) => {
  const user = await getUser(c.req.raw, c.env.CF_TEAM_DOMAIN)
  if (!user) return c.json({ error: 'Not authenticated via Cloudflare Access' }, 401)
  let isAdmin = false
  if (user.isGroupMode) {
    isAdmin = await isGroupAdmin(user.email, user.domain, c.env)
  }
  return c.json({
    email: user.email,
    sub: user.sub,
    domain: user.domain,
    isGroupMode: user.isGroupMode,
    isAdmin,
  })
})

app.get('/api/user-config', async (c) => {
  const user = await getUser(c.req.raw, c.env.CF_TEAM_DOMAIN)
  if (!user) return c.json({ error: 'Unauthorized' }, 401)
  const raw = await c.env.MULTI_POST_DASH_USER_CONFIGS.get(`user:${user.sub}:config`)
  if (!raw) return c.json(null)
  return c.json(JSON.parse(raw))
})

app.post('/api/user-config', async (c) => {
  const user = await getUser(c.req.raw, c.env.CF_TEAM_DOMAIN)
  if (!user) return c.json({ error: 'Unauthorized' }, 401)
  const config = await c.req.json()
  await c.env.MULTI_POST_DASH_USER_CONFIGS.put(`user:${user.sub}:config`, JSON.stringify(config))
  return c.json({ success: true })
})

app.get('/api/group-config', async (c) => {
  const user = await getUser(c.req.raw, c.env.CF_TEAM_DOMAIN)
  if (!user || !user.isGroupMode) return c.json({ error: 'Unauthorized' }, 401)
  const raw = await c.env.MULTI_POST_DASH_USER_CONFIGS.get(`group:${user.domain}:config`)
  if (!raw) return c.json(null)
  return c.json(JSON.parse(raw))
})

app.post('/api/group-config', async (c) => {
  const user = await getUser(c.req.raw, c.env.CF_TEAM_DOMAIN)
  if (!user || !user.isGroupMode) return c.json({ error: 'Unauthorized' }, 401)
  const admin = await isGroupAdmin(user.email, user.domain, c.env)
  if (!admin) return c.json({ error: 'Forbidden: admin only' }, 403)
  const config = await c.req.json()
  await c.env.MULTI_POST_DASH_USER_CONFIGS.put(
    `group:${user.domain}:config`,
    JSON.stringify(config),
  )
  return c.json({ success: true })
})

app.get('/api/group-admins', async (c) => {
  const user = await getUser(c.req.raw, c.env.CF_TEAM_DOMAIN)
  if (!user || !user.isGroupMode) return c.json({ error: 'Unauthorized' }, 401)
  const admins = await getGroupAdmins(user.domain, c.env)
  const isAdmin = admins.includes(user.email)
  return c.json({ admins, isAdmin })
})

app.post('/api/group-admins', async (c) => {
  const user = await getUser(c.req.raw, c.env.CF_TEAM_DOMAIN)
  if (!user || !user.isGroupMode) return c.json({ error: 'Unauthorized' }, 401)
  const admin = await isGroupAdmin(user.email, user.domain, c.env)
  if (!admin) return c.json({ error: 'Forbidden: admin only' }, 403)
  const { email } = await c.req.json()
  if (!email.endsWith(`@${user.domain}`)) return c.json({ error: `Must be @${user.domain}` }, 400)
  const admins = await getGroupAdmins(user.domain, c.env)
  if (!admins.includes(email)) {
    admins.push(email)
    await c.env.MULTI_POST_DASH_USER_CONFIGS.put(
      `group:${user.domain}:admins`,
      JSON.stringify(admins),
    )
  }
  return c.json({ success: true })
})

app.delete('/api/group-admins/:email', async (c) => {
  const user = await getUser(c.req.raw, c.env.CF_TEAM_DOMAIN)
  if (!user || !user.isGroupMode) return c.json({ error: 'Unauthorized' }, 401)
  const admin = await isGroupAdmin(user.email, user.domain, c.env)
  if (!admin) return c.json({ error: 'Forbidden: admin only' }, 403)
  const targetEmail = decodeURIComponent(c.req.param('email'))
  const admins = await getGroupAdmins(user.domain, c.env)
  if (admins.length <= 1) return c.json({ error: '最後の管理者は削除できません' }, 400)
  const updated = admins.filter((e: string) => e !== targetEmail)
  await c.env.MULTI_POST_DASH_USER_CONFIGS.put(
    `group:${user.domain}:admins`,
    JSON.stringify(updated),
  )
  return c.json({ success: true })
})

app.get('/api/x-post-count', async (c) => {
  const user = await getUser(c.req.raw, c.env.CF_TEAM_DOMAIN)
  if (!user) return c.json({ error: 'Unauthorized' }, 401)
  const now = new Date(Date.now() + 9 * 60 * 60 * 1000) // JST
  const yyyymm = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`
  const raw = await c.env.MULTI_POST_DASH_USER_CONFIGS.get(
    `user:${user.sub}:x_post_count:${yyyymm}`,
  )
  return c.json({ count: raw ? parseInt(raw) : 0, limit: 500, yearMonth: yyyymm })
})

async function executePost(data: any) {
  // const { text, platforms, config } = await c.req.json()
  const { text, platforms, config } = data
  const results: any = {}

  // 1. X (Twitter)
  if (platforms.includes('x')) {
    try {
      const xUrl = 'https://api.twitter.com/2/tweets'
      let xAuthHeader: string

      // OAuth 2.0 トークンが KV にあれば優先、なければ 1.0a にフォールバック
      const oauth2Token =
        data.userSub && data.env
          ? await getXOAuth2Token(
              data.userSub,
              data.domain ?? '',
              data.isGroupMode ?? false,
              data.env,
            )
          : null

      if (oauth2Token) {
        // --- OAuth 2.0 Bearer ---
        xAuthHeader = `Bearer ${oauth2Token}`
      } else {
        // --- OAuth 1.0a HMAC-SHA1 ---
        const escape = (s: string) =>
          encodeURIComponent(s).replace(
            /[!'()*]/g,
            (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
          )
        const oauth_params: any = {
          oauth_consumer_key: config.xKey,
          oauth_nonce: Math.random().toString(36).substring(2),
          oauth_signature_method: 'HMAC-SHA1',
          oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
          oauth_token: config.xToken,
          oauth_version: '1.0',
        }
        const paramsString = Object.keys(oauth_params)
          .sort()
          .map((k) => `${escape(k)}=${escape(oauth_params[k])}`)
          .join('&')
        const signatureBase = `POST&${escape(xUrl)}&${escape(paramsString)}`
        const signingKey = `${escape(config.xSecret)}&${escape(config.xTokenSecret)}`
        const key = await crypto.subtle.importKey(
          'raw',
          new TextEncoder().encode(signingKey),
          { name: 'HMAC', hash: 'SHA-1' },
          false,
          ['sign'],
        )
        const signature = await crypto.subtle.sign(
          'HMAC',
          key,
          new TextEncoder().encode(signatureBase),
        )
        oauth_params.oauth_signature = btoa(String.fromCharCode(...new Uint8Array(signature)))
        xAuthHeader =
          'OAuth ' +
          Object.keys(oauth_params)
            .map((k) => `${escape(k)}="${escape(oauth_params[k])}"`)
            .join(', ')
      }

      const xRes = await fetch(xUrl, {
        method: 'POST',
        headers: { Authorization: xAuthHeader, 'Content-Type': 'application/json' },
        body: JSON.stringify({ text }),
      })

      if (xRes.ok) {
        results.x = 'success'
        if (data.userSub && data.env) {
          await incrementXPostCount(data.userSub, data.env)
        }
      } else {
        const errText = await xRes.text()
        console.error(`X API error [${xRes.status}]:`, errText)
        try {
          const err = JSON.parse(errText) as any
          results.x = `error: ${err.detail || err.title || err.errors?.[0]?.message || xRes.status}`
        } catch {
          results.x = `error: ${xRes.status} ${errText.slice(0, 100)}`
        }
      }
    } catch (e: any) {
      results.x = `error: ${e.message}`
    }
  }

  // 2. Bluesky
  if (platforms.includes('bsky')) {
    try {
      const PDS = 'https://bsky.social/xrpc'

      const loginRes = await fetch(`${PDS}/com.atproto.server.createSession`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identifier: config.bskyHandle,
          password: config.bskyPass,
        }),
      })
      const session = (await loginRes.json()) as any

      if (!loginRes.ok) throw new Error(session.message || 'Login failed')

      const postRes = await fetch(`${PDS}/com.atproto.repo.createRecord`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.accessJwt}`,
        },
        body: JSON.stringify({
          repo: session.did,
          collection: 'app.bsky.feed.post',
          record: {
            text: text,
            createdAt: new Date().toISOString(),
            $type: 'app.bsky.feed.post',
          },
        }),
      })

      if (postRes.ok) {
        results.bsky = 'success'
      } else {
        const err = (await postRes.json()) as any
        results.bsky = `error: ${err.message}`
      }
    } catch (e: any) {
      console.error('Bsky Error:', e)
      results.bsky = `error: ${e.message}`
    }
  }

  // 3. Threads
  if (platforms.includes('threads')) {
    try {
      const containerRes = await fetch(
        `https://graph.threads.net/v1.0/${config.threadsUserId}/threads`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            media_type: 'TEXT',
            text: text,
            access_token: config.threadsToken,
          }),
        },
      )

      const containerData: any = await containerRes.json()

      if (!containerData.id) {
        throw new Error(containerData.error?.message || 'Failed to create container')
      }

      const publishRes = await fetch(
        `https://graph.threads.net/v1.0/${config.threadsUserId}/threads_publish`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            creation_id: containerData.id,
            access_token: config.threadsToken,
          }),
        },
      )

      if (publishRes.ok) {
        results.threads = 'success'
      } else {
        const errorData: any = await publishRes.json()
        results.threads = `error: ${errorData.error?.message}`
      }
    } catch (e: any) {
      results.threads = `error: ${e.message}`
    }
  }

  // 4. Mastodon
  if (platforms.includes('mastodon')) {
    try {
      const instanceUrl = config.mastoInstance.replace(/\/$/, '') // 末尾の / を削除
      const res = await fetch(`${instanceUrl}/api/v1/statuses`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${config.mastoToken}`,
        },
        body: JSON.stringify({ status: text }),
      })

      if (res.ok) {
        results.mastodon = 'success'
      } else {
        const err = await res.json()
        results.mastodon = `error: ${err.error}`
      }
    } catch (e: any) {
      results.mastodon = `error: ${e.message}`
    }
  }

  //   return c.json(results)
  return results
  // })
}

app.get('/auth/x/login', async (c) => {
  const user = await getUser(c.req.raw, c.env.CF_TEAM_DOMAIN)
  if (!user) return c.json({ error: 'Unauthorized' }, 401)

  if (user.isGroupMode) {
    const admin = await isGroupAdmin(user.email, user.domain, c.env)
    if (!admin) return c.json({ error: 'Forbidden: admin only' }, 403)
  }

  const appKey = user.isGroupMode
    ? `group:${user.domain}:x_oauth2_app`
    : `user:${user.sub}:x_oauth2_app`
  const appRaw = await c.env.MULTI_POST_DASH_USER_CONFIGS.get(appKey)
  if (!appRaw) {
    return c.html(
      '<p>X の Client ID が設定されていません。<a href="/">戻る</a></p>',
    )
  }

  const { clientId } = JSON.parse(appRaw)

  const codeVerifier = await generateCodeVerifier()
  const codeChallenge = await generateCodeChallenge(codeVerifier)
  const state = crypto.randomUUID()

  const callbackUrl = `${new URL(c.req.url).origin}/auth/x/callback`

  await c.env.MULTI_POST_DASH_USER_CONFIGS.put(
    `pkce:${state}`,
    JSON.stringify({
      codeVerifier,
      userSub: user.sub,
      domain: user.domain,
      isGroupMode: user.isGroupMode,
      callbackUrl,
    }),
    { expirationTtl: 600 },
  )

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: callbackUrl,
    scope: 'tweet.read tweet.write users.read offline.access',
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  })

  return c.redirect(`https://twitter.com/i/oauth2/authorize?${params}`)
})

app.get('/auth/x/callback', async (c) => {
  const code = c.req.query('code')
  const state = c.req.query('state')
  const error = c.req.query('error')

  if (error || !code || !state) {
    return c.html('<p>認証がキャンセルされました。<a href="/">戻る</a></p>')
  }

  const pkceRaw = await c.env.MULTI_POST_DASH_USER_CONFIGS.get(`pkce:${state}`)
  if (!pkceRaw) return c.html('<p>セッションが期限切れです。<a href="/">戻る</a></p>')

  const { codeVerifier, userSub, domain, isGroupMode, callbackUrl } = JSON.parse(pkceRaw)
  await c.env.MULTI_POST_DASH_USER_CONFIGS.delete(`pkce:${state}`)

  const appKey = isGroupMode ? `group:${domain}:x_oauth2_app` : `user:${userSub}:x_oauth2_app`
  const appRaw = await c.env.MULTI_POST_DASH_USER_CONFIGS.get(appKey)
  if (!appRaw) return c.html('<p>アプリ設定が見つかりません。<a href="/">戻る</a></p>')
  const { clientId, clientSecret } = JSON.parse(appRaw)

  const tokenRes = await fetch('https://api.twitter.com/2/oauth2/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: callbackUrl,
      code_verifier: codeVerifier,
    }),
  })

  if (!tokenRes.ok) {
    const err = await tokenRes.text()
    return c.html(`<p>トークン取得に失敗しました: ${err} <a href="/">戻る</a></p>`)
  }

  const tokenData = (await tokenRes.json()) as any
  const stored = {
    access_token: tokenData.access_token,
    refresh_token: tokenData.refresh_token,
    expires_at: Date.now() + (tokenData.expires_in ?? 7200) * 1000,
  }
  const tokenKey = isGroupMode ? `group:${domain}:x_oauth2` : `user:${userSub}:x_oauth2`

  await c.env.MULTI_POST_DASH_USER_CONFIGS.put(tokenKey, JSON.stringify(stored))

  return c.html(`
    <html><head><meta http-equiv="refresh" content="0;url=/" /></head>
    <body><p>X 認証が完了しました。リダイレクト中...</p></body></html>
  `)
})

app.get('/auth/x/status', async (c) => {
  const user = await getUser(c.req.raw, c.env.CF_TEAM_DOMAIN)
  if (!user) return c.json({ error: 'Unauthorized' }, 401)
  const kvKey = user.isGroupMode ? `group:${user.domain}:x_oauth2` : `user:${user.sub}:x_oauth2`
  const raw = await c.env.MULTI_POST_DASH_USER_CONFIGS.get(kvKey)
  return c.json({ connected: !!raw })
})

app.get('/auth/x/app-config', async (c) => {
  const user = await getUser(c.req.raw, c.env.CF_TEAM_DOMAIN)
  if (!user) return c.json({ error: 'Unauthorized' }, 401)
  const kvKey = user.isGroupMode
    ? `group:${user.domain}:x_oauth2_app`
    : `user:${user.sub}:x_oauth2_app`
  const raw = await c.env.MULTI_POST_DASH_USER_CONFIGS.get(kvKey)
  if (!raw) return c.json({ clientId: null, clientSecret: null })
  return c.json(JSON.parse(raw))
})

app.post('/auth/x/app-config', async (c) => {
  const user = await getUser(c.req.raw, c.env.CF_TEAM_DOMAIN)
  if (!user) return c.json({ error: 'Unauthorized' }, 401)
  if (user.isGroupMode) {
    const admin = await isGroupAdmin(user.email, user.domain, c.env)
    if (!admin) return c.json({ error: 'Forbidden: admin only' }, 403)
  }
  const { clientId, clientSecret } = await c.req.json()
  const kvKey = user.isGroupMode
    ? `group:${user.domain}:x_oauth2_app`
    : `user:${user.sub}:x_oauth2_app`
  await c.env.MULTI_POST_DASH_USER_CONFIGS.put(kvKey, JSON.stringify({ clientId, clientSecret }))
  return c.json({ success: true })
})

app.delete('/auth/x/token', async (c) => {
  const user = await getUser(c.req.raw, c.env.CF_TEAM_DOMAIN)
  if (!user) return c.json({ error: 'Unauthorized' }, 401)
  if (user.isGroupMode) {
    const admin = await isGroupAdmin(user.email, user.domain, c.env)
    if (!admin) return c.json({ error: 'Forbidden: admin only' }, 403)
  }
  const kvKey = user.isGroupMode ? `group:${user.domain}:x_oauth2` : `user:${user.sub}:x_oauth2`
  await c.env.MULTI_POST_DASH_USER_CONFIGS.delete(kvKey)
  return c.json({ success: true })
})

app.post('/api/post', async (c) => {
  const user = await getUser(c.req.raw, c.env.CF_TEAM_DOMAIN)
  const data = await c.req.json()
  const results = await executePost({
    ...data,
    userSub: user?.sub ?? null,
    domain: user?.domain ?? '',
    isGroupMode: user?.isGroupMode ?? false,
    env: c.env,
  })
  return c.json(results)
})

app.post('/api/schedule', async (c) => {
  const user = await getUser(c.req.raw, c.env.CF_TEAM_DOMAIN)
  if (!user) return c.json({ error: 'Unauthorized' }, 401)
  const { text, platforms, scheduledAt } = await c.req.json()
  const id = crypto.randomUUID()
  const ts = new Date(scheduledAt).getTime()
  const payload = {
    id,
    text,
    platforms,
    userSub: user.sub,
    domain: user.domain,
    isGroupMode: user.isGroupMode,
    scheduledAt: ts,
  }
  const queueKey = user.isGroupMode
    ? `queue:group:${user.domain}:${ts}:${id}`
    : `queue:user:${user.sub}:${ts}:${id}`
  await c.env.POST_QUEUE.put(queueKey, JSON.stringify(payload))
  return c.json({ success: true })
})

app.get('/api/queue', async (c) => {
  const user = await getUser(c.req.raw, c.env.CF_TEAM_DOMAIN)
  if (!user) return c.json({ error: 'Unauthorized' }, 401)
  const prefix = user.isGroupMode ? `queue:group:${user.domain}:` : `queue:user:${user.sub}:`
  const list = await c.env.POST_QUEUE.list({ prefix })
  const items = await Promise.all(
    list.keys.map(async (k: { name: string }) =>
      JSON.parse((await c.env.POST_QUEUE.get(k.name)) || 'null'),
    ),
  )
  return c.json(
    items
      .filter((i: unknown) => i)
      .sort(
        (a: { scheduledAt: number }, b: { scheduledAt: number }) => a.scheduledAt - b.scheduledAt,
      ),
  )
})

app.delete('/api/queue/:id', async (c) => {
  const user = await getUser(c.req.raw, c.env.CF_TEAM_DOMAIN)
  if (!user) return c.json({ error: 'Unauthorized' }, 401)
  const id = c.req.param('id')
  const prefix = user.isGroupMode ? `queue:group:${user.domain}:` : `queue:user:${user.sub}:`
  const list = await c.env.POST_QUEUE.list({ prefix })
  const target = list.keys.find((k: { name: string }) => k.name.endsWith(id))
  if (target) await c.env.POST_QUEUE.delete(target.name)
  return c.json({ success: !!target })
})

// serve({
//   fetch: app.fetch,
//   port: 3000,
// })

export default {
  fetch: app.fetch,
  async scheduled(event: ScheduledEvent, env: Bindings, ctx: ExecutionContext) {
    const now = Date.now()
    const list = await env.POST_QUEUE.list({ prefix: 'queue:' })
    for (const key of list.keys) {
      const timestamp = parseInt(key.name.split(':')[3])
      if (timestamp <= now) {
        const val = await env.POST_QUEUE.get(key.name)
        if (val) {
          const payload = JSON.parse(val)
          const configKey = payload.isGroupMode
            ? `group:${payload.domain}:config`
            : `user:${payload.userSub}:config`
          const configRaw = await env.MULTI_POST_DASH_USER_CONFIGS.get(configKey)
          if (!configRaw) {
            console.error('Config not found:', configKey)
            continue
          }
          await executePost({
            text: payload.text,
            platforms: payload.platforms,
            config: JSON.parse(configRaw),
            userSub: payload.userSub,
            domain: payload.domain ?? '',
            isGroupMode: payload.isGroupMode ?? false,
            env,
          })
          await env.POST_QUEUE.delete(key.name)
        }
      }
    }
  },
}
