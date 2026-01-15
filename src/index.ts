import { Hono } from 'hono'
import { html } from 'hono/html'
import { cors } from 'hono/cors'
import { AtpAgent } from '@atproto/api'
import { TwitterApi } from 'twitter-api-v2'
import { serve } from '@hono/node-server'

const app = new Hono()

app.use('/*', cors())

// --- フロントエンド: HTML / CSS / JavaScript ---
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
            <button
              onclick="toggleSettings()"
              class="text-slate-400 hover:text-slate-600 transition-colors"
            >
              ⚙️
            </button>
          </header>

          <div
            id="settings"
            class="hidden space-y-4 mb-6 p-6 bg-slate-50 rounded-3xl border border-slate-200 text-sm"
          >
            <h3 class="font-bold border-b pb-2 mb-2 text-slate-700">API Credentials</h3>
            <div class="space-y-2">
              <p class="font-semibold text-slate-500">𝕏 (Twitter)</p>
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
            <button
              onclick="saveSettings()"
              class="w-full bg-slate-900 text-white p-3 rounded-xl font-bold mt-4"
            >
              設定をブラウザに保存
            </button>
          </div>

          <div class="grid grid-cols-4 gap-2 mb-6 text-[10px]">
            <button
              onclick="togglePlatform('x')"
              id="card-x"
              class="platform-card active border-2 border-slate-900 bg-slate-50 p-3 rounded-2xl flex flex-col items-center"
            >
              <span class="text-xl">𝕏</span><span class="text-[10px] font-bold">X</span>
            </button>
            <button
              onclick="togglePlatform('bsky')"
              id="card-bsky"
              class="platform-card active border-2 border-blue-500 bg-blue-50 p-3 rounded-2xl flex flex-col items-center"
            >
              <span class="text-xl">🦋</span><span class="text-[10px] font-bold">Bluesky</span>
            </button>
            <button
              onclick="togglePlatform('threads')"
              id="card-threads"
              class="platform-card active border-2 border-purple-500 bg-purple-50 p-3 rounded-2xl flex flex-col items-center"
            >
              <span class="text-xl">🧵</span><span class="text-[10px] font-bold">Threads</span>
            </button>
            <button
              onclick="togglePlatform('mastodon')"
              id="card-mastodon"
              class="platform-card active border-2 border-orange-400 bg-orange-50 p-2 rounded-2xl flex flex-col items-center"
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
              0 / 140
            </div>
          </div>

          <button
            id="postBtn"
            onclick="sendPost()"
            class="w-full bg-blue-600 hover:bg-blue-700 text-white py-5 rounded-[1.5rem] font-extrabold text-xl shadow-xl shadow-blue-200 transition-all disabled:opacity-30 disabled:shadow-none"
          >
            投稿を配信する
          </button>
        </div>

        <script>
          let platforms = ['x', 'bsky', 'threads']
          const limits = { x: 140, bsky: 300, threads: 500, mastodon: 500 }

          function togglePlatform(p) {
            const el = document.getElementById('card-' + p)
            if (platforms.includes(p)) {
              platforms = platforms.filter((i) => i !== p)
              el.className =
                'platform-card border-2 border-transparent bg-slate-100 p-3 rounded-2xl flex flex-col items-center text-slate-400 opacity-50'
            } else {
              platforms.push(p)
              const colors = { x: 'slate-900', bsky: 'blue-500', threads: 'purple-500' }
              const bgs = { x: 'slate-50', bsky: 'blue-50', threads: 'purple-50' }
              el.className = \`platform-card border-2 border-\${colors[p]} bg-\${bgs[p]} p-3 rounded-2xl flex flex-col items-center\`
            }
            updateUI()
          }

          function updateUI() {
            const text = document.getElementById('mainText').value
            const minLimit = Math.min(...platforms.map((p) => limits[p]))
            document.getElementById('counter').innerText = \`\${text.length} / \${minLimit}\`
            document.getElementById('postBtn').disabled =
              text.length === 0 || text.length > minLimit
          }

          function toggleSettings() {
            document.getElementById('settings').classList.toggle('hidden')
          }

          function saveSettings() {
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
            localStorage.setItem('post_dash_v3', JSON.stringify(config))
            alert('Saved!')
            toggleSettings()
          }

          async function sendPost() {
            const text = document.getElementById('mainText').value
            const config = JSON.parse(localStorage.getItem('post_dash_v3'))
            const btn = document.getElementById('postBtn')

            btn.disabled = true
            btn.innerText = '配信中...'

            try {
              const res = await fetch('/api/post', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ text, platforms, config }),
              })
              const result = await res.json()
              alert('配信完了！')
              document.getElementById('mainText').value = ''
              updateUI()
            } catch (e) {
              alert('Error: ' + e)
            } finally {
              btn.disabled = false
              btn.innerText = '投稿を配信する'
            }
          }
        </script>
      </body>
    </html>
  `)
})

// --- バックエンド: API ロジック ---
app.post('/api/post', async (c) => {
  const { text, platforms, config } = await c.req.json()
  const results: any = {}

  // 1. X (Twitter)
  if (platforms.includes('x')) {
    try {
      const x = new TwitterApi({
        appKey: config.xKey,
        appSecret: config.xSecret,
        accessToken: config.xToken,
        accessSecret: config.xTokenSecret,
      })
      await x.v2.tweet(text)
      results.x = 'success'
    } catch (e) {
      results.x = 'error'
    }
  }

  // 2. Bluesky
  if (platforms.includes('bsky')) {
    try {
      const agent = new AtpAgent({ service: 'https://bsky.social' })
      await agent.login({
        identifier: config.bskyHandle,
        password: config.bskyPass,
      })
      await agent.login({ identifier: config.bskyHandle, password: config.bskyPass })
      await agent.post({ text, createdAt: new Date().toISOString() })
      results.bsky = 'success'
    } catch (e) {
      results.bsky = 'error'
    }
  }

  // 3. Threads
  if (platforms.includes('threads')) {
    try {
      // 1. 投稿コンテナを作成
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

      // 2. 作成したコンテナを公開
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

  // --- 4. Mastodon 投稿処理 ---
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

  return c.json(results)
})

// serve({
//   fetch: app.fetch,
//   port: 3000,
// })

export default app
