const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('trust proxy', true); // 让 req 拿到真实协议/域名（Render 在代理后）

// =================【核心配置：全部走环境变量】=================
const CLIENT_ID = process.env.SF_CLIENT_ID;                       // Salesforce 消费者密钥 (Consumer Key)
const CLIENT_SECRET = process.env.SF_CLIENT_SECRET;               // Salesforce 消费者密钥 (Consumer Secret)
const SF_LOGIN_URL = process.env.SF_LOGIN_URL || 'https://login.salesforce.com'; // 沙箱改 https://test.salesforce.com
const REDIRECT_URI = process.env.REDIRECT_URI;                    // 必须与 ECA/Connected App 里注册的回调完全一致，如 https://xxx.onrender.com/oauth/callback
const DOUBAO_REDIRECT_URI = process.env.DOUBAO_REDIRECT_URI;      // 可选：豆包回调兜底（豆包不传 redirect_uri 时用）

// Upstash Redis（REST 接口，免费常驻，解决 Render 休眠丢状态的问题）
const UPSTASH_URL = process.env.UPSTASH_REDIS_REST_URL;           // 形如 https://xxx.upstash.io
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

const TTL_SECONDS = 300; // state 会话有效期 5 分钟

// =================【启动自检】=================
if (!CLIENT_ID || !REDIRECT_URI) {
  console.warn('[warn] 缺少必要环境变量: SF_CLIENT_ID / REDIRECT_URI');
}
if (!CLIENT_SECRET) {
  console.log('[info] 未配置 SF_CLIENT_SECRET（官方托管 MCP 为 public client，通常无需 secret）');
}
if (!UPSTASH_URL || !UPSTASH_TOKEN) {
  console.warn('[warn] 未配置 Upstash Redis，将使用内存存储（仅限本地调试，生产会丢状态）');
}

// =================【PKCE 生成】=================
function generatePKCE() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

// =================【会话存储：Upstash Redis + 内存兜底】=================
const memoryStore = new Map();

async function redisCmd(commandArray) {
  const res = await axios.post(UPSTASH_URL, commandArray, {
    headers: { Authorization: `Bearer ${UPSTASH_TOKEN}` },
  });
  return res.data.result;
}

async function saveSession(state, payload) {
  if (UPSTASH_URL && UPSTASH_TOKEN) {
    await redisCmd(['SET', state, JSON.stringify(payload), 'EX', TTL_SECONDS]);
    return;
  }
  memoryStore.set(state, { ...payload, expiresAt: Date.now() + TTL_SECONDS * 1000 });
}

async function getSession(state) {
  if (UPSTASH_URL && UPSTASH_TOKEN) {
    const raw = await redisCmd(['GET', state]);
    return raw ? JSON.parse(raw) : null;
  }
  const s = memoryStore.get(state);
  if (s && s.expiresAt > Date.now()) return s;
  memoryStore.delete(state);
  return null;
}

async function deleteSession(state) {
  if (UPSTASH_URL && UPSTASH_TOKEN) {
    await redisCmd(['DEL', state]);
    return;
  }
  memoryStore.delete(state);
}

// =================【路由】=================

// 健康检查
app.get('/', (req, res) => res.send('Salesforce OAuth PKCE Bridge OK'));

/**
 * 1. 授权入口（豆包的 Authorization URL 填这里）
 * 帮豆包补上 code_challenge，再引导用户去 Salesforce 登录
 */
app.get('/oauth/authorize', async (req, res) => {
  const { redirect_uri, scope, state } = req.query;
  const doubaoRedirect = redirect_uri || DOUBAO_REDIRECT_URI;

  if (!doubaoRedirect) {
    return res.status(400).send('缺少 redirect_uri（豆包回调地址）');
  }
  if (!state) {
    return res.status(400).send('缺少 state 参数');
  }

  const { verifier, challenge } = generatePKCE();
  await saveSession(state, { doubaoRedirectUri: doubaoRedirect, verifier });

  const scopeStr = scope || 'mcp_api refresh_token offline_access'; // 官方托管 MCP 所需 scope
  const sfAuthUrl = `${SF_LOGIN_URL}/services/oauth2/authorize?` +
    'response_type=code' +
    `&client_id=${encodeURIComponent(CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&scope=${encodeURIComponent(scopeStr)}` +
    `&state=${encodeURIComponent(state)}` +
    `&code_challenge=${encodeURIComponent(challenge)}` +
    '&code_challenge_method=S256';

  res.redirect(sfAuthUrl);
});

/**
 * 2. 桥接回调（Salesforce 的 Callback URL 填这里）
 * 拦截 Salesforce 返回的 code，透传回豆包（state 保持不变）
 */
app.get('/oauth/callback', async (req, res) => {
  const { code, state, error, error_description } = req.query;
  const session = await getSession(state);

  if (!session) {
    return res.status(400).send('OAuth 会话已过期或非法，请回到豆包重新发起授权。');
  }

  const doubaoCallback = new URL(session.doubaoRedirectUri);
  if (error) {
    doubaoCallback.searchParams.set('error', error);
    if (error_description) doubaoCallback.searchParams.set('error_description', error_description);
    return res.redirect(doubaoCallback.toString());
  }

  doubaoCallback.searchParams.set('code', code);
  doubaoCallback.searchParams.set('state', state);
  res.redirect(doubaoCallback.toString());
});

/**
 * 3. 换 Token（豆包的 Token URL 填这里）
 * 授权码换 token 时自动补 code_verifier；client_secret 可选（配了就带）
 */
app.post('/oauth/token', async (req, res) => {
  const { grant_type, code, state, refresh_token } = req.body;

  try {
    // 刷新 token：Salesforce 启用 RTR，返回的 refresh_token 是新的，客户端必须替换存储
    if (grant_type === 'refresh_token') {
      const params = new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: CLIENT_ID,
        refresh_token: refresh_token,
      });
      if (CLIENT_SECRET) params.set('client_secret', CLIENT_SECRET); // public client 场景不配则不带
      const response = await axios.post(`${SF_LOGIN_URL}/services/oauth2/token`, params.toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      });
      return res.json(response.data);
    }

    // 首次授权码换 token
    if (grant_type === 'authorization_code') {
      const session = await getSession(state);
      if (!session) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'state 会话不存在或已过期' });
      }

      const params = new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        code_verifier: session.verifier, // 核心补全
      });
      if (CLIENT_SECRET) params.set('client_secret', CLIENT_SECRET); // public client 场景不配则不带
      const response = await axios.post(`${SF_LOGIN_URL}/services/oauth2/token`, params.toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      });

      await deleteSession(state); // 用完即删，防重放
      return res.json(response.data);
    }

    return res.status(400).json({ error: 'unsupported_grant_type' });
  } catch (error) {
    return res.status(error.response?.status || 500).json(
      error.response?.data || { error: 'token_exchange_failed' }
    );
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`[ok] Salesforce OAuth PKCE Bridge 运行在端口 ${PORT}`));
