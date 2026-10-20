const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// =================【核心配置区】=================
const SF_DOMAIN = 'https://salesforce.com'; // 沙箱环境请改为 https://salesforce.com
const CLIENT_ID = '你的_SALESFORCE_CLIENT_ID';
const CLIENT_SECRET = '你的_SALESFORCE_CLIENT_SECRET';
// ===============================================

// 内存中转站：用于临时绑定不同用户的 state 与 verifier (生产环境建议设置 5 分钟过期的 Redis 缓存)
const pkceSessionStore = new Map();

// 辅助函数：生成 PKCE 校验参数
function generatePKCE() {
    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier).digest().toString('base64url');
    return { verifier, challenge };
}

/**
 * 1. 代理授权入口 (豆包的 Authorization URL 填这里)
 * 作用：帮豆包补全 code_challenge，然后把用户引导至 Salesforce 官方登录
 */
app.get('/oauth/authorize', (req, res) => {
    const { redirect_uri, scope, state } = req.query;
    
    // 生成这一轮登录专属的 PKCE 校验对
    const { verifier, challenge } = generatePKCE();
    
    // 关键：将豆包带过来的 state、redirect_uri 与生成的 verifier 绑定存入内存
    pkceSessionStore.set(state, {
        doubaoRedirectUri: redirect_uri,
        verifier: verifier
    });

    // 拼装带有 PKCE 参数的真正 Salesforce 授权地址
    const sfAuthUrl = `${SF_DOMAIN}/services/oauth2/authorize?` + 
        `response_type=code` +
        `&client_id=${encodeURIComponent(CLIENT_ID)}` +
        `&redirect_uri=${encodeURIComponent('https://' + req.get('host') + '/oauth/callback')}` + // 必须是本桥接服务的 callback
        `&scope=${encodeURIComponent(scope || '')}` +
        `&state=${encodeURIComponent(state || '')}` +
        `&code_challenge=${encodeURIComponent(challenge)}` +
        `&code_challenge_method=S256`;

    // 将用户重定向到 Salesforce 官方页面进行登录
    res.redirect(sfAuthUrl);
});

/**
 * 2. 桥接服务回调接收点 (Salesforce 的 Callback URL 填这里)
 * 作用：拦截 Salesforce 返回的 code，透传回豆包
 */
app.get('/oauth/callback', (req, res) => {
    const { code, state } = req.query;
    const session = pkceSessionStore.get(state);

    if (!session) {
        return res.status(400).send('OAuth 会话已过期或非法访问，请在豆包重试。');
    }

    // 将 Salesforce 颁发的 code 携带原有的 state，安全重定向回豆包的回调地址
    const doubaoCallbackUrl = `${session.doubaoRedirectUri}?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`;
    res.redirect(doubaoCallbackUrl);
});

/**
 * 3. 代理换取 Token 入口 (豆包的 获取 Access Token URL 填这里)
 * 作用：当豆包用 code 换 token 时，拦截请求并自动补齐 code_verifier 传给 Salesforce
 */
app.post('/oauth/token', async (req, res) => {
    const { grant_type, code, state, refresh_token } = req.body;

    // 处理刷新 Token 流程 (刷新 Token 阶段 Salesforce 同样强制校验 Client Secret)
    if (grant_type === 'refresh_token') {
        try {
            const params = new URLSearchParams({
                grant_type: 'refresh_token',
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                refresh_token: refresh_token
            });
            const response = await axios.post(`${SF_DOMAIN}/services/oauth2/token`, params.toString(), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            });
            return res.json(response.data);
        } catch (error) {
            return res.status(error.response?.status || 500).json(error.response?.data || { error: 'Refresh token failed' });
        }
    }

    // 处理首次授权码换 Token 流程
    const session = pkceSessionStore.get(state);
    if (!session) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'State session not found' });
    }

    try {
        // 拼装请求体，将豆包发不出的 code_verifier 自动补上
        const params = new URLSearchParams({
            grant_type: 'authorization_code',
            code: code,
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
            redirect_uri: `https://${req.get('host')}/oauth/callback`,
            code_verifier: session.verifier // 核心补全！
        });

        const response = await axios.post(`${SF_DOMAIN}/services/oauth2/token`, params.toString(), {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });

        // 使用完立刻从内存删除，防止重放攻击
        pkceSessionStore.delete(state);

        // 将 Salesforce 颁发的专属 JWT 格式 Token 丢回给豆包存储
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json(error.response?.data || { error: 'Token exchange failed' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`OAuth Bridge Proxy 运行在端口: ${PORT}`));
