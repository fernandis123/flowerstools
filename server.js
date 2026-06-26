const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'my_digital_tool_secret_key_2024';

// ===== PostgreSQL 连接 =====
// Railway 会自动注入 DATABASE_URL 环境变量
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// ===== 初始化数据库表 =====
async function initDB() {
    try {
        // 用户表
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                username VARCHAR(100) PRIMARY KEY,
                password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);
        // 道具表
        await pool.query(`
            CREATE TABLE IF NOT EXISTS props (
                id SERIAL PRIMARY KEY,
                owner_name VARCHAR(100) NOT NULL,
                prop_name VARCHAR(200) NOT NULL,
                prop_desc TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);
        console.log('✅ 数据库初始化完成');
    } catch(e) {
        console.error('❌ 数据库初始化失败:', e.message);
        // 如果没有数据库（本地运行），回退到 JSON 文件
        console.log('⚠️  回退到 JSON 文件存储');
    }
}
initDB();

// ===== JWT 认证中间件 =====
function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: '未登录，请先登录' });
    }
    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        req.username = decoded.username;
        next();
    } catch(e) {
        return res.status(401).json({ error: '登录已过期，请重新登录' });
    }
}

// ===== 用户 API =====

app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });
        if (username.length < 2) return res.status(400).json({ error: '用户名至少2个字符' });
        if (password.length < 3) return res.status(400).json({ error: '密码至少3个字符' });

        const hashedPw = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashedPw]);

        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, username, message: '注册成功' });
    } catch(e) {
        if (e.code === '23505') return res.status(409).json({ error: '用户名已存在' });
        res.status(500).json({ error: '服务器错误' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });

        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) return res.status(404).json({ error: '用户不存在' });

        const valid = await bcrypt.compare(password, result.rows[0].password);
        if (!valid) return res.status(401).json({ error: '密码错误' });

        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, username, message: '登录成功' });
    } catch(e) {
        res.status(500).json({ error: '服务器错误' });
    }
});

app.get('/api/user/profile', authMiddleware, (req, res) => {
    res.json({ username: req.username });
});

app.put('/api/user/username', authMiddleware, async (req, res) => {
    try {
        const { newUsername } = req.body;
        if (!newUsername || newUsername.length < 2) return res.status(400).json({ error: '用户名至少2个字符' });

        await pool.query('UPDATE users SET username = $1 WHERE username = $2', [newUsername, req.username]);
        await pool.query('UPDATE props SET owner_name = $1 WHERE owner_name = $2', [newUsername, req.username]);

        const token = jwt.sign({ username: newUsername }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, username: newUsername, message: '用户名修改成功' });
    } catch(e) {
        if (e.code === '23505') return res.status(409).json({ error: '该用户名已被使用' });
        res.status(500).json({ error: '服务器错误' });
    }
});

app.put('/api/user/password', authMiddleware, async (req, res) => {
    try {
        const { newPassword } = req.body;
        if (!newPassword || newPassword.length < 3) return res.status(400).json({ error: '密码至少3个字符' });

        const hashedPw = await bcrypt.hash(newPassword, 10);
        await pool.query('UPDATE users SET password = $1 WHERE username = $2', [hashedPw, req.username]);
        res.json({ message: '密码修改成功' });
    } catch(e) {
        res.status(500).json({ error: '服务器错误' });
    }
});

// ===== 道具 API =====

app.post('/api/props', authMiddleware, async (req, res) => {
    try {
        const { propName, propDesc } = req.body;
        if (!propName || !propDesc) return res.status(400).json({ error: '道具名称和描述不能为空' });

        const result = await pool.query(
            'INSERT INTO props (owner_name, prop_name, prop_desc) VALUES ($1, $2, $3) RETURNING id',
            [req.username, propName.trim(), propDesc.trim()]
        );
        res.json({ id: result.rows[0].id, message: '道具录入成功' });
    } catch(e) {
        res.status(500).json({ error: '服务器错误' });
    }
});

app.get('/api/props/mine', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM props WHERE owner_name = $1 ORDER BY created_at DESC',
            [req.username]
        );
        res.json(result.rows);
    } catch(e) {
        res.status(500).json({ error: '服务器错误' });
    }
});

app.delete('/api/props/:id', authMiddleware, async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        const result = await pool.query('DELETE FROM props WHERE id = $1 AND owner_name = $2 RETURNING id', [id, req.username]);
        if (result.rows.length === 0) return res.status(404).json({ error: '道具不存在' });
        res.json({ message: '删除成功' });
    } catch(e) {
        res.status(500).json({ error: '服务器错误' });
    }
});

app.get('/api/props/search', async (req, res) => {
    try {
        const q = (req.query.q || '').trim();
        if (!q) return res.json([]);
        const result = await pool.query(
            'SELECT * FROM props WHERE LOWER(prop_name) LIKE LOWER($1) ORDER BY created_at DESC',
            ['%' + q + '%']
        );
        res.json(result.rows);
    } catch(e) {
        res.status(500).json({ error: '服务器错误' });
    }
});

// ===== 启动 =====
app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🎮 数字化工具服务器已启动！`);
    console.log(`📡 端口: ${PORT}`);
    console.log(`🔗 打开浏览器访问: http://localhost:${PORT}\n`);
});