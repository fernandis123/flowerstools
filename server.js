// ============================================================
// 数字化工具 - 多用户云端后端服务器 (PostgreSQL + JSON 回退)
// ============================================================

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const path = require('path');
const fs = require('fs');

// ===== 配置 =====
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'mySuperSecretKey2024';

// ===== 中间件 =====
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ===== 数据库连接 =====
let pool;
let useJsonFallback = false;
const DB_FILE = path.join(__dirname, 'data.json');

// ===== 初始化数据库 =====
async function initDatabase() {
  const connectionString = process.env.DATABASE_URL;

  if (!connectionString) {
    console.log('⚠️ 未设置 DATABASE_URL，回退到 JSON 文件存储');
    useJsonFallback = true;
    initJsonStorage();
    return;
  }

  try {
    pool = new Pool({
      connectionString: connectionString,
      ssl: {
        rejectUnauthorized: false   // Railway 必须！
      }
    });

    // 测试连接
    const client = await pool.connect();
    console.log('✅ PostgreSQL 连接成功！');

    // 创建 users 表
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        score INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('✅ users 表已就绪');
    client.release();

  } catch (err) {
    console.error('❌ 数据库初始化失败:', err.message);
    console.log('⚠️ 回退到 JSON 文件存储');
    useJsonFallback = true;
    initJsonStorage();
  }
}

// ===== JSON 文件存储初始化 =====
function initJsonStorage() {
  if (!fs.existsSync(DB_FILE)) {
    const defaultData = { users: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(defaultData, null, 2));
    console.log('✅ 已创建 data.json 文件');
  } else {
    console.log('✅ data.json 已存在');
  }
}

// ===== 读取用户数据（JSON 回退） =====
function readUsers() {
  try {
    const data = fs.readFileSync(DB_FILE, 'utf8');
    const parsed = JSON.parse(data);
    return parsed.users || [];
  } catch {
    return [];
  }
}

// ===== 写入用户数据（JSON 回退） =====
function writeUsers(users) {
  fs.writeFileSync(DB_FILE, JSON.stringify({ users }, null, 2));
}

// ===== 注册接口 =====
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: '用户名和密码不能为空' });
    }
    if (username.length < 2) {
      return res.status(400).json({ error: '用户名至少2个字符' });
    }
    if (password.length < 4) {
      return res.status(400).json({ error: '密码至少4个字符' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    if (useJsonFallback) {
      // === JSON 方式 ===
      const users = readUsers();
      const existing = users.find(u => u.username === username);
      if (existing) {
        return res.status(400).json({ error: '用户名已存在' });
      }
      const newUser = {
        id: users.length + 1,
        username,
        password: hashedPassword,
        score: 0,
        created_at: new Date().toISOString()
      };
      users.push(newUser);
      writeUsers(users);

      const token = jwt.sign(
        { id: newUser.id, username: newUser.username },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      return res.json({
        message: '注册成功',
        token,
        user: { id: newUser.id, username: newUser.username, score: 0 }
      });

    } else {
      // === PostgreSQL 方式 ===
      const existing = await pool.query(
        'SELECT * FROM users WHERE username = $1',
        [username]
      );
      if (existing.rows.length > 0) {
        return res.status(400).json({ error: '用户名已存在' });
      }

      const result = await pool.query(
        'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username, score',
        [username, hashedPassword]
      );
      const newUser = result.rows[0];

      const token = jwt.sign(
        { id: newUser.id, username: newUser.username },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      return res.json({
        message: '注册成功',
        token,
        user: { id: newUser.id, username: newUser.username, score: newUser.score }
      });
    }

  } catch (err) {
    console.error('注册错误:', err.message);
    res.status(500).json({ error: '服务器错误，请稍后再试' });
  }
});

// ===== 登录接口 =====
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: '用户名和密码不能为空' });
    }

    if (useJsonFallback) {
      // === JSON 方式 ===
      const users = readUsers();
      const user = users.find(u => u.username === username);
      if (!user) {
        return res.status(400).json({ error: '用户名或密码错误' });
      }

      const isValid = await bcrypt.compare(password, user.password);
      if (!isValid) {
        return res.status(400).json({ error: '用户名或密码错误' });
      }

      const token = jwt.sign(
        { id: user.id, username: user.username },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      return res.json({
        message: '登录成功',
        token,
        user: { id: user.id, username: user.username, score: user.score }
      });

    } else {
      // === PostgreSQL 方式 ===
      const result = await pool.query(
        'SELECT * FROM users WHERE username = $1',
        [username]
      );
      if (result.rows.length === 0) {
        return res.status(400).json({ error: '用户名或密码错误' });
      }

      const user = result.rows[0];
      const isValid = await bcrypt.compare(password, user.password);
      if (!isValid) {
        return res.status(400).json({ error: '用户名或密码错误' });
      }

      const token = jwt.sign(
        { id: user.id, username: user.username },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      return res.json({
        message: '登录成功',
        token,
        user: { id: user.id, username: user.username, score: user.score }
      });
    }

  } catch (err) {
    console.error('登录错误:', err.message);
    res.status(500).json({ error: '服务器错误，请稍后再试' });
  }
});

// ===== 获取用户信息（需要 Token） =====
app.get('/api/user', authenticateToken, async (req, res) => {
  try {
    if (useJsonFallback) {
      const users = readUsers();
      const user = users.find(u => u.id === req.user.id);
      if (!user) return res.status(404).json({ error: '用户不存在' });
      return res.json({ id: user.id, username: user.username, score: user.score });
    } else {
      const result = await pool.query(
        'SELECT id, username, score FROM users WHERE id = $1',
        [req.user.id]
      );
      if (result.rows.length === 0) {
        return res.status(404).json({ error: '用户不存在' });
      }
      return res.json(result.rows[0]);
    }
  } catch (err) {
    console.error('获取用户信息错误:', err.message);
    res.status(500).json({ error: '服务器错误' });
  }
});

// ===== 更新分数 =====
app.post('/api/score', authenticateToken, async (req, res) => {
  try {
    const { score } = req.body;

    if (useJsonFallback) {
      const users = readUsers();
      const idx = users.findIndex(u => u.id === req.user.id);
      if (idx === -1) return res.status(404).json({ error: '用户不存在' });
      users[idx].score = score || 0;
      writeUsers(users);
      return res.json({ message: '分数已更新', score: users[idx].score });
    } else {
      const result = await pool.query(
        'UPDATE users SET score = $1 WHERE id = $2 RETURNING id, username, score',
        [score || 0, req.user.id]
      );
      if (result.rows.length === 0) {
        return res.status(404).json({ error: '用户不存在' });
      }
      return res.json({ message: '分数已更新', score: result.rows[0].score });
    }
  } catch (err) {
    console.error('更新分数错误:', err.message);
    res.status(500).json({ error: '服务器错误' });
  }
});

// ===== 排行榜 =====
app.get('/api/ranking', async (req, res) => {
  try {
    if (useJsonFallback) {
      const users = readUsers();
      const ranking = users
        .sort((a, b) => b.score - a.score)
        .slice(0, 50)
        .map((u, i) => ({
          rank: i + 1,
          username: u.username,
          score: u.score
        }));
      return res.json(ranking);
    } else {
      const result = await pool.query(
        'SELECT username, score FROM users ORDER BY score DESC LIMIT 50'
      );
      const ranking = result.rows.map((u, i) => ({
        rank: i + 1,
        username: u.username,
        score: u.score
      }));
      return res.json(ranking);
    }
  } catch (err) {
    console.error('排行榜错误:', err.message);
    res.status(500).json({ error: '服务器错误' });
  }
});

// ===== Token 验证中间件 =====
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: '未登录，请先登录' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: '登录已过期，请重新登录' });
    }
    req.user = user;
    next();
  });
}

// ===== 启动服务器 =====
async function start() {
  await initDatabase();

  app.listen(PORT, '0.0.0.0', () => {
    console.log('\n==========================================');
    console.log('🎮 数字化工具服务器已启动！');
    console.log('📡 端口:', PORT);
    console.log('🔗 打开浏览器访问: http://localhost:' + PORT);
    console.log('==========================================\n');
  });
}

start();
