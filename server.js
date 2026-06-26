const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'mySuperSecretKey2024';
const DB_FILE = path.join(__dirname, 'data.json');

app.use(cors());
app.use(express.json());
app.use('/', express.static(path.join(__dirname, 'public')));

let pool = null;
let useJson = false;

async function initDB() {
  const cs = process.env.DATABASE_URL;
  if (!cs) { useJson = true; initJson(); return; }
  try {
    pool = new Pool({ connectionString: cs, ssl: { rejectUnauthorized: false } });
    const c = await pool.connect();
    console.log('✅ PostgreSQL 连接成功！');
    await c.query(`CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL, password VARCHAR(255) NOT NULL, score INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await c.query(`CREATE TABLE IF NOT EXISTS props (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, prop_name VARCHAR(100) NOT NULL, prop_desc TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    console.log('✅ 数据表已就绪');
    c.release();
  } catch(e) {
    console.log('⚠️ 数据库失败，改用JSON:', e.message);
    useJson = true; initJson();
  }
}
function initJson() {
  if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({users:[],props:[]}));
}
function readDB() {
  try { return JSON.parse(fs.readFileSync(DB_FILE,'utf8')); } catch { return {users:[],props:[]}; }
}
function writeDB(d) { fs.writeFileSync(DB_FILE, JSON.stringify(d,null,2)); }

function auth(req, res, next) {
  const t = (req.headers['authorization']||'').split(' ')[1];
  if (!t) return res.status(401).json({error:'未登录'});
  jwt.verify(t, JWT_SECRET, (e,u) => { if(e) return res.status(403).json({error:'登录过期'}); req.user=u; next(); });
}

// 用户接口
app.post('/api/register', async (req, res) => {
  try {
    const {username, password} = req.body;
    if (!username||!password) return res.status(400).json({error:'用户名和密码不能为空'});
    if (username.length<2) return res.status(400).json({error:'用户名至少2个字符'});
    if (password.length<4) return res.status(400).json({error:'密码至少4个字符'});
    const hp = await bcrypt.hash(password, 10);
    if (useJson) {
      const d=readDB();
      if (d.users.find(u=>u.username===username)) return res.status(400).json({error:'用户名已存在'});
      const nu={id:d.users.length+1,username,password:hp,score:0,created_at:new Date().toISOString()};
      d.users.push(nu); writeDB(d);
      const token=jwt.sign({id:nu.id,username:nu.username},JWT_SECRET,{expiresIn:'7d'});
      return res.json({message:'注册成功',token,user:{id:nu.id,username:nu.username,score:0}});
    } else {
      const e=await pool.query('SELECT * FROM users WHERE username=$1',[username]);
      if (e.rows.length>0) return res.status(400).json({error:'用户名已存在'});
      const r=await pool.query('INSERT INTO users(username,password) VALUES($1,$2) RETURNING id,username,score',[username,hp]);
      const nu=r.rows[0];
      const token=jwt.sign({id:nu.id,username:nu.username},JWT_SECRET,{expiresIn:'7d'});
      return res.json({message:'注册成功',token,user:{id:nu.id,username:nu.username,score:nu.score}});
    }
  } catch(e) { console.error('注册错误:',e.message); res.status(500).json({error:'服务器错误'}); }
});

app.post('/api/login', async (req, res) => {
  try {
    const {username,password}=req.body;
    if (!username||!password) return res.status(400).json({error:'用户名和密码不能为空'});
    if (useJson) {
      const d=readDB(); const u=d.users.find(x=>x.username===username);
      if (!u||!(await bcrypt.compare(password,u.password))) return res.status(400).json({error:'用户名或密码错误'});
      const token=jwt.sign({id:u.id,username:u.username},JWT_SECRET,{expiresIn:'7d'});
      return res.json({message:'登录成功',token,user:{id:u.id,username:u.username,score:u.score}});
    } else {
      const r=await pool.query('SELECT * FROM users WHERE username=$1',[username]);
      if (r.rows.length===0||!(await bcrypt.compare(password,r.rows[0].password))) return res.status(400).json({error:'用户名或密码错误'});
      const u=r.rows[0];
      const token=jwt.sign({id:u.id,username:u.username},JWT_SECRET,{expiresIn:'7d'});
      return res.json({message:'登录成功',token,user:{id:u.id,username:u.username,score:u.score}});
    }
  } catch(e) { console.error('登录错误:',e.message); res.status(500).json({error:'服务器错误'}); }
});

app.get('/api/user/profile', auth, async (req, res) => {
  try {
    if (useJson) { const d=readDB(); const u=d.users.find(x=>x.id===req.user.id); if(!u) return res.status(404).json({error:'用户不存在'}); return res.json({id:u.id,username:u.username,score:u.score}); }
    else { const r=await pool.query('SELECT id,username,score FROM users WHERE id=$1',[req.user.id]); if(r.rows.length===0) return res.status(404).json({error:'用户不存在'}); return res.json(r.rows[0]); }
  } catch(e) { res.status(500).json({error:'服务器错误'}); }
});

app.put('/api/user/username', auth, async (req, res) => {
  try {
    const {newUsername}=req.body;
    if (!newUsername||newUsername.length<2) return res.status(400).json({error:'用户名至少2个字符'});
    if (useJson) {
      const d=readDB();
      if (d.users.find(u=>u.username===newUsername&&u.id!==req.user.id)) return res.status(400).json({error:'用户名已被使用'});
      const i=d.users.findIndex(u=>u.id===req.user.id); if(i===-1) return res.status(404).json({error:'用户不存在'});
      d.users[i].username=newUsername; writeDB(d);
      const token=jwt.sign({id:req.user.id,username:newUsername},JWT_SECRET,{expiresIn:'7d'});
      return res.json({message:'用户名已更新',token,username:newUsername});
    } else {
      const e=await pool.query('SELECT * FROM users WHERE username=$1 AND id!=$2',[newUsername,req.user.id]);
      if (e.rows.length>0) return res.status(400).json({error:'用户名已被使用'});
      await pool.query('UPDATE users SET username=$1 WHERE id=$2',[newUsername,req.user.id]);
      const token=jwt.sign({id:req.user.id,username:newUsername},JWT_SECRET,{expiresIn:'7d'});
      return res.json({message:'用户名已更新',token,username:newUsername});
    }
  } catch(e) { console.error('修改用户名错误:',e.message); res.status(500).json({error:'服务器错误'}); }
});

app.put('/api/user/password', auth, async (req, res) => {
  try {
    const {newPassword}=req.body;
    if (!newPassword||newPassword.length<4) return res.status(400).json({error:'密码至少4个字符'});
    const hp=await bcrypt.hash(newPassword,10);
    if (useJson) { const d=readDB(); const i=d.users.findIndex(u=>u.id===req.user.id); if(i===-1) return res.status(404).json({error:'用户不存在'}); d.users[i].password=hp; writeDB(d); return res.json({message:'密码已更新'}); }
    else { await pool.query('UPDATE users SET password=$1 WHERE id=$2',[hp,req.user.id]); return res.json({message:'密码已更新'}); }
  } catch(e) { res.status(500).json({error:'服务器错误'}); }
});

// 道具接口
app.post('/api/props', auth, async (req, res) => {
  try {
    const {propName,propDesc}=req.body;
    if(!propName) return res.status(400).json({error:'请输入道具名称'});
    if(!propDesc) return res.status(400).json({error:'请输入道具描述'});
    if (useJson) {
      const d=readDB();
      const np={id:d.props.length+1,userId:req.user.id,ownerName:req.user.username,propName,propDesc,createdAt:new Date().toISOString()};
      d.props.push(np); writeDB(d);
      return res.json({message:'道具录入成功',prop:np});
    } else {
      const r=await pool.query('INSERT INTO props(user_id,prop_name,prop_desc) VALUES($1,$2,$3) RETURNING id,user_id,prop_name,prop_desc,created_at',[req.user.id,propName,propDesc]);
      return res.json({message:'道具录入成功',prop:{id:r.rows[0].id,userId:r.rows[0].user_id,ownerName:req.user.username,propName:r.rows[0].prop_name,propDesc:r.rows[0].prop_desc,createdAt:r.rows[0].created_at}});
    }
  } catch(e) { console.error('录入道具错误:',e.message); res.status(500).json({error:'服务器错误'}); }
});

app.get('/api/props/mine', auth, async (req, res) => {
  try {
    if (useJson) { const d=readDB(); return res.json(d.props.filter(p=>p.userId===req.user.id).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt))); }
    else { const r=await pool.query('SELECT id,user_id,prop_name,prop_desc,created_at FROM props WHERE user_id=$1 ORDER BY created_at DESC',[req.user.id]); return res.json(r.rows.map(p=>({id:p.id,userId:p.user_id,ownerName:req.user.username,propName:p.prop_name,propDesc:p.prop_desc,createdAt:p.created_at}))); }
  } catch(e) { res.status(500).json({error:'服务器错误'}); }
});

app.delete('/api/props/:id', auth, async (req, res) => {
  try {
    const pid=parseInt(req.params.id);
    if (useJson) { const d=readDB(); const i=d.props.findIndex(p=>p.id===pid&&p.userId===req.user.id); if(i===-1) return res.status(404).json({error:'道具不存在或无权删除'}); d.props.splice(i,1); writeDB(d); return res.json({message:'道具已删除'}); }
    else { const r=await pool.query('DELETE FROM props WHERE id=$1 AND user_id=$2 RETURNING id',[pid,req.user.id]); if(r.rows.length===0) return res.status(404).json({error:'道具不存在或无权删除'}); return res.json({message:'道具已删除'}); }
  } catch(e) { res.status(500).json({error:'服务器错误'}); }
});

app.get('/api/props/search', async (req, res) => {
  try {
    const keyword=(req.query.q||'').trim();
    if(!keyword) return res.status(400).json({error:'请输入搜索关键词'});
    if (useJson) { const d=readDB(); return res.json(d.props.filter(p=>p.propName.toLowerCase().includes(keyword.toLowerCase())||p.propDesc.toLowerCase().includes(keyword.toLowerCase()))); }
    else { const r=await pool.query("SELECT p.id,p.user_id,p.prop_name,p.prop_desc,p.created_at,u.username as owner_name FROM props p JOIN users u ON p.user_id=u.id WHERE p.prop_name ILIKE $1 OR p.prop_desc ILIKE $1 ORDER BY p.created_at DESC",[`%${keyword}%`]); return res.json(r.rows.map(p=>({id:p.id,userId:p.user_id,ownerName:p.owner_name,propName:p.prop_name,propDesc:p.prop_desc,createdAt:p.created_at}))); }
  } catch(e) { res.status(500).json({error:'服务器错误'}); }
});

app.get('/api/ranking', async (req, res) => {
  try {
    if (useJson) { const d=readDB(); return res.json(d.users.sort((a,b)=>b.score-a.score).slice(0,50).map((u,i)=>({rank:i+1,username:u.username,score:u.score}))); }
    else { const r=await pool.query('SELECT username,score FROM users ORDER BY score DESC LIMIT 50'); return res.json(r.rows.map((u,i)=>({rank:i+1,username:u.username,score:u.score}))); }
  } catch(e) { res.status(500).json({error:'服务器错误'}); }
});

// 启动
async function start() {
  await initDB();
  app.listen(PORT, '0.0.0.0', () => {
    console.log('\n🎮 数字化工具服务器已启动！端口:', PORT);
  });
}
start();
