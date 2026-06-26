const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

// 静态文件
app.use('/', express.static(path.join(__dirname, 'public')));

// 首页路由（兜底）
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('✅ 服务器启动，端口:', PORT);
});
