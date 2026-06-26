const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

app.get('/', (req, res) => {
  res.send('<h1>✅ 服务器正常运行！</h1><p>如果看到这行字，说明 Express 工作正常</p>');
});

app.get('/api/test', (req, res) => {
  res.json({ status: 'ok', message: 'API 正常' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('✅ 测试服务器启动，端口:', PORT);
});
