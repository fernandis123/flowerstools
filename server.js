const express = require('express');
const path = require('path');
const fs = require('fs');
const app = express();
const PORT = process.env.PORT || 3000;

app.get('/', (req, res) => {
  const htmlPath = path.join(__dirname, 'public', 'index.html');
  console.log('📂 查找文件:', htmlPath);
  console.log('📂 文件存在:', fs.existsSync(htmlPath));
  try {
    const content = fs.readFileSync(htmlPath, 'utf8');
    console.log('📂 文件内容(前100字符):', content.substring(0, 100));
    res.send(content);
  } catch(e) {
    console.log('❌ 读取失败:', e.message);
    res.status(500).send('错误: ' + e.message);
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('✅ 服务器启动，端口:', PORT);
  console.log('📂 __dirname 路径:', __dirname);
  console.log('📂 public 路径:', path.join(__dirname, 'public'));
  try {
    const files = fs.readdirSync(path.join(__dirname, 'public'));
    console.log('📂 public 目录文件列表:', files);
  } catch(e) {
    console.log('❌ public 目录不存在或无法读取:', e.message);
  }
});
