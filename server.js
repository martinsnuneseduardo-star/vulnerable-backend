// ============================================================
//  BACKEND PROPOSITALMENTE VULNERAVEL - APENAS PARA ESTUDO
//  Nunca exponha este servidor na internet nem use em producao.
//  Por padrao, escuta somente em 127.0.0.1.
// ============================================================
const express = require('express');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors()); // VULN 10: CORS aberto para qualquer origem

const JWT_SECRET = 'secret123'; // VULN 4: segredo fraco e hardcoded
const db = new Database(':memory:');

db.exec(`
  CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, email TEXT);
  CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL, secret_note TEXT);
  INSERT INTO users (username, password, role, email) VALUES
    ('admin', 'admin123', 'admin', 'admin@example.com'),
    ('alice', 'password1', 'user', 'alice@example.com'),
    ('bob', 'qwerty', 'user', 'bob@example.com');
  INSERT INTO products (name, price, secret_note) VALUES
    ('Notebook', 3500.0, 'custo: 2100'),
    ('Mouse', 80.0, 'custo: 20'),
    ('Teclado', 150.0, 'fornecedor secreto: ACME');
`);

// Autenticacao "fraca" usada nas rotas protegidas
function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  // VULN 5: jwt.decode NAO verifica a assinatura -> token forjado e aceito
  req.user = jwt.decode(token);
  if (!req.user) return res.status(401).json({ error: 'nao autenticado' });
  next();
}

app.get('/', (req, res) => res.json({ msg: 'Vulnerable backend rodando. Veja o README.' }));

// VULN 1: Mass assignment + senha em texto puro (A04/A07)
app.post('/api/register', (req, res) => {
  const { username, password, email, role } = req.body;
  const info = db
    .prepare('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)')
    .run(username, password, email, role || 'user'); // cliente controla o "role"
  res.json({ id: info.lastInsertRowid, username, role: role || 'user' });
});

// VULN 2: SQL Injection no login (A03)
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  try {
    const user = db.prepare(sql).get();
    if (!user) return res.status(401).json({ error: 'credenciais invalidas' });
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET);
    res.json({ token }); // sem expiracao
  } catch (e) {
    res.status(500).json({ error: e.message, sql }); // VULN 11: vaza SQL e erro
  }
});

// VULN 3: IDOR + exposicao de dados sensiveis (A01/A02)
app.get('/api/users/:id', auth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  res.json(user || {}); // qualquer usuario le qualquer perfil, inclusive a senha
});

// VULN 6: SQL Injection (UNION) na busca (A03)
app.get('/api/products/search', (req, res) => {
  const q = req.query.q || '';
  try {
    const rows = db.prepare(`SELECT id, name, price FROM products WHERE name LIKE '%${q}%'`).all();
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// VULN 7: XSS refletido (A03)
app.get('/api/greet', (req, res) => {
  res.type('html').send(`<h1>Ola, ${req.query.name || 'visitante'}!</h1>`);
});

// VULN 8: Command Injection (A03)
app.get('/api/ping', (req, res) => {
  exec(`ping -c 1 ${req.query.host}`, (err, stdout, stderr) => {
    res.type('text').send(stdout || stderr || String(err));
  });
});

// VULN 9: Path Traversal (A01)
app.get('/api/files', (req, res) => {
  const file = path.join(__dirname, 'files', req.query.name || 'hello.txt');
  fs.readFile(file, 'utf8', (err, data) => {
    if (err) return res.status(404).json({ error: err.message });
    res.type('text').send(data);
  });
});

// VULN 12: SSRF (A10)
app.get('/api/fetch', async (req, res) => {
  try {
    const r = await fetch(req.query.url);
    res.type('text').send(await r.text());
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// VULN 13: Controle de acesso quebrado - confia em claim sem verificar assinatura (A01)
app.get('/api/admin/users', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'apenas admin' });
  res.json(db.prepare('SELECT * FROM users').all());
});

// VULN 14: Exposicao de variaveis de ambiente / configuracao (A05)
app.get('/api/debug', (req, res) => {
  res.json({ env: process.env, jwtSecret: JWT_SECRET, cwd: process.cwd() });
});

// VULN 11 (cont.): handler de erro vaza stack trace
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

// Sem rate limiting em nenhuma rota (A07 - brute force liberado)
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '127.0.0.1';
app.listen(PORT, HOST, () => console.log(`Vulnerable backend em http://${HOST}:${PORT}`));
