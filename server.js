
const express = require('express');
const { Pool } = require('pg');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 10000;
const APP_PASSWORD = process.env.APP_PASSWORD || 'mudeesta senha';
const APP_SECRET = process.env.APP_SECRET || crypto.randomBytes(32).toString('hex');
const MAX_FILE_SIZE = 4 * 1024 * 1024; // 4MB

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('localhost')
    ? false
    : { rejectUnauthorized: false },
});

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_FILE_SIZE } });

app.use(express.json({ limit: '200mb' }));

// ---------- migrações ----------
async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS clientes (
      id TEXT PRIMARY KEY,
      nome TEXT NOT NULL,
      empresa TEXT, telefone TEXT, email TEXT, endereco TEXT, cep TEXT,
      cnpj TEXT, inscricao_estadual TEXT, categoria TEXT, observacoes TEXT,
      criado_em TIMESTAMPTZ DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS produtos (
      id TEXT PRIMARY KEY,
      cliente_id TEXT NOT NULL,
      linha TEXT, descricao TEXT, medidas TEXT, cores TEXT, impressao TEXT,
      preco NUMERIC, quantidade NUMERIC, ordem INT DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS pedidos (
      id TEXT PRIMARY KEY,
      cliente_id TEXT NOT NULL,
      data TEXT, descricao TEXT, valor NUMERIC
    );
    CREATE TABLE IF NOT EXISTS anexos (
      id TEXT PRIMARY KEY,
      cliente_id TEXT, produto_id TEXT,
      nome TEXT, tipo TEXT, tamanho BIGINT, dados BYTEA,
      criado_em TIMESTAMPTZ DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS prospectos (
      id TEXT PRIMARY KEY,
      nome TEXT NOT NULL, empresa TEXT, telefone TEXT, email TEXT,
      anotacoes TEXT, data TEXT
    );
    CREATE TABLE IF NOT EXISTS tarefas (
      id TEXT PRIMARY KEY,
      titulo TEXT NOT NULL, descricao TEXT, prazo TEXT,
      prioridade TEXT, status TEXT DEFAULT 'pendente',
      cliente_id TEXT, cliente_nome TEXT,
      criado_em TIMESTAMPTZ DEFAULT now()
    );
  `);
  console.log('Migração concluída.');
}

// ---------- autenticação (token assinado, sem sessão em memória) ----------
function signToken() {
  const exp = Date.now() + 1000 * 60 * 60 * 24 * 60; // 60 dias
  const payload = String(exp);
  const sig = crypto.createHmac('sha256', APP_SECRET).update(payload).digest('hex');
  return Buffer.from(`${payload}.${sig}`).toString('base64');
}
function verifyToken(token) {
  try {
    const decoded = Buffer.from(token, 'base64').toString('utf8');
    const [payload, sig] = decoded.split('.');
    const expected = crypto.createHmac('sha256', APP_SECRET).update(payload).digest('hex');
    if (sig !== expected) return false;
    return Number(payload) > Date.now();
  } catch (e) {
    return false;
  }
}
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const fromHeader = header.startsWith('Bearer ') ? header.slice(7) : null;
  const token = fromHeader || req.query.token;
  if (!token || !verifyToken(token)) return res.status(401).json({ error: 'não autorizado' });
  next();
}

app.post('/api/login', (req, res) => {
  const { senha } = req.body || {};
  if (senha !== APP_PASSWORD) return res.status(401).json({ error: 'senha incorreta' });
  res.json({ token: signToken() });
});

// ---------- clientes ----------
app.get('/api/clientes', requireAuth, async (req, res) => {
  try {
    const { rows: clientes } = await pool.query('SELECT * FROM clientes ORDER BY criado_em');
    const { rows: produtos } = await pool.query('SELECT * FROM produtos ORDER BY ordem');
    const { rows: pedidos } = await pool.query('SELECT * FROM pedidos');
    const { rows: anexos } = await pool.query('SELECT id, cliente_id, produto_id, nome, tipo, tamanho FROM anexos');

    const result = clientes.map((c) => ({
      id: c.id, nome: c.nome, empresa: c.empresa, telefone: c.telefone, email: c.email,
      endereco: c.endereco, cep: c.cep, cnpj: c.cnpj, inscricaoEstadual: c.inscricao_estadual,
      categoria: c.categoria, observacoes: c.observacoes,
      produtos: produtos.filter((p) => p.cliente_id === c.id).map((p) => ({
        id: p.id, linha: p.linha, descricao: p.descricao, medidas: p.medidas, cores: p.cores,
        impressao: p.impressao, preco: p.preco, quantidade: p.quantidade,
        anexos: anexos.filter((a) => a.produto_id === p.id).map((a) => ({ id: a.id, nome: a.nome, tipo: a.tipo, tamanho: Number(a.tamanho) })),
      })),
      pedidos: pedidos.filter((p) => p.cliente_id === c.id).map((p) => ({ id: p.id, data: p.data, descricao: p.descricao, valor: p.valor })),
      orcamentos: anexos.filter((a) => a.cliente_id === c.id && !a.produto_id).map((a) => ({ id: a.id, nome: a.nome, tipo: a.tipo, tamanho: Number(a.tamanho) })),
    }));
    res.json(result);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'erro ao buscar clientes' });
  }
});

app.post('/api/clientes', requireAuth, async (req, res) => {
  const c = req.body || {};
  if (!c.id || !c.nome) return res.status(400).json({ error: 'id e nome são obrigatórios' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `INSERT INTO clientes (id, nome, empresa, telefone, email, endereco, cep, cnpj, inscricao_estadual, categoria, observacoes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       ON CONFLICT (id) DO UPDATE SET nome=$2, empresa=$3, telefone=$4, email=$5, endereco=$6, cep=$7, cnpj=$8, inscricao_estadual=$9, categoria=$10, observacoes=$11`,
      [c.id, c.nome, c.empresa || '', c.telefone || '', c.email || '', c.endereco || '', c.cep || '', c.cnpj || '', c.inscricaoEstadual || '', c.categoria || '', c.observacoes || '']
    );

    const incomingProdutos = c.produtos || [];
    const incomingIds = incomingProdutos.map((p) => p.id);
    const { rows: existentes } = await client.query('SELECT id FROM produtos WHERE cliente_id = $1', [c.id]);
    const idsRemover = existentes.map((r) => r.id).filter((id) => !incomingIds.includes(id));
    if (idsRemover.length) {
      await client.query('DELETE FROM produtos WHERE id = ANY($1::text[])', [idsRemover]);
      await client.query('DELETE FROM anexos WHERE produto_id = ANY($1::text[])', [idsRemover]);
    }
    let ordem = 0;
    for (const p of incomingProdutos) {
      await client.query(
        `INSERT INTO produtos (id, cliente_id, linha, descricao, medidas, cores, impressao, preco, quantidade, ordem)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         ON CONFLICT (id) DO UPDATE SET linha=$3, descricao=$4, medidas=$5, cores=$6, impressao=$7, preco=$8, quantidade=$9, ordem=$10`,
        [p.id, c.id, p.linha || '', p.descricao || '', p.medidas || '', p.cores || '', p.impressao || '', p.preco || 0, p.quantidade || 0, ordem++]
      );
    }

    await client.query('DELETE FROM pedidos WHERE cliente_id = $1', [c.id]);
    for (const p of (c.pedidos || [])) {
      await client.query(
        `INSERT INTO pedidos (id, cliente_id, data, descricao, valor) VALUES ($1,$2,$3,$4,$5)`,
        [p.id, c.id, p.data || '', p.descricao || '', p.valor || 0]
      );
    }

    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error(e);
    res.status(500).json({ error: 'erro ao salvar cliente' });
  } finally {
    client.release();
  }
});

app.delete('/api/clientes/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: produtos } = await client.query('SELECT id FROM produtos WHERE cliente_id = $1', [id]);
    const produtoIds = produtos.map((p) => p.id);
    if (produtoIds.length) {
      await client.query('DELETE FROM anexos WHERE produto_id = ANY($1::text[])', [produtoIds]);
    }
    await client.query('DELETE FROM anexos WHERE cliente_id = $1', [id]);
    await client.query('DELETE FROM produtos WHERE cliente_id = $1', [id]);
    await client.query('DELETE FROM pedidos WHERE cliente_id = $1', [id]);
    await client.query('DELETE FROM clientes WHERE id = $1', [id]);
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error(e);
    res.status(500).json({ error: 'erro ao excluir cliente' });
  } finally {
    client.release();
  }
});

// ---------- prospectos ----------
app.get('/api/prospectos', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM prospectos ORDER BY data');
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'erro ao buscar prospecções' });
  }
});

app.post('/api/prospectos', requireAuth, async (req, res) => {
  const p = req.body || {};
  if (!p.id || !p.nome) return res.status(400).json({ error: 'id e nome são obrigatórios' });
  try {
    await pool.query(
      `INSERT INTO prospectos (id, nome, empresa, telefone, email, anotacoes, data)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (id) DO UPDATE SET nome=$2, empresa=$3, telefone=$4, email=$5, anotacoes=$6, data=$7`,
      [p.id, p.nome, p.empresa || '', p.telefone || '', p.email || '', p.anotacoes || '', p.data || new Date().toISOString()]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'erro ao salvar prospecção' });
  }
});

app.delete('/api/prospectos/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM prospectos WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'erro ao excluir prospecção' });
  }
});

// ---------- tarefas ----------
app.get('/api/tarefas', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM tarefas ORDER BY (prazo IS NULL), prazo, criado_em');
    res.json(rows.map((t) => ({
      id: t.id, titulo: t.titulo, descricao: t.descricao, prazo: t.prazo,
      prioridade: t.prioridade, status: t.status,
      clienteId: t.cliente_id, clienteNome: t.cliente_nome,
    })));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'erro ao buscar tarefas' });
  }
});

app.post('/api/tarefas', requireAuth, async (req, res) => {
  const t = req.body || {};
  if (!t.id || !t.titulo) return res.status(400).json({ error: 'id e título são obrigatórios' });
  try {
    await pool.query(
      `INSERT INTO tarefas (id, titulo, descricao, prazo, prioridade, status, cliente_id, cliente_nome)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       ON CONFLICT (id) DO UPDATE SET titulo=$2, descricao=$3, prazo=$4, prioridade=$5, status=$6, cliente_id=$7, cliente_nome=$8`,
      [t.id, t.titulo, t.descricao || '', t.prazo || null, t.prioridade || '', t.status || 'pendente', t.clienteId || null, t.clienteNome || '']
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'erro ao salvar tarefa' });
  }
});

app.delete('/api/tarefas/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM tarefas WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'erro ao excluir tarefa' });
  }
});

// ---------- anexos ----------
app.post('/api/anexos', requireAuth, upload.single('arquivo'), async (req, res) => {
  const file = req.file;
  const { clienteId, produtoId } = req.body || {};
  if (!file) return res.status(400).json({ error: 'arquivo ausente' });
  try {
    const id = crypto.randomUUID();
    await pool.query(
      `INSERT INTO anexos (id, cliente_id, produto_id, nome, tipo, tamanho, dados) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [id, clienteId || null, produtoId || null, file.originalname, file.mimetype, file.size, file.buffer]
    );
    res.json({ id, nome: file.originalname, tipo: file.mimetype, tamanho: file.size });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'erro ao salvar anexo' });
  }
});

app.get('/api/anexos/:id', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT nome, tipo, dados FROM anexos WHERE id = $1', [req.params.id]);
    if (!rows[0]) return res.status(404).end();
    const a = rows[0];
    res.setHeader('Content-Type', a.tipo || 'application/octet-stream');
    res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(a.nome || 'arquivo')}"`);
    res.send(a.dados);
  } catch (e) {
    console.error(e);
    res.status(500).end();
  }
});

app.delete('/api/anexos/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM anexos WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'erro ao excluir anexo' });
  }
});

// ---------- backup e restauração ----------
app.get('/api/backup', requireAuth, async (req, res) => {
  try {
    const [clientes, produtos, pedidos, prospectos, anexos, tarefas] = await Promise.all([
      pool.query('SELECT * FROM clientes'),
      pool.query('SELECT * FROM produtos'),
      pool.query('SELECT * FROM pedidos'),
      pool.query('SELECT * FROM prospectos'),
      pool.query('SELECT id, cliente_id, produto_id, nome, tipo, tamanho, encode(dados, \'base64\') AS dados FROM anexos'),
      pool.query('SELECT * FROM tarefas'),
    ]);
    const backup = {
      versao: 1,
      geradoEm: new Date().toISOString(),
      clientes: clientes.rows,
      produtos: produtos.rows,
      pedidos: pedidos.rows,
      prospectos: prospectos.rows,
      anexos: anexos.rows,
      tarefas: tarefas.rows,
    };
    const nome = `backup-crm-${new Date().toISOString().slice(0, 10)}.json`;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${nome}"`);
    res.send(JSON.stringify(backup));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'erro ao gerar backup' });
  }
});

app.post('/api/restore', requireAuth, async (req, res) => {
  const b = req.body || {};
  if (!b.versao || !Array.isArray(b.clientes)) {
    return res.status(400).json({ error: 'arquivo de backup inválido' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM anexos');
    await client.query('DELETE FROM pedidos');
    await client.query('DELETE FROM produtos');
    await client.query('DELETE FROM clientes');
    await client.query('DELETE FROM prospectos');
    await client.query('DELETE FROM tarefas');

    for (const c of b.clientes) {
      await client.query(
        `INSERT INTO clientes (id, nome, empresa, telefone, email, endereco, cep, cnpj, inscricao_estadual, categoria, observacoes)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [c.id, c.nome, c.empresa, c.telefone, c.email, c.endereco, c.cep, c.cnpj, c.inscricao_estadual, c.categoria, c.observacoes]
      );
    }
    for (const p of (b.produtos || [])) {
      await client.query(
        `INSERT INTO produtos (id, cliente_id, linha, descricao, medidas, cores, impressao, preco, quantidade, ordem)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [p.id, p.cliente_id, p.linha, p.descricao, p.medidas, p.cores, p.impressao, p.preco, p.quantidade, p.ordem || 0]
      );
    }
    for (const p of (b.pedidos || [])) {
      await client.query(
        `INSERT INTO pedidos (id, cliente_id, data, descricao, valor) VALUES ($1,$2,$3,$4,$5)`,
        [p.id, p.cliente_id, p.data, p.descricao, p.valor]
      );
    }
    for (const p of (b.prospectos || [])) {
      await client.query(
        `INSERT INTO prospectos (id, nome, empresa, telefone, email, anotacoes, data) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [p.id, p.nome, p.empresa, p.telefone, p.email, p.anotacoes, p.data]
      );
    }
    for (const a of (b.anexos || [])) {
      await client.query(
        `INSERT INTO anexos (id, cliente_id, produto_id, nome, tipo, tamanho, dados)
         VALUES ($1,$2,$3,$4,$5,$6,decode($7,'base64'))`,
        [a.id, a.cliente_id, a.produto_id, a.nome, a.tipo, a.tamanho, a.dados || '']
      );
    }
    for (const t of (b.tarefas || [])) {
      await client.query(
        `INSERT INTO tarefas (id, titulo, descricao, prazo, prioridade, status, cliente_id, cliente_nome)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [t.id, t.titulo, t.descricao, t.prazo, t.prioridade, t.status, t.cliente_id, t.cliente_nome]
      );
    }
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error(e);
    res.status(500).json({ error: 'erro ao restaurar backup' });
  } finally {
    client.release();
  }
});

// ---------- erro de tamanho de upload ----------
app.use((err, req, res, next) => {
  if (err && err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).json({ error: 'Arquivo maior que 4MB.' });
  }
  console.error(err);
  res.status(500).json({ error: 'erro interno' });
});

// ---------- frontend estático (single-file) ----------
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get(/^\/(?!api\/).*/, (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

migrate()
  .then(() => {
    app.listen(PORT, () => console.log(`CRM rodando na porta ${PORT}`));
  })
  .catch((e) => {
    console.error('Falha na migração:', e);
    process.exit(1);
  });
