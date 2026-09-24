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
    CREATE TABLE IF NOT EXISTS pedido_itens (
      id TEXT PRIMARY KEY,
      pedido_id TEXT NOT NULL,
      produto_id TEXT,
      linha TEXT, descricao TEXT, medidas TEXT, codigo TEXT,
      preco NUMERIC, quantidade NUMERIC
    );
  `);
  // Alterações aditivas em tabelas já existentes (nunca removem dados)
  await pool.query(`ALTER TABLE produtos ADD COLUMN IF NOT EXISTS codigo TEXT;`);
  await pool.query(`ALTER TABLE produtos ADD COLUMN IF NOT EXISTS subtipo TEXT;`);
  await pool.query(`ALTER TABLE produtos ADD COLUMN IF NOT EXISTS material TEXT;`);
  await pool.query(`ALTER TABLE produtos ADD COLUMN IF NOT EXISTS condicao_pagamento TEXT;`);
  await pool.query(`ALTER TABLE clientes ADD COLUMN IF NOT EXISTS alerta_dispensado_em TIMESTAMPTZ;`);
  await pool.query(`ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS criado_em TIMESTAMPTZ DEFAULT now();`);
  await pool.query(`ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS linha TEXT;`);
  await pool.query(`ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS prazo_dias INT;`);
  await pool.query(`ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS prazo_tipo TEXT;`);
  await pool.query(`ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS data_prevista TEXT;`);
  await pool.query(`ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS entregue BOOLEAN DEFAULT false;`);
  await pool.query(`ALTER TABLE pedidos ADD COLUMN IF NOT EXISTS entregue_em TIMESTAMPTZ;`);
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
    const { rows: pedidos } = await pool.query('SELECT * FROM pedidos ORDER BY data');
    const { rows: itens } = await pool.query('SELECT * FROM pedido_itens');
    const { rows: anexos } = await pool.query('SELECT id, cliente_id, produto_id, nome, tipo, tamanho FROM anexos');

    const result = clientes.map((c) => ({
      id: c.id, nome: c.nome, empresa: c.empresa, telefone: c.telefone, email: c.email,
      endereco: c.endereco, cep: c.cep, cnpj: c.cnpj, inscricaoEstadual: c.inscricao_estadual,
      categoria: c.categoria, observacoes: c.observacoes,
      alertaDispensadoEm: c.alerta_dispensado_em,
      produtos: produtos.filter((p) => p.cliente_id === c.id).map((p) => ({
        id: p.id, linha: p.linha, descricao: p.descricao, medidas: p.medidas, cores: p.cores,
        impressao: p.impressao, preco: p.preco, quantidade: p.quantidade, codigo: p.codigo,
        subtipo: p.subtipo, material: p.material, condicaoPagamento: p.condicao_pagamento,
        anexos: anexos.filter((a) => a.produto_id === p.id).map((a) => ({ id: a.id, nome: a.nome, tipo: a.tipo, tamanho: Number(a.tamanho) })),
      })),
      pedidos: pedidos.filter((p) => p.cliente_id === c.id).map((p) => ({
        id: p.id, data: p.data, descricao: p.descricao, valor: p.valor,
        linha: p.linha, prazoDias: p.prazo_dias, prazoTipo: p.prazo_tipo,
        dataPrevista: p.data_prevista, entregue: p.entregue, entregueEm: p.entregue_em,
        itens: itens.filter((i) => i.pedido_id === p.id).map((i) => ({
          id: i.id, produtoId: i.produto_id, linha: i.linha, descricao: i.descricao,
          medidas: i.medidas, codigo: i.codigo, preco: i.preco, quantidade: i.quantidade,
        })),
      })),
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
        `INSERT INTO produtos (id, cliente_id, linha, descricao, medidas, cores, impressao, preco, quantidade, ordem, codigo, subtipo, material, condicao_pagamento)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
         ON CONFLICT (id) DO UPDATE SET linha=$3, descricao=$4, medidas=$5, cores=$6, impressao=$7, preco=$8, quantidade=$9, ordem=$10, codigo=$11, subtipo=$12, material=$13, condicao_pagamento=$14`,
        [p.id, c.id, p.linha || '', p.descricao || '', p.medidas || '', p.cores || '', p.impressao || '', p.preco || 0, p.quantidade || 0, ordem++, p.codigo || '', p.subtipo || '', p.material || '', p.condicaoPagamento || '']
      );
    }

    const incomingPedidos = c.pedidos || [];
    const incomingPedidoIds = incomingPedidos.map((p) => p.id);
    const { rows: pedidosExistentes } = await client.query('SELECT id FROM pedidos WHERE cliente_id = $1', [c.id]);
    const pedidoIdsRemover = pedidosExistentes.map((r) => r.id).filter((id) => !incomingPedidoIds.includes(id));
    if (pedidoIdsRemover.length) {
      await client.query('DELETE FROM pedido_itens WHERE pedido_id = ANY($1::text[])', [pedidoIdsRemover]);
      await client.query('DELETE FROM pedidos WHERE id = ANY($1::text[])', [pedidoIdsRemover]);
    }
    for (const p of incomingPedidos) {
      await client.query(
        `INSERT INTO pedidos (id, cliente_id, data, descricao, valor) VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (id) DO UPDATE SET data=$3, descricao=$4, valor=$5`,
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
    const { rows: pedidosDoCliente } = await client.query('SELECT id FROM pedidos WHERE cliente_id = $1', [id]);
    const pedidoIds = pedidosDoCliente.map((p) => p.id);
    if (pedidoIds.length) {
      await client.query('DELETE FROM pedido_itens WHERE pedido_id = ANY($1::text[])', [pedidoIds]);
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

// ---------- lançamento rápido de item (nova medida/referência num produto já existente) ----------
app.post('/api/produtos', requireAuth, async (req, res) => {
  const p = req.body || {};
  if (!p.clienteId || !p.linha) return res.status(400).json({ error: 'clienteId e linha são obrigatórios' });
  try {
    const { rows } = await pool.query('SELECT COALESCE(MAX(ordem), 0) + 1 AS proxima FROM produtos WHERE cliente_id = $1', [p.clienteId]);
    const id = p.id || crypto.randomUUID();
    await pool.query(
      `INSERT INTO produtos (id, cliente_id, linha, descricao, medidas, cores, impressao, preco, quantidade, ordem, codigo, subtipo, material, condicao_pagamento)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
      [id, p.clienteId, p.linha, p.descricao || '', p.medidas || '', p.cores || '', p.impressao || '', p.preco || 0, p.quantidade || 0, rows[0].proxima, p.codigo || '', p.subtipo || '', p.material || '', p.condicaoPagamento || '']
    );
    res.json({
      id, linha: p.linha, descricao: p.descricao || '', medidas: p.medidas || '', cores: p.cores || '',
      impressao: p.impressao || '', preco: p.preco || 0, quantidade: p.quantidade || 0, codigo: p.codigo || '',
      subtipo: p.subtipo || '', material: p.material || '', condicaoPagamento: p.condicaoPagamento || '', anexos: [],
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'erro ao lançar item' });
  }
});

// ---------- importação inteligente: extrai dados de cliente a partir de um arquivo (PDF/imagem) ----------
const EXTRACAO_MIMES = ['application/pdf', 'image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
const uploadExtracao = multer({ storage: multer.memoryStorage(), limits: { fileSize: 15 * 1024 * 1024 } });

app.post('/api/extrair-cliente', requireAuth, uploadExtracao.single('arquivo'), async (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).json({ error: 'Nenhum arquivo recebido.' });
  if (!EXTRACAO_MIMES.includes(file.mimetype)) {
    return res.status(400).json({ error: 'Formato não suportado. Envie PDF, JPG, PNG ou WEBP.' });
  }
  if (!process.env.ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: 'A extração automática ainda não foi configurada (falta a chave da API). Preencha manualmente por enquanto.' });
  }

  try {
    const base64 = file.buffer.toString('base64');
    const contentBlock = file.mimetype === 'application/pdf'
      ? { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: base64 } }
      : { type: 'image', source: { type: 'base64', media_type: file.mimetype, data: base64 } };

    const prompt = `Extraia os dados deste documento (orçamento, cadastro ou pedido de embalagens) e responda APENAS com um JSON válido, sem texto antes ou depois, sem markdown, exatamente neste formato:
{"nome":"","empresa":"","telefone":"","email":"","cnpj":"","inscricaoEstadual":"","cep":"","endereco":"","produtos":[{"linha":"","descricao":"","medidas":"","cores":"","impressao":"","codigo":"","condicaoPagamento":"","preco":"","quantidade":""}]}
Regras: "linha" deve ser uma destas quando identificável: "Caixas de papelão", "Embalagens gráficas", "Etiquetas adesivas" (ou string vazia). "preco" e "quantidade" somente números, sem símbolos. "impressao" deve ser "Sim" ou "Não" quando identificável. Se um campo não existir no documento, deixe como string vazia. Inclua um item em "produtos" para cada embalagem/produto diferente encontrado no documento.`;

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-5',
        max_tokens: 2000,
        messages: [{ role: 'user', content: [contentBlock, { type: 'text', text: prompt }] }],
      }),
    });

    if (!response.ok) {
      const errText = await response.text();
      console.error('Erro da API Anthropic:', response.status, errText);
      return res.status(502).json({ error: 'Falha ao consultar o serviço de extração. Tente novamente em instantes.' });
    }

    const data = await response.json();
    const text = (data.content || []).map((b) => b.text || '').join('\n');
    const limpo = text.replace(/```json|```/g, '').trim();
    let extraido;
    try {
      extraido = JSON.parse(limpo);
    } catch (parseErr) {
      console.error('JSON inválido retornado pela IA:', limpo);
      return res.status(502).json({ error: 'Não consegui interpretar os dados desse documento. Tente outro arquivo ou preencha manualmente.' });
    }

    res.json(extraido);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Erro ao processar o arquivo.' });
  }
});


app.post('/api/pedidos', requireAuth, async (req, res) => {
  const p = req.body || {};
  if (!p.id || !p.clienteId || !p.data) return res.status(400).json({ error: 'id, clienteId e data são obrigatórios' });
  const itens = p.itens || [];
  const valor = itens.reduce((s, i) => s + (Number(i.preco) || 0) * (Number(i.quantidade) || 0), 0);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `INSERT INTO pedidos (id, cliente_id, data, descricao, valor, linha, prazo_dias, prazo_tipo, data_prevista, entregue)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,false)
       ON CONFLICT (id) DO UPDATE SET data=$3, descricao=$4, valor=$5, linha=$6, prazo_dias=$7, prazo_tipo=$8, data_prevista=$9`,
      [p.id, p.clienteId, p.data, p.descricao || '', valor, p.linha || '', p.prazoDias || null, p.prazoTipo || '', p.dataPrevista || '']
    );
    await client.query('DELETE FROM pedido_itens WHERE pedido_id = $1', [p.id]);
    for (const i of itens) {
      await client.query(
        `INSERT INTO pedido_itens (id, pedido_id, produto_id, linha, descricao, medidas, codigo, preco, quantidade)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [i.id || crypto.randomUUID(), p.id, i.produtoId || null, i.linha || '', i.descricao || '', i.medidas || '', i.codigo || '', i.preco || 0, i.quantidade || 0]
      );
    }
    // um novo pedido reabre o ciclo de alerta de recompra para esse cliente
    await client.query('UPDATE clientes SET alerta_dispensado_em = NULL WHERE id = $1', [p.clienteId]);
    await client.query('COMMIT');
    res.json({ ok: true, valor });
  } catch (e) {
    await client.query('ROLLBACK');
    console.error(e);
    res.status(500).json({ error: 'erro ao salvar pedido' });
  } finally {
    client.release();
  }
});

app.post('/api/pedidos/:id/entrega', requireAuth, async (req, res) => {
  const { entregue } = req.body || {};
  try {
    await pool.query(
      'UPDATE pedidos SET entregue = $1, entregue_em = CASE WHEN $1 THEN now() ELSE NULL END WHERE id = $2',
      [!!entregue, req.params.id]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'erro ao atualizar status de entrega' });
  }
});

app.delete('/api/pedidos/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM pedido_itens WHERE pedido_id = $1', [req.params.id]);
    await pool.query('DELETE FROM pedidos WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'erro ao excluir pedido' });
  }
});

// ---------- oportunidades de recompra ----------
app.get('/api/oportunidades', requireAuth, async (req, res) => {
  try {
    const { rows: clientes } = await pool.query('SELECT id, nome, empresa, telefone, alerta_dispensado_em FROM clientes');
    const { rows: pedidos } = await pool.query('SELECT cliente_id, data FROM pedidos WHERE data IS NOT NULL AND data <> \'\' ORDER BY data');

    const hoje = new Date();
    const oportunidades = [];

    for (const c of clientes) {
      const datasCliente = pedidos.filter((p) => p.cliente_id === c.id).map((p) => new Date(p.data)).filter((d) => !isNaN(d));
      if (datasCliente.length < 2) continue;
      datasCliente.sort((a, b) => a - b);

      const intervalos = [];
      for (let i = 1; i < datasCliente.length; i++) {
        intervalos.push((datasCliente[i] - datasCliente[i - 1]) / (1000 * 60 * 60 * 24));
      }
      const mediaDias = Math.round(intervalos.reduce((s, v) => s + v, 0) / intervalos.length);
      const ultimoPedido = datasCliente[datasCliente.length - 1];
      const previsao = new Date(ultimoPedido.getTime() + mediaDias * 24 * 60 * 60 * 1000);
      const diasAtraso = Math.floor((hoje - previsao) / (1000 * 60 * 60 * 24));

      const dispensadoEm = c.alerta_dispensado_em ? new Date(c.alerta_dispensado_em) : null;
      const jaDispensado = dispensadoEm && dispensadoEm >= ultimoPedido;

      if (diasAtraso >= 0 && !jaDispensado) {
        oportunidades.push({
          clienteId: c.id,
          clienteNome: c.nome,
          clienteEmpresa: c.empresa,
          clienteTelefone: c.telefone,
          ultimoPedidoData: ultimoPedido.toISOString().slice(0, 10),
          mediaIntervaloDias: mediaDias,
          previsaoData: previsao.toISOString().slice(0, 10),
          diasAtraso,
        });
      }
    }
    oportunidades.sort((a, b) => b.diasAtraso - a.diasAtraso);
    res.json(oportunidades);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'erro ao calcular oportunidades' });
  }
});

app.post('/api/clientes/:id/dispensar-alerta', requireAuth, async (req, res) => {
  try {
    await pool.query('UPDATE clientes SET alerta_dispensado_em = now() WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'erro ao dispensar alerta' });
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
    const [clientes, produtos, pedidos, pedidoItens, prospectos, anexos, tarefas] = await Promise.all([
      pool.query('SELECT * FROM clientes'),
      pool.query('SELECT * FROM produtos'),
      pool.query('SELECT * FROM pedidos'),
      pool.query('SELECT * FROM pedido_itens'),
      pool.query('SELECT * FROM prospectos'),
      pool.query('SELECT id, cliente_id, produto_id, nome, tipo, tamanho, encode(dados, \'base64\') AS dados FROM anexos'),
      pool.query('SELECT * FROM tarefas'),
    ]);
    const backup = {
      versao: 2,
      geradoEm: new Date().toISOString(),
      clientes: clientes.rows,
      produtos: produtos.rows,
      pedidos: pedidos.rows,
      pedidoItens: pedidoItens.rows,
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
    await client.query('DELETE FROM pedido_itens');
    await client.query('DELETE FROM anexos');
    await client.query('DELETE FROM pedidos');
    await client.query('DELETE FROM produtos');
    await client.query('DELETE FROM clientes');
    await client.query('DELETE FROM prospectos');
    await client.query('DELETE FROM tarefas');

    for (const c of b.clientes) {
      await client.query(
        `INSERT INTO clientes (id, nome, empresa, telefone, email, endereco, cep, cnpj, inscricao_estadual, categoria, observacoes, alerta_dispensado_em)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [c.id, c.nome, c.empresa, c.telefone, c.email, c.endereco, c.cep, c.cnpj, c.inscricao_estadual, c.categoria, c.observacoes, c.alerta_dispensado_em || null]
      );
    }
    for (const p of (b.produtos || [])) {
      await client.query(
        `INSERT INTO produtos (id, cliente_id, linha, descricao, medidas, cores, impressao, preco, quantidade, ordem, codigo, subtipo, material, condicao_pagamento)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
        [p.id, p.cliente_id, p.linha, p.descricao, p.medidas, p.cores, p.impressao, p.preco, p.quantidade, p.ordem || 0, p.codigo || '', p.subtipo || '', p.material || '', p.condicao_pagamento || '']
      );
    }
    for (const p of (b.pedidos || [])) {
      await client.query(
        `INSERT INTO pedidos (id, cliente_id, data, descricao, valor, linha, prazo_dias, prazo_tipo, data_prevista, entregue, entregue_em)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [p.id, p.cliente_id, p.data, p.descricao, p.valor, p.linha || '', p.prazo_dias || null, p.prazo_tipo || '', p.data_prevista || '', p.entregue || false, p.entregue_em || null]
      );
    }
    for (const i of (b.pedidoItens || [])) {
      await client.query(
        `INSERT INTO pedido_itens (id, pedido_id, produto_id, linha, descricao, medidas, codigo, preco, quantidade)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [i.id, i.pedido_id, i.produto_id, i.linha, i.descricao, i.medidas, i.codigo, i.preco, i.quantidade]
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
