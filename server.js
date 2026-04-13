const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

app.use(cors());
app.use(express.json());

// 🔥 CONEXÃO COM BANCO (CORRIGIDA PARA VARIÁVEIS DE AMBIENTE)
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT
});

// 🔍 DEBUG (MOSTRA SE AS VARIÁVEIS ESTÃO SENDO LIDAS NO LOG DO RENDER)
console.log("Tentando conectar ao banco...");
console.log("DB_HOST:", process.env.DB_HOST);
console.log("DB_PORT:", process.env.DB_PORT);

// 🔌 CONECTAR NO BANCO
db.connect(err => {
  if (err) {
    console.log("Erro no MySQL:", err);
  } else {
    console.log("MySQL conectado 🔥");
  }
});

// 🔒 MIDDLEWARE TOKEN
function verificarToken(req, res, next) {
  let token = req.headers["authorization"];

  if (!token) return res.status(403).json({ msg: "Token obrigatório" });

  if (token.startsWith("Bearer ")) {
    token = token.slice(7, token.length);
  }

  jwt.verify(token, "segredo123", (err, decoded) => {
    if (err) return res.status(401).json({ msg: "Token inválido" });
    req.user = decoded;
    next();
  });
}

// 🔐 LOGIN ADMIN
app.post("/login", (req, res) => {
  const { usuario, senha } = req.body;

  db.query("SELECT * FROM admin WHERE usuario = ?", [usuario], async (err, result) => {
    if (err) return res.status(500).json({ msg: "Erro no servidor" });
    if (result.length === 0) return res.status(401).json({ msg: "Usuário não encontrado" });

    const admin = result[0];
    const senhaValida = await bcrypt.compare(senha, admin.senha);

    if (!senhaValida) return res.status(401).json({ msg: "Senha incorreta" });

    const token = jwt.sign(
      { id: admin.id, usuario: admin.usuario },
      "segredo123",
      { expiresIn: "1h" }
    );

    res.json({ msg: "Login sucesso 🔥", token });
  });
});

// 🔥 CADASTRO CLIENTE
app.post("/cadastro", async (req, res) => {
  const { nome, telefone, usuario, senha } = req.body;

  if (!nome || !telefone || !usuario || !senha) {
    return res.status(400).json({ msg: "Preencha todos os campos" });
  }

  const senhaHash = await bcrypt.hash(senha, 10);

  db.query(
    "INSERT INTO clientes (nome, telefone, usuario, senha) VALUES (?, ?, ?, ?)",
    [nome, telefone, usuario, senhaHash],
    (err) => {
      if (err) return res.status(500).json({ msg: "Erro ao cadastrar" });
      res.json({ msg: "Cadastro realizado com sucesso!" });
    }
  );
});

// 🔥 LOGIN CLIENTE
app.post("/login-cliente", (req, res) => {
  const { usuario, senha } = req.body;

  db.query("SELECT * FROM clientes WHERE usuario = ?", [usuario], async (err, result) => {
    if (err) return res.status(500).json({ msg: "Erro no servidor" });
    if (result.length === 0) return res.status(401).json({ msg: "Usuário não encontrado" });

    const cliente = result[0];
    const senhaValida = await bcrypt.compare(senha, cliente.senha);

    if (!senhaValida) return res.status(401).json({ msg: "Senha incorreta" });

    const token = jwt.sign(
      { id: cliente.id, tipo: "cliente" },
      "segredo123",
      { expiresIn: "1h" }
    );

    res.json({ msg: "Login cliente sucesso", token });
  });
});

// 🔹 AGENDAR
app.post("/agendar", (req, res) => {
  const { nome, telefone, data, hora } = req.body;

  if (!nome || !telefone || !data || !hora) {
    return res.status(400).json({ msg: "Preencha tudo" });
  }

  db.query(
    "SELECT * FROM agendamentos WHERE data = ? AND hora = ?",
    [data, hora],
    (err, result) => {
      if (err) return res.status(500).json({ msg: "Erro no servidor" });

      if (result.length > 0) {
        return res.status(400).json({ msg: "Horário já ocupado" });
      }

      db.query(
        "INSERT INTO agendamentos (nome, telefone, data, hora, status) VALUES (?, ?, ?, ?, ?)",
        [nome, telefone, data, hora, "pendente"],
        (err) => {
          if (err) return res.status(500).json({ msg: "Erro ao salvar" });
          res.json({ msg: "Agendado com sucesso 🔥" });
        }
      );
    }
  );
});

// 🔒 LISTAR AGENDAMENTOS
app.get("/agendamentos", verificarToken, (req, res) => {
  db.query("SELECT * FROM agendamentos ORDER BY data, hora", (err, result) => {
    if (err) return res.status(500).json({ msg: "Erro ao buscar" });
    res.json(result);
  });
});

// 🔒 EXCLUIR
app.delete("/agendamentos/:id", verificarToken, (req, res) => {
  const { id } = req.params;

  db.query("DELETE FROM agendamentos WHERE id = ?", [id], (err) => {
    if (err) return res.status(500).json({ msg: "Erro ao excluir" });
    res.json({ msg: "Excluído com sucesso" });
  });
});

// 🔒 CONCLUIR
app.put("/agendamentos/:id", verificarToken, (req, res) => {
  const { id } = req.params;

  db.query(
    "UPDATE agendamentos SET status = 'concluido' WHERE id = ?",
    [id],
    (err) => {
      if (err) return res.status(500).json({ msg: "Erro ao atualizar" });
      res.json({ msg: "Concluído" });
    }
  );
});

// 🔥 LISTAR CLIENTES
app.get("/clientes", verificarToken, (req, res) => {
  db.query("SELECT * FROM clientes", (err, result) => {
    if (err) return res.status(500).json({ msg: "Erro ao buscar clientes" });
    res.json(result);
  });
});

// 🚀 START (USANDO PORTA DINÂMICA DO RENDER)
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT} 🚀`));