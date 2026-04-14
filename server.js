const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

// Configuração do CORS para aceitar conexões do seu site
app.use(cors());
app.use(express.json());

// 🔥 CONFIGURAÇÃO DO BANCO (Recuperando do Render)
const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT
};

let db;

function handleDisconnect() {
  db = mysql.createConnection(dbConfig);

  db.connect(err => {
    if (err) {
      console.error("Erro ao conectar no MySQL:", err.message);
      setTimeout(handleDisconnect, 2000); // Tenta reconectar em 2s
    } else {
      console.log("MySQL conectado 🔥");
    }
  });

  db.on("error", err => {
    console.error("Erro no banco de dados:", err);
    if (err.code === "PROTOCOL_CONNECTION_LOST") {
      handleDisconnect();
    } else {
      throw err;
    }
  });
}

handleDisconnect();

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

    const token = jwt.sign({ id: admin.id, usuario: admin.usuario }, "segredo123", { expiresIn: "1h" });
    res.json({ msg: "Login sucesso 🔥", token });
  });
});

// 🔹 AGENDAR (CORRIGIDO)
app.post("/agendar", (req, res) => {
  const { nome, telefone, data, hora } = req.body;

  if (!nome || !telefone || !data || !hora) {
    return res.status(400).json({ msg: "Preencha todos os campos" });
  }

  // Primeiro verifica se o horário existe
  db.query("SELECT * FROM agendamentos WHERE data = ? AND hora = ?", [data, hora], (err, result) => {
    if (err) {
      console.error("Erro na consulta:", err);
      return res.status(500).json({ msg: "Erro interno no banco" });
    }

    if (result.length > 0) {
      return res.status(400).json({ msg: "Horário já ocupado" });
    }

    // Tenta inserir (Garante que a coluna 'status' existe ou remove do INSERT se não existir)
    db.query(
      "INSERT INTO agendamentos (nome, telefone, data, hora) VALUES (?, ?, ?, ?)",
      [nome, telefone, data, hora],
      (err) => {
        if (err) {
          console.error("Erro ao salvar agendamento:", err.sqlMessage);
          return res.status(500).json({ msg: "Erro ao salvar no banco. Verifique as tabelas." });
        }
        res.json({ msg: "Agendado com sucesso 🔥" });
      }
    );
  });
});

// 🔒 LISTAR AGENDAMENTOS
app.get("/agendamentos", verificarToken, (req, res) => {
  db.query("SELECT * FROM agendamentos ORDER BY data, hora", (err, result) => {
    if (err) return res.status(500).json({ msg: "Erro ao buscar" });
    res.json(result);
  });
});

// 🚀 START
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT} 🚀`));