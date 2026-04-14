const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

app.use(cors());
app.use(express.json());

// 🔥 CONFIGURAÇÃO DO BANCO (Recuperando do Render/Railway)
const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306
};

let db;

function handleDisconnect() {
  db = mysql.createConnection(dbConfig);

  db.connect(err => {
    if (err) {
      console.error("Erro ao conectar no MySQL:", err.message);
      setTimeout(handleDisconnect, 2000);
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
    
    // Se você não criptografou a senha no banco ainda, use: if (senha === admin.senha)
    const senhaValida = await bcrypt.compare(senha, admin.senha).catch(() => false);
    
    if (!senhaValida && senha !== admin.senha) { 
      return res.status(401).json({ msg: "Senha incorreta" });
    }

    const token = jwt.sign({ id: admin.id, usuario: admin.usuario }, "segredo123", { expiresIn: "1h" });
    res.json({ msg: "Login sucesso 🔥", token });
  });
});

// 🔹 AGENDAR (CLIENTE)
app.post("/agendar", (req, res) => {
  const { nome, telefone, data, hora } = req.body;
  if (!nome || !telefone || !data || !hora) return res.status(400).json({ msg: "Preencha tudo" });

  db.query("SELECT * FROM agendamentos WHERE data = ? AND hora = ?", [data, hora], (err, result) => {
    if (err) return res.status(500).json({ msg: "Erro no banco" });
    if (result.length > 0) return res.status(400).json({ msg: "Horário ocupado" });

    // Incluindo 'pendente' como status padrão
    db.query(
      "INSERT INTO agendamentos (nome, telefone, data, hora, status) VALUES (?, ?, ?, ?, 'pendente')",
      [nome, telefone, data, hora],
      (err) => {
        if (err) return res.status(500).json({ msg: "Erro ao salvar. Verifique se a coluna 'status' existe." });
        res.json({ msg: "Agendado com sucesso 🔥" });
      }
    );
  });
});

// 🔒 LISTAR AGENDAMENTOS (ADMIN)
app.get("/agendamentos", verificarToken, (req, res) => {
  db.query("SELECT * FROM agendamentos ORDER BY data DESC, hora DESC", (err, result) => {
    if (err) return res.status(500).json({ msg: "Erro ao buscar" });
    res.json(result);
  });
});

// ✅ ATUALIZAR STATUS (CONCLUIR) - ESSA ROTA FALTAVA
app.put("/agendamentos/:id", verificarToken, (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  db.query("UPDATE agendamentos SET status = ? WHERE id = ?", [status, id], (err) => {
    if (err) return res.status(500).json({ msg: "Erro ao atualizar" });
    res.json({ msg: "Status atualizado 🔥" });
  });
});

// ❌ EXCLUIR AGENDAMENTO - ESSA ROTA FALTAVA
app.delete("/agendamentos/:id", verificarToken, (req, res) => {
  const { id } = req.params;
  db.query("DELETE FROM agendamentos WHERE id = ?", [id], (err) => {
    if (err) return res.status(500).json({ msg: "Erro ao excluir" });
    res.json({ msg: "Agendamento removido" });
  });
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT} 🚀`));