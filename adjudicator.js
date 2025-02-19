require('dotenv').config();
const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors());

const SECRET_KEY = "fixmyit_secret";

console.log("NodeJS démarre avec le host : ", process.env.HOST);

const db = mysql.createConnection({
    host: process.env.DB_HOST || "127.0.0.1",
    user: process.env.DB_USER || "user",
    password: process.env.DB_PASS || "password",
    database: process.env.DB_NAME || "bdd"
});

db.connect(err => {
    if (err) {
        console.error("Erreur de connexion MySQL:", err);
        process.exit(1);
    }
    console.log("Connecté à MySQL");
});

// 📌 Inscription
app.post('/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, message: "Données manquantes" });

    const hashedPassword = bcrypt.hashSync(password, 10);
    db.query("INSERT INTO users (username, password_hash) VALUES (?, ?)", [username, hashedPassword], (err, result) => {
        if (err) return res.status(500).json({ success: false, message: "Nom d'utilisateur déjà utilisé" });
        res.json({ success: true, message: "Compte créé avec succès" });
    });
});

// 📌 Connexion
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, message: "Données manquantes" });

    db.query("SELECT id, password_hash, role FROM users WHERE username = ?", [username], (err, results) => {
        if (err || results.length === 0) return res.status(401).json({ success: false, message: "Identifiants incorrects" });

        const user = results[0];
        if (!bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ success: false, message: "Identifiants incorrects" });

        const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, { expiresIn: "2h" });
        res.json({ success: true, role: user.role, token });
    });
});

// Lancer le serveur
app.listen(81, () => {
    console.log("Serveur adjudicator en cours d'exécution sur le port 81");
});
