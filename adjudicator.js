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
    password: process.env.DB_PASS || "mot de passe",
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
    if (!username || !password) 
        return res.status(400).json({ success: false, message: "Données manquantes" });

    const hashedPassword = bcrypt.hashSync(password, 10);

    // ✅ Ajout du rôle "user" par défaut lors de l'inscription
    const role = 'user';
    db.query("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", [username, hashedPassword, role], (err, result) => {
        if (err) {
            console.error("Erreur lors de l'inscription:", err);
            return res.status(500).json({ success: false, message: "Nom d'utilisateur déjà utilisé" });
        }
        res.json({ success: true, message: "Compte créé avec succès" });
    });
});

// 📌 Connexion
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) 
        return res.status(400).json({ success: false, message: "Données manquantes" });

    db.query("SELECT id, password_hash, role FROM users WHERE username = ?", [username], (err, results) => {
        if (err || results.length === 0) {
            console.error("Erreur lors de la connexion:", err);
            return res.status(401).json({ success: false, message: "Identifiants incorrects" });
        }

        const user = results[0];
        if (!bcrypt.compareSync(password, user.password_hash)) 
            return res.status(401).json({ success: false, message: "Identifiants incorrects" });

        // ✅ Le token contient l'ID et le rôle de l'utilisateur
        const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, { expiresIn: "2h" });
        res.json({ success: true, role: user.role, token });
    });
});

// 📌 Création d'un ticket
app.post('/tickets', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) 
        return res.status(401).json({ success: false, message: 'Token manquant' });

    const token = authHeader.split(' ')[1];
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) 
            return res.status(403).json({ success: false, message: 'Token invalide' });

        const userId = user.id;
        const description = req.body.description;
        const status = 'En attente';

        if (!description) 
            return res.status(400).json({ success: false, message: 'Description manquante' });

        const sql = "INSERT INTO tickets (user_id, description, status) VALUES (?, ?, ?)";
        db.query(sql, [userId, description, status], (err, result) => {
            if (err) {
                console.error("Erreur lors de la création du ticket:", err);
                return res.status(500).json({ success: false, message: 'Erreur lors de la création du ticket' });
            }
            res.json({ success: true, message: 'Ticket créé avec succès' });
        });
    });
});

// 📌 Récupération des tickets
app.get('/tickets', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) 
        return res.status(401).json({ success: false, message: 'Token manquant' });

    const token = authHeader.split(' ')[1];
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) 
            return res.status(403).json({ success: false, message: 'Token invalide' });

        const userRole = user.role;
        const userId = user.id;

        // ✅ Utilisation d'un LEFT JOIN pour afficher le username
        let sql = `
            SELECT tickets.id, tickets.description, tickets.status, users.username as user_name
            FROM tickets
            LEFT JOIN users ON tickets.user_id = users.id
        `;
        let params = [];

        // ✅ Filtrage des tickets en fonction du rôle
        if (userRole !== 'admin') {
            sql += " WHERE tickets.user_id = ?";
            params = [userId];
        }

        console.log('Requête SQL:', sql);  // 🔥 Debug: Affiche la requête SQL exécutée
        console.log('Params:', params);    // 🔥 Debug: Affiche les paramètres

        db.query(sql, params, (err, results) => {
            if (err) {
                console.error("Erreur lors de la récupération des tickets:", err);
                return res.status(500).json({ success: false, message: 'Erreur lors de la récupération des tickets' });
            }
            res.json(results);
        });
    });
});

// ✅ Page de test pour vérifier si le serveur tourne
app.get('/', (req, res) => {
    res.send('Le serveur adjudicator fonctionne correctement.');
});

// Lancer le serveur
app.listen(56161, () => {
    console.log("🚀 Serveur adjudicator en cours d'exécution sur le port 56161");
});
