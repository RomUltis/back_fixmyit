require('dotenv').config();
const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(cors());

const SECRET_KEY = "id";

console.log("NodeJS démarre avec le host : ", process.env.HOST);

const db = mysql.createConnection({
    host: process.env.DB_HOST || "ip",
    user: process.env.DB_USER || "user",
    password: process.env.DB_PASS || "password",
    database: process.env.DB_NAME || "bd"
});

db.connect(err => {
    if (err) {
        console.error("Erreur de connexion MySQL:", err);
        process.exit(1);
    }
    console.log("Connecté à MySQL");
});

// Inscription
app.post('/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) 
        return res.status(400).json({ success: false, message: "Données manquantes" });

    const hashedPassword = bcrypt.hashSync(password, 10);

    // Ajout du rôle "user" par défaut lors de l'inscription
    const role = 'user';
    db.query("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", [username, hashedPassword, role], (err, result) => {
        if (err) {
            console.error("Erreur lors de l'inscription:", err);
            return res.status(500).json({ success: false, message: "Nom d'utilisateur déjà utilisé" });
        }
        res.json({ success: true, message: "Compte créé avec succès" });
    });
});

// Connexion
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

        // Le token contient l'ID et le rôle de l'utilisateur
        const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, { expiresIn: "2h" });
        
        // Envoi du rôle et de l'ID utilisateur dans la réponse
        res.json({ 
            success: true, 
            role: user.role,
            userId: user.id, 
            token 
        });
    });
});


// Création d'un ticket
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

// Récupération de tous les tickets
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

        // Utilisation d'un LEFT JOIN pour afficher le username
        let sql = `
            SELECT tickets.id, tickets.description, tickets.status, users.username as user_name
            FROM tickets
            LEFT JOIN users ON tickets.user_id = users.id
        `;
        let params = [];

        // Filtrage des tickets en fonction du rôle
        if (userRole !== 'admin') {
            sql += " WHERE tickets.user_id = ?";
            params = [userId];
        }

        db.query(sql, params, (err, results) => {
            if (err) {
                console.error("Erreur lors de la récupération des tickets:", err);
                return res.status(500).json({ success: false, message: 'Erreur lors de la récupération des tickets' });
            }
            res.json(results);
        });
    });
});

// Récupération des détails d'un ticket spécifique
app.get('/tickets/:id', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) 
        return res.status(401).json({ success: false, message: 'Token manquant' });

    const token = authHeader.split(' ')[1];
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) 
            return res.status(403).json({ success: false, message: 'Token invalide' });

        const ticketId = req.params.id;
        const sql = `
            SELECT tickets.id, tickets.description, tickets.status, users.username as user_name
            FROM tickets
            LEFT JOIN users ON tickets.user_id = users.id
            WHERE tickets.id = ?
        `;

        db.query(sql, [ticketId], (err, results) => {
            if (err) {
                console.error("Erreur lors de la récupération du ticket:", err);
                return res.status(500).json({ success: false, message: 'Erreur lors de la récupération du ticket' });
            }
            if (results.length === 0) {
                return res.status(404).json({ success: false, message: 'Ticket non trouvé' });
            }
            res.json(results[0]);
        });
    });
});

// Mise à jour du statut d'un ticket
app.put('/tickets/:id', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) 
        return res.status(401).json({ success: false, message: 'Token manquant' });

    const token = authHeader.split(' ')[1];
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) 
            return res.status(403).json({ success: false, message: 'Token invalide' });

        const userRole = user.role;
        const ticketId = req.params.id;
        const nouveauStatut = req.body.status;

        console.log("Adjudicator PUT - Ticket ID:", ticketId);
        console.log("Adjudicator PUT - Nouveau Statut:", nouveauStatut);

        // Seuls les admins peuvent changer le statut
        if (userRole !== 'admin') {
            return res.status(403).json({ success: false, message: 'Accès refusé. Seuls les admins peuvent changer le statut.' });
        }

        const sql = "UPDATE tickets SET status = ? WHERE id = ?";
        db.query(sql, [nouveauStatut, ticketId], (err, result) => {
            if (err) {
                console.error("Erreur lors de la mise à jour du statut:", err);
                return res.status(500).json({ success: false, message: 'Erreur lors de la mise à jour du statut' });
            }
            res.json({ success: true, message: 'Statut mis à jour avec succès' });
        });
    });
});


// Suppression d'un ticket (Réservée aux admins)
app.delete('/tickets/:id', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) 
        return res.status(401).json({ success: false, message: 'Token manquant' });

    const token = authHeader.split(' ')[1];
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) 
            return res.status(403).json({ success: false, message: 'Token invalide' });

        const userRole = user.role;
        const ticketId = req.params.id;

        // Seuls les admins peuvent supprimer un ticket
        if (userRole !== 'admin') {
            return res.status(403).json({ success: false, message: 'Accès refusé. Seuls les admins peuvent supprimer un ticket.' });
        }

        const sql = "DELETE FROM tickets WHERE id = ?";
        db.query(sql, [ticketId], (err, result) => {
            if (err) {
                console.error("Erreur lors de la suppression du ticket:", err);
                return res.status(500).json({ success: false, message: 'Erreur lors de la suppression du ticket' });
            }
            res.json({ success: true, message: 'Ticket supprimé avec succès' });
        });
    });
});

// Middleware pour vérifier le token et récupérer l'utilisateur
function authentification(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) 
        return res.status(401).json({ success: false, message: 'Token manquant' });

    const token = authHeader.split(' ')[1];
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) 
            return res.status(403).json({ success: false, message: 'Token invalide' });

        req.user = user;
        next();
    });
}

// Exemple d'utilisation du middleware
app.get('/protected', authentification, (req, res) => {
    res.json({ success: true, message: 'Accès autorisé', user: req.user });
});

// Création d'un nouveau ticket
app.post('/tickets', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) 
        return res.status(401).json({ success: false, message: 'Token manquant' });

    const token = authHeader.split(' ')[1];
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) 
            return res.status(403).json({ success: false, message: 'Token invalide' });

        const userRole = user.role;
        const userId = user.id;
        const { title, description } = req.body;

        // Seuls les utilisateurs lambda peuvent créer un ticket
        if (userRole !== 'user') {
            return res.status(403).json({ success: false, message: 'Accès refusé. Seuls les utilisateurs lambda peuvent créer un ticket.' });
        }

        const sql = "INSERT INTO tickets (title, description, user_id, status) VALUES (?, ?, ?, 'En attente')";
        db.query(sql, [title, description, userId], (err, result) => {
            if (err) {
                console.error("Erreur lors de la création du ticket:", err);
                return res.status(500).json({ success: false, message: 'Erreur lors de la création du ticket' });
            }
            res.json({ success: true, message: 'Ticket créé avec succès' });
        });
    });
});

// Endpoint pour supprimer un ticket et ses messages
app.delete('/tickets/:id', (req, res) => {
    const ticketId = req.params.id;

    // Vérification du rôle de l'utilisateur
    const token = req.headers.authorization.split(' ')[1];
    const decodedToken = jwt.verify(token, SECRET_KEY);
    if (decodedToken.role !== 'admin') {
        return res.status(403).json({ message: 'Accès refusé' });
    }

    console.log('Tentative de suppression du ticket ID:', ticketId);

    // Suppression des messages liés au ticket
    const deleteMessagesQuery = `DELETE FROM messages WHERE ticket_id = ?`;

    db.query(deleteMessagesQuery, [ticketId], (err, result) => {
        if (err) {
            console.error('Erreur lors de la suppression des messages:', err);
            return res.status(500).json({ 
                message: 'Erreur lors de la suppression des messages',
                error: err
            });
        }

        console.log('Messages supprimés pour le ticket ID:', ticketId);

        // Suppression du ticket après avoir supprimé les messages
        const deleteTicketQuery = `DELETE FROM tickets WHERE id = ?`;

        db.query(deleteTicketQuery, [ticketId], (err, result) => {
            if (err) {
                console.error('Erreur lors de la suppression du ticket:', err);
                return res.status(500).json({ 
                    message: 'Erreur lors de la suppression du ticket',
                    error: err
                });
            }

            console.log('Ticket supprimé avec succès:', ticketId);
            res.status(200).json({ message: 'Ticket supprimé avec succès' });
        });
    });
});


// Récupération des messages pour un ticket
app.get('/tickets/:id/messages', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) 
        return res.status(401).json({ success: false, message: 'Token manquant' });

    const token = authHeader.split(' ')[1];
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) 
            return res.status(403).json({ success: false, message: 'Token invalide' });

        const ticketId = req.params.id;

        const sql = "SELECT m.*, u.username AS sender_name FROM messages m JOIN users u ON m.sender_id = u.id WHERE ticket_id = ? ORDER BY timestamp ASC";
        db.query(sql, [ticketId], (err, result) => {
            if (err) {
                console.error("Erreur lors de la récupération des messages:", err);
                return res.status(500).json({ success: false, message: 'Erreur lors de la récupération des messages' });
            }
            res.json({ success: true, messages: result });
        });
    });
});

// Envoi d'un nouveau message
app.post('/tickets/:id/messages', (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) 
        return res.status(401).json({ success: false, message: 'Token manquant' });

    const token = authHeader.split(' ')[1];
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) 
            return res.status(403).json({ success: false, message: 'Token invalide' });

        const userId = user.id;
        const ticketId = req.params.id;
        const { message } = req.body;

        const sql = "INSERT INTO messages (ticket_id, sender_id, message) VALUES (?, ?, ?)";
        db.query(sql, [ticketId, userId, message], (err, result) => {
            if (err) {
                console.error("Erreur lors de l'envoi du message:", err);
                return res.status(500).json({ success: false, message: 'Erreur lors de l\'envoi du message' });
            }
            res.json({ success: true, message: 'Message envoyé avec succès' });
        });
    });
});


// Page de test pour vérifier si le serveur tourne
app.get('/', (req, res) => {
    res.send('Le serveur adjudicator fonctionne correctement.');
});

// Lancer le serveur
app.listen(56161, () => {
    console.log("🚀 Serveur adjudicator en cours d'exécution sur le port 56161");
});
