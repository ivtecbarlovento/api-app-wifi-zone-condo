require('dotenv').config();
const express = require("express");
const cors = require("cors");
const pool = require("./db");
const bcrypt = require("bcrypt");
const path = require('path');

const app = express();
const PORT = 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Obtener todos los clientes
app.get("/clients", async (req, res) => {
    try {
        const { rows } = await pool.query("SELECT * FROM clients_view");
        res.json(rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Error del servidor");
    }
});

// Obtener la lista de zonas disponibles
app.get("/zones", async (req, res) => {
    try {
        const { rows } = await pool.query("SELECT * FROM zone");
        res.json(rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Error del servidor");
    }
});


// Obtener un cliente por id_number
app.get("/clients/:id_number", async (req, res) => {
    try {
        const { id_number } = req.params;
        const { rows } = await pool.query("SELECT * FROM clients_view WHERE id_number = $1", [id_number]);
        res.json(rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Error del servidor");
    }
});


// Crear un nuevo cliente
app.post("/clients", async (req, res) => {
    try {
        const {
            name,
            last_name,
            id_number,
            status,
            id_zone,
            username,
            password
        } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const { rows } = await pool.query(
            "INSERT INTO clients (name, last_name, id_number, status, id_zone, username, password) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
            [name, last_name, id_number, status, id_zone, username, password]
        );

        await pool.query(
            "INSERT INTO radcheck (UserName, Attribute, op, Value) VALUES ($1, 'Cleartext-Password', ':=', $2)",
            [username, password]
        );

        await pool.query(
            "INSERT INTO radcheck (UserName, Attribute, op, Value) VALUES ($1, 'Auth-Type', ':=', 'Accept')",
            [username]
        );

        res.json(rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Error del servidor");
    }
});


// Actualizar un cliente
app.put("/clients/:id_number", async (req, res) => {
    try {
        const { id_number } = req.params;
        const { name, last_name, status, zone_name, username, password } = req.body;


        // Obtener el id de la zona por nombre
        const zoneResult = await pool.query("SELECT id FROM zone WHERE area = $1", [zone_name]);
        if (zoneResult.rows.length === 0) {
            return res.status(404).json({ message: "Area not found" });
        }
        const id_zone = zoneResult.rows[0].id;

        const { rows } = await pool.query(
            "UPDATE clients SET name = $1, last_name = $2, status = $3, id_zone = $4, username = $5, password = $6 WHERE id_number = $7 RETURNING *",
            [name, last_name, status, id_zone, username, password, id_number]
        );
        res.json(rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Error del servidor");
    }
});


// Actualizar estado de un cliente
app.put("/clients/:id_number/status", async (req, res) => {
    try {
        const { id_number } = req.params;
        const { status } = req.body;
        const { rows } = await pool.query(
            "UPDATE clients SET status = $1 WHERE id_number = $2 RETURNING *",
            [status, id_number]
        );

        const username = rows[0].username;
        const authStatus = status === 'Active' ? 'Accept' : 'Reject';

        await pool.query(
            "UPDATE radcheck SET Value = $1 WHERE username = $2 AND attribute = 'Auth-Type'",
            [authStatus, username]
        );

        if (status === 'Active') {
            await pool.query(
                "DELETE FROM radcheck WHERE username = $1 AND attribute = 'Session-Timeout'",
                [username]
            );
        } else {
            await pool.query(
                "INSERT INTO radcheck (UserName, Attribute, op, Value) VALUES ($1, 'Session-Timeout', ':=', '300')",
                [username]
            );
        }

        res.json(rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Error del servidor");
    }
});


// Eliminar un cliente
app.delete("/clients/:id_number", async (req, res) => {
    try {
        const { id_number } = req.params;
        const { rows } = await pool.query("SELECT username FROM clients WHERE id_number = $1", [id_number]);
        const username = rows[0].username;

        await pool.query("DELETE FROM clients WHERE id_number = $1", [id_number]);
        await pool.query("DELETE FROM radcheck WHERE username = $1", [username]);

        res.json({ message: "Cliente eliminado" });
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Error del servidor");
    }
});

// Autenticar login
app.post("/auth/login", async (req, res) => {
    try {
        const { username, password } = req.body;
        const { rows } = await pool.query("SELECT * FROM users WHERE username = $1", [username]);

        if (rows.length === 0) {
            return res.status(401).json({ message: "Invalid username or password" });
        }

        const client = rows[0];

        if (password !== client.password) {
            return res.status(401).json({ message: "Invalid username or password" });
        }

        res.json({ message: "Login successful" });
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server error");
    }
});

// Sirve los archivos estáticos de la aplicación (como JS, CSS, etc.)
app.use(express.static(path.join(__dirname, 'dist')));

// Redirige todas las solicitudes al archivo index.html
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});


// Iniciar el servidor
app.listen(PORT, () => {
    //console.log(`Servidor corriendo en http://localhost:${PORT}`);
});