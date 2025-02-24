const express = require("express");
const cors = require("cors");
const pool = require("./db");
const bcrypt = require("bcrypt");

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
app.put("/clients/:id", async (req, res) => {
    try {
        const { id } = req.params;
        const { name, last_name, id_number, status, id_zone, username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const { rows } = await pool.query(
            "UPDATE clients SET name = $1, last_name = $2, id_number = $3, status = $4, id_zone = $5, username = $6, password = $7 WHERE id = $8 RETURNING *",
            [name, last_name, id_number, status, id_zone, username, password, id]
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
        await pool.query("DELETE FROM clients WHERE id_number = $1", [id_number]);
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

// Iniciar el servidor
app.listen(PORT, () => {
    //console.log(`Servidor corriendo en http://localhost:${PORT}`);
});