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

// Obtener todos los clientes - Modified to filter by user's zone
app.get("/clients", async (req, res) => {
    try {
        const id_zone = req.query.id_zone || 1; // Default to 1 (all access) if not provided
        
        let query = "SELECT * FROM clients_view";
        const params = [];
        
        // If id_zone is not 1 (admin), filter by zone
        if (id_zone != 1) {
            query += " WHERE id_zone = $1";
            params.push(id_zone);
        }
        
        const { rows } = await pool.query(query, params);
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

// Get all roles
app.get("/roles", async (req, res) => {
    try {
        const { rows } = await pool.query("SELECT * FROM roles");
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


// Create a new client - Add apartment field
app.post("/clients", async (req, res) => {
    try {
        const {
            name,
            last_name,
            id_number,
            status,
            id_zone,
            username,
            password,
            apartment
        } = req.body;
        
        // Get user's zone from token or request (you'll need to modify your auth middleware)
        const userZone = req.user?.id_zone || 1;
        
        // Only allow zone 1 (admin) to create clients in other zones
        if (userZone !== 1 && id_zone !== userZone) {
            return res.status(403).json({ 
                message: "You can only create clients in your own zone" 
            });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const { rows } = await pool.query(
            "INSERT INTO clients (name, last_name, id_number, status, id_zone, username, password, apartment) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *",
            [name, last_name, id_number, status, id_zone, username, password, apartment]
        );

        // Rest of the function remains the same
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


// Update client - Add apartment field
app.put("/clients/:id_number", async (req, res) => {
    try {
        const { id_number } = req.params;
        const { name, last_name, status, zone_name, username, password, apartment } = req.body;

        // Get user's zone from token or request
        const userZone = req.user?.id_zone || 1;
        
        // Get the zone ID from zone name
        const zoneResult = await pool.query("SELECT id FROM zone WHERE area = $1", [zone_name]);
        if (zoneResult.rows.length === 0) {
            return res.status(404).json({ message: "Area not found" });
        }
        const id_zone = zoneResult.rows[0].id;
        
        // Only allow zone 1 (admin) to update clients to other zones
        if (userZone !== 1 && id_zone !== userZone) {
            return res.status(403).json({ 
                message: "You can only update clients to your own zone" 
            });
        }
        
        // Also prevent non-admins from updating clients from other zones
        if (userZone !== 1) {
            // Check if the client belongs to the user's zone
            const clientResult = await pool.query(
                "SELECT id_zone FROM clients WHERE id_number = $1", 
                [id_number]
            );
            
            if (clientResult.rows.length === 0) {
                return res.status(404).json({ message: "Client not found" });
            }
            
            if (clientResult.rows[0].id_zone !== userZone) {
                return res.status(403).json({ 
                    message: "You can only update clients in your own zone" 
                });
            }
        }

        const { rows } = await pool.query(
            "UPDATE clients SET name = $1, last_name = $2, status = $3, id_zone = $4, username = $5, password = $6, apartment = $7 WHERE id_number = $8 RETURNING *",
            [name, last_name, status, id_zone, username, password, apartment, id_number]
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

// Autenticar login - Updated to return user's id_zone
app.post("/auth/login", async (req, res) => {
    try {
        const { username, password } = req.body;
        const { rows } = await pool.query("SELECT * FROM users WHERE username = $1", [username]);

        if (rows.length === 0) {
            return res.status(401).json({ message: "Invalid username or password" });
        }

        const user = rows[0];

        if (password !== user.password) {
            return res.status(401).json({ message: "Invalid username or password" });
        }

        // Return user's id_zone with the response
        res.json({ 
            message: "Login successful",
            id_zone: user.id_zone,
            id_role: user.id_role,
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server error");
    }
});

// Get all users - with enhanced zone filtering
app.get("/users", async (req, res) => {
    try {
        const userZone = req.query.id_zone || 1; // Default to 1 (all access) if not provided
        const userRole = req.query.role || 3; // Default to regular user role
        
        let query = "SELECT * FROM users";
        const params = [];
        
        // Admin in zone 1 can see all users
        if (userZone == 1 && userRole == 1) {
            // No additional filtering for global admin
        } 
        // Role 1 users from other zones can only see users from their zone
        else if (userRole == 1 && userZone != 1) {
            query += " WHERE id_zone = $1";
            params.push(userZone);
        }
        // Non-admin or non-role 1 users see only their zone users
        else {
            query += " WHERE id_zone = $1";
            params.push(userZone);
        }
        
        const { rows } = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Error del servidor");
    }
});

// Create a new user with enhanced authorization
app.post("/users", async (req, res) => {
    try {
        const { username, password, role, zone } = req.body;
        
        // Get user's zone from request or session
        const userZone = req.query.id_zone || 1;
        const userRole = req.query.role || 3;
        
        // Get zone ID based on zone name
        const zoneResult = await pool.query("SELECT id FROM zone WHERE area = $1", [zone]);
        if (zoneResult.rows.length === 0) {
            return res.status(404).json({ message: "Zone not found" });
        }
        const id_zone = zoneResult.rows[0].id;
        
        // Get role ID based on role name
        const roleResult = await pool.query("SELECT id FROM roles WHERE name = $1", [role]);
        if (roleResult.rows.length === 0) {
            return res.status(404).json({ message: "Role not found" });
        }
        const id_role = roleResult.rows[0].id;
        
        // Global admin (zone 1, role 1) can create users anywhere
        if (userZone === 1 && userRole === 1) {
            // No restrictions
        } 
        // Role 1 users from other zones can only create users in their zone
        else if (userRole === 1 && userZone !== 1) {
            if (id_zone !== userZone) {
                return res.status(403).json({ 
                    message: "You can only create users in your own zone" 
                });
            }
        }
        // Other users cannot create users
        else {
            return res.status(403).json({ 
                message: "You do not have permission to create users" 
            });
        }
        
        const { rows } = await pool.query(
            "INSERT INTO users (username, password, id_role, id_zone) VALUES ($1, $2, $3, $4) RETURNING *",
            [username, password, id_role, id_zone]
        );
        
        res.json(rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Error del servidor");
    }
});

// Update a user with enhanced authorization
app.put("/users/:id", async (req, res) => {
    try {
        const { id } = req.params;
        const { username, password, role, zone } = req.body;
        
        // Get user's zone from request or session
        const userZone = req.query.id_zone || 1;
        const userRole = req.query.role || 3;
        
        // Get zone ID based on zone name
        const zoneResult = await pool.query("SELECT id FROM zone WHERE area = $1", [zone]);
        if (zoneResult.rows.length === 0) {
            return res.status(404).json({ message: "Zone not found" });
        }
        const id_zone = zoneResult.rows[0].id;
        
        // Get role ID based on role name
        const roleResult = await pool.query("SELECT id FROM roles WHERE name = $1", [role]);
        if (roleResult.rows.length === 0) {
            return res.status(404).json({ message: "Role not found" });
        }
        const id_role = roleResult.rows[0].id;
        
        // Check if the user exists and retrieve current zone
        const userCheck = await pool.query("SELECT id_zone FROM users WHERE id = $1", [id]);
        
        if (userCheck.rows.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }
        
        // Global admin (zone 1, role 1) can update any user
        if (userZone === 1 && userRole === 1) {
            // No restrictions
        } 
        // Role 1 users from other zones can only update users in their zone
        else if (userRole === 1 && userZone !== 1) {
            if (userCheck.rows[0].id_zone !== userZone) {
                return res.status(403).json({ 
                    message: "You can only update users in your own zone" 
                });
            }
            // Prevent changing zone for non-global admins
            if (id_zone !== userZone) {
                return res.status(403).json({ 
                    message: "You cannot assign users to other zones" 
                });
            }
        }
        // Other users cannot update users
        else {
            return res.status(403).json({ 
                message: "You do not have permission to update users" 
            });
        }
        
        let query = "UPDATE users SET username = $1, id_role = $2, id_zone = $3";
        const params = [username, id_role, id_zone];
        
        // Only update password if provided
        if (password) {
            query += ", password = $4 WHERE id = $5 RETURNING *";
            params.push(password, id);
        } else {
            query += " WHERE id = $4 RETURNING *";
            params.push(id);
        }
        
        const { rows } = await pool.query(query, params);
        res.json(rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Error del servidor");
    }
});

// Delete a user with enhanced authorization
app.delete("/users/:id", async (req, res) => {
    try {
        const { id } = req.params;
        
        // Get user's zone from request or session
        const userZone = req.query.id_zone || 1;
        const userRole = req.query.role || 3;
        
        // Check if the user exists
        const userCheck = await pool.query("SELECT id_zone FROM users WHERE id = $1", [id]);
        
        if (userCheck.rows.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }
        
        // Global admin (zone 1, role 1) can delete any user
        if (userZone === 1 && userRole === 1) {
            // No restrictions
        } 
        // Role 1 users from other zones can only delete users in their zone
        else if (userRole === 1 && userZone !== 1) {
            if (userCheck.rows[0].id_zone !== userZone) {
                return res.status(403).json({ 
                    message: "You can only delete users in your own zone" 
                });
            }
        }
        // Other users cannot delete users
        else {
            return res.status(403).json({ 
                message: "You do not have permission to delete users" 
            });
        }
        
        await pool.query("DELETE FROM users WHERE id = $1", [id]);
        res.json({ message: "User deleted successfully" });
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Error del servidor");
    }
});


// // Sirve los archivos estáticos de la aplicación (como JS, CSS, etc.)
// app.use(express.static(path.join(__dirname, 'dist')));

// // Redirige todas las solicitudes al archivo index.html
// app.get('*', (req, res) => {
//     res.sendFile(path.join(__dirname, 'dist', 'index.html'));
// });


// Iniciar el servidor
app.listen(PORT, () => {
    //console.log(`Servidor corriendo en http://localhost:${PORT}`);
});