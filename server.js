const bcrypt = require('bcryptjs');
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors()); // Remote access kosam
app.use(express.json());

// In-memory arrays / variables for dynamic storage
let staffDatabase = [];
let currentAdminPassword = process.env.ADMIN_PASS || "ADMIN123";
const ADMIN_ID = process.env.ADMIN_ID || "ADMIN"; // <--- ఇక్కడ fallback add చేశాము

// Login Route (Both Admin & Staff)
app.post('/api/login', (req, res) => {
    const { id, pass } = req.body;
    const cleanId = id ? id.trim().toUpperCase() : '';
    const cleanPass = pass ? pass.trim() : '';

    // 1. Check Admin Credentials
    if (cleanId === ADMIN_ID && cleanPass === currentAdminPassword) {
        return res.json({ success: true, role: 'ADMIN', message: 'Admin authenticated' });
    }

    // 2. Check Dynamic Staff Credentials
    const staffUser = staffDatabase.find(s => s.code === cleanId && s.pass === cleanPass);
    if (staffUser) {
        return res.json({ success: true, role: 'STAFF', code: staffUser.code, message: 'Staff authenticated' });
    }

    return res.status(401).json({ success: false, message: 'Invalid Username or Password' });
});

// Save / Update Staff Route (Called by Admin)
app.post('/api/staff/save', (req, res) => {
    const { code, pass } = req.body;
    const cleanCode = code ? code.trim().toUpperCase() : '';
    const cleanPass = pass ? pass.trim() : '';

    if (!cleanCode || !cleanPass) {
        return res.status(400).json({ success: false, message: 'Missing Code or Password' });
    }

    const index = staffDatabase.findIndex(s => s.code === cleanCode);
    if (index !== -1) {
        staffDatabase[index].pass = cleanPass;
    } else {
        staffDatabase.push({ code: cleanCode, pass: cleanPass });
    }

    return res.json({ success: true, staffList: staffDatabase });
});

// Admin Password Change Route
app.post('/api/admin/change-password', async (req, res) => {
    try {
        const { currentPass, newPass } = req.body;

        if (!currentPass || !newPass) {
            return res.status(400).json({ success: false, message: 'Passwords are required' });
        }

        if (newPass.trim().length < 6) {
            return res.status(400).json({ success: false, message: 'New password must be at least 6 characters long' });
        }

        if (currentPass.trim() !== currentAdminPassword.trim()) { 
            return res.status(400).json({ success: false, message: 'Current password is incorrect' });
        }

        currentAdminPassword = newPass.trim();

        return res.json({ 
            success: true, 
            message: 'Admin password updated successfully in backend!' 
        });

    } catch (error) {
        console.error("Backend Error:", error);
        return res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Fetch Staff List Route
app.get('/api/staff/list', (req, res) => {
    res.json({ success: true, staffList: staffDatabase });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});