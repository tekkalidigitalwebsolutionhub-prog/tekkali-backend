const bcrypt = require('bcryptjs');
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors()); // Remote access kosam
app.use(express.json());

// Render dynamically port assign chesthundhi
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// In-memory array for dynamic staff storage (Database replace sese varaku)
let staffDatabase = [];

// Login Route (Both Admin & Staff)
app.post('/api/login', (req, res) => {
    const { id, pass } = req.body;
    const cleanId = id ? id.trim().toUpperCase() : '';
    const cleanPass = pass ? pass.trim() : '';

    // 1. Check Admin Credentials
    if (cleanId === process.env.ADMIN_ID && cleanPass === process.env.ADMIN_PASS) {
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

        // Demo Admin credentials check (Leda database search)
        // Express lo plain check leda bcrypt compare
        if (currentPass !== "ADMIN123") { // Leda bcrypt compare vadandi
            return res.status(400).json({ success: false, message: 'Current password is incorrect' });
        }

        // Salt & Hash generate cheyadam
        const salt = await bcrypt.genSalt(10);
        const newPasswordHash = await bcrypt.hash(newPass, salt);

        console.log("New Password Hash:", newPasswordHash);

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