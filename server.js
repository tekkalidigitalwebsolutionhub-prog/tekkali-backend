const bcrypt = require('bcryptjs');
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const app = express();

app.use(cors()); // Remote access kosam
app.use(express.json());

// 1. MongoDB Connection Setup
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("MongoDB Connected Successfully"))
  .catch(err => console.log("DB Connection Error:", err));

// 2. Mongoose Schema & Models for Staff
const staffSchema = new mongoose.Schema({
    code: { type: String, required: true, unique: true },
    pass: { type: String, required: true }
});
const Staff = mongoose.model('Staff', staffSchema);

let currentAdminPassword = process.env.ADMIN_PASS || "ADMIN123";
const ADMIN_ID = process.env.ADMIN_ID || "ADMIN";

// Login Route (Both Admin & Staff)
app.post('/api/login', async (req, res) => {
    try {
        const { id, pass } = req.body;
        const cleanId = id ? id.trim().toUpperCase() : '';
        const cleanPass = pass ? pass.trim() : '';

        // 1. Check Admin Credentials
        if (cleanId === ADMIN_ID && cleanPass === currentAdminPassword) {
            return res.json({ success: true, role: 'ADMIN', message: 'Admin authenticated' });
        }

        // 2. Check Dynamic Staff Credentials from MongoDB
        const staffUser = await Staff.findOne({ code: cleanId, pass: cleanPass });
        if (staffUser) {
            return res.json({ success: true, role: 'STAFF', code: staffUser.code, message: 'Staff authenticated' });
        }

        return res.status(401).json({ success: false, message: 'Invalid Username or Password' });
    } catch (error) {
        console.error("Login Error:", error);
        return res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Save / Update Staff Route (Called by Admin) - Supports /api/staff/save and /api/register
app.post('/api/staff/save', async (req, res) => {
    try {
        const { code, pass } = req.body;
        const cleanCode = code ? code.trim().toUpperCase() : '';
        const cleanPass = pass ? pass.trim() : '';

        if (!cleanCode || !cleanPass) {
            return res.status(400).json({ success: false, message: 'Missing Code or Password' });
        }

        let staffUser = await Staff.findOne({ code: cleanCode });
        if (staffUser) {
            staffUser.pass = cleanPass;
            await staffUser.save();
        } else {
            staffUser = new Staff({ code: cleanCode, pass: cleanPass });
            await staffUser.save();
        }

        const staffList = await Staff.find({}, { code: 1, pass: 1, _id: 0 });
        return res.json({ success: true, staffList });
    } catch (error) {
        console.error("Save Staff Error:", error);
        return res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Alias for register route compatibility
app.post('/api/register', async (req, res) => {
    req.url = '/api/staff/save';
    return app._router.handle(req, res);
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

// Fetch Staff List Route - Supports /api/staff/list and /api/executives
app.get('/api/staff/list', async (req, res) => {
    try {
        const staffList = await Staff.find({}, { code: 1, pass: 1, _id: 0 });
        res.json({ success: true, staffList });
    } catch (error) {
        console.error("Fetch Staff Error:", error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/executives', async (req, res) => {
    try {
        const users = await Staff.find({}, { code: 1, pass: 1, _id: 0 });
        res.json({ success: true, users, staffList: users });
    } catch (error) {
        console.error("Fetch Executives Error:", error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});