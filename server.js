require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');

const app = express();

app.use(cors()); 
app.use(express.json());

// 1. MongoDB Connection Setup
mongoose.connect(process.env.MONGO_URI)
.then(() => console.log("MongoDB Connected Successfully"))
.catch(err => console.log("DB Connection Error:", err));

// 2. Mongoose Schemas & Models
const staffSchema = new mongoose.Schema({
    code: { type: String, required: true, unique: true },
    pass: { type: String, required: true } 
});
const Staff = mongoose.model('Staff', staffSchema);

const agreementSchema = new mongoose.Schema({
    projectId: { type: String, required: true, unique: true },
    category: String,
    clientName: String,
    companyName: String,
    email: String,
    phone: String,
    panId: String,
    address: String,
    empId: String,
    budget: Number,
    advance: Number,
    balance: Number,
    date: String,
    signatureImage: String
});
const Agreement = mongoose.model('Agreement', agreementSchema);

let currentAdminPassword = process.env.ADMIN_PASS || "ADMIN123";
const ADMIN_ID = process.env.ADMIN_ID || "ADMIN";

// Helper function for Staff Save/Register
const handleStaffSaveOrRegister = async (req, res) => {
    try {
        const { code, pass } = req.body;
        const cleanCode = code ? code.trim().toUpperCase() : '';
        const cleanPass = pass ? pass.trim() : '';

        if (!cleanCode || !cleanPass) {
            return res.status(400).json({ success: false, message: 'Missing Code or Password' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(cleanPass, salt);

        let staffUser = await Staff.findOne({ code: cleanCode });
        if (staffUser) {
            staffUser.pass = hashedPassword;
            await staffUser.save();
        } else {
            staffUser = new Staff({ code: cleanCode, pass: hashedPassword });
            await staffUser.save();
        }

        const staffList = await Staff.find({}, { code: 1, pass: 1, _id: 0 });
        return res.json({ success: true, staffList });
    } catch (error) {
        console.error("Save Staff Error:", error);
        return res.status(500).json({ success: false, message: 'Server error' });
    }
};

// Login Route
app.post('/api/login', async (req, res) => {
    try {
        const { id, pass } = req.body;
        const cleanId = id ? id.trim().toUpperCase() : '';
        const cleanPass = pass ? pass.trim() : '';

        if (cleanId === ADMIN_ID && cleanPass === currentAdminPassword) {
            return res.json({ success: true, role: 'ADMIN', message: 'Admin authenticated' });
        }

        const staffUser = await Staff.findOne({ code: cleanId });
        if (staffUser) {
            const isMatch = await bcrypt.compare(cleanPass, staffUser.pass);
            if (isMatch) {
                return res.json({ success: true, role: 'STAFF', code: staffUser.code, message: 'Staff authenticated' });
            }
        }

        return res.status(401).json({ success: false, message: 'Invalid Username or Password' });
    } catch (error) {
        console.error("Login Error:", error);
        return res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Staff Routes
app.post('/api/staff/save', handleStaffSaveOrRegister);
app.post('/api/register', handleStaffSaveOrRegister);

app.get('/api/staff/list', async (req, res) => {
    try {
        const staffList = await Staff.find({}, { code: 1, pass: 1, _id: 0 });
        res.json({ success: true, staffList });
    } catch (error) {
        console.error("Fetch Staff Error:", error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.delete('/api/staff/delete/:code', async (req, res) => {
    try {
        const code = req.params.code.toUpperCase();
        await Staff.deleteOne({ code });
        const staffList = await Staff.find({}, { code: 1, pass: 1, _id: 0 });
        res.json({ success: true, staffList });
    } catch (error) {
        console.error("Delete Staff Error:", error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
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
        return res.json({ success: true, message: 'Admin password updated successfully!' });
    } catch (error) {
        console.error("Password Change Error:", error);
        return res.status(500).json({ success: false, message: 'Server error' });
    }
});

// --- AGREEMENTS ROUTES (Cross-Device Sync) ---
app.get('/api/agreements', async (req, res) => {
    try {
        const agreements = await Agreement.find({});
        res.json({ success: true, agreements });
    } catch (error) {
        console.error("Fetch Agreements Error:", error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.post('/api/agreements/save', async (req, res) => {
    try {
        const newAgreementData = req.body;
        const newAgreement = new Agreement(newAgreementData);
        await newAgreement.save();
        const agreements = await Agreement.find({});
        res.json({ success: true, agreements });
    } catch (error) {
        console.error("Save Agreement Error:", error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.delete('/api/agreements/delete/:projectId', async (req, res) => {
    try {
        const projectId = req.params.projectId;
        await Agreement.deleteOne({ projectId });
        const agreements = await Agreement.find({});
        res.json({ success: true, agreements });
    } catch (error) {
        console.error("Delete Agreement Error:", error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
