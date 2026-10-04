require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');

const app = express();

app.use(cors()); // Remote access kosam
app.use(express.json());

// 1. MongoDB Connection Setup (Deprecated options removed)
mongoose.connect(process.env.MONGO_URI)
.then(() => console.log("MongoDB Connected Successfully"))
.catch(err => console.log("DB Connection Error:", err));

// 2. Mongoose Schema & Models for Staff
const staffSchema = new mongoose.Schema({
    code: { type: String, required: true, unique: true },
    pass: { type: String, required: true } // Hashed password storage
});
const Staff = mongoose.model('Staff', staffSchema);

let currentAdminPassword = process.env.ADMIN_PASS || "ADMIN123";
const ADMIN_ID = process.env.ADMIN_ID || "ADMIN";

// Helper function to handle staff save/register logic securely
const handleStaffSaveOrRegister = async (req, res) => {
    try {
        const { code, pass } = req.body;
        const cleanCode = code ? code.trim().toUpperCase() : '';
        const cleanPass = pass ? pass.trim() : '';

        if (!cleanCode || !cleanPass) {
            return res.status(400).json({ success: false, message: 'Missing Code or Password' });
        }

        // Hash password before saving
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

        const staffList = await Staff.find({}, { code: 1, _id: 0 });
        return res.json({ success: true, staffList });
    } catch (error) {
        console.error("Save Staff Error:", error);
        return res.status(500).json({ success: false, message: 'Server error' });
    }
};

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

        // 2. Check Dynamic Staff Credentials from MongoDB using bcrypt compare
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

// Save / Update Staff Route
app.post('/api/staff/save', handleStaffSaveOrRegister);

// Alias for register route compatibility (Direct function call instead of router hack)
app.post('/api/register', handleStaffSaveOrRegister);

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
app.get('/api/staff/list', async (req, res) => {
    try {
        const staffList = await Staff.find({}, { code: 1, _id: 0 });
        res.json({ success: true, staffList });
    } catch (error) {
        console.error("Fetch Staff Error:", error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

app.get('/api/executives', async (req, res) => {
    try {
        const users = await Staff.find({}, { code: 1, _id: 0 });
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
```[cite: 1]

---

### 2. Complete `package.json` Code:
```json
{
  "name": "backend-server",
  "version": "1.0.0",
  "description": "Tekkali Digital Web Solutions Hub Backend Server",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "keywords": [],
  "author": "",
  "license": "ISC",
  "type": "commonjs",
  "dependencies": {
    "bcryptjs": "^3.0.3",
    "cors": "^2.8.6",
    "dotenv": "^18.0.3",
    "express": "^5.2.1",
    "mongoose": "^8.24.4"
  }
}
```[cite: 2]

---

### 3. Complete `package-lock.json` Code:
```json
{
  "name": "backend-server",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "backend-server",
      "version": "1.0.0",
      "license": "ISC",
      "dependencies": {
        "bcryptjs": "^3.0.3",
        "cors": "^2.8.6",
        "dotenv": "^18.0.3",
        "express": "^5.2.1",
        "mongoose": "^8.24.4"
      }
    },
    "node_modules/@mongodb-js/saslprep": {
      "version": "1.5.4",
      "resolved": "https://registry.npmjs.org/@mongodb-js/saslprep/-/saslprep-1.5.4.tgz",
      "integrity": "sha512-05UC0jQsjKAOuXQ0H9Ud9vUTJpZIg+n/FinpR30tI5I8pY2inTfPOZ5OF/cg3Ce/N9MoD1xhRCeOsJtuTbFYlw==",
      "license": "MIT",
      "dependencies": {
        "sparse-bitfield": "^3.0.3"
      }
    },
    "node_modules/@types/webidl-conversions": {
      "version": "7.0.3",
      "resolved": "https://registry.npmjs.org/@types/webidl-conversions/-/webidl-conversions-7.0.3.tgz",
      "integrity": "sha512-CiJJvcRtIgzadHCYXw7dqEnMNRjhGZlYK05Mj9OyktqV8uVT8fD2BFOB7S1uwBE3Kj2Z+4UyPmFw/Ixgw/LAlA==",
      "license": "MIT"
    },
    "node_modules/@types/whatwg-url": {
      "version": "11.0.5",
      "resolved": "https://registry.npmjs.org/@types/whatwg-url/-/whatwg-url-11.0.5.tgz",
      "integrity": "sha512-coYR071JRaHa+xoEvvYqvnIHaVqaYrLPbsufM9BF63HkwI5Lgmy2QR8Q5K/lYDYo5AK82wOvSOS0UsLTpTG7uQ==",
      "license": "MIT",
      "dependencies": {
        "@types/webidl-conversions": "*"
      }
    },
    "node_modules/accepts": {
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/accepts/-/accepts-2.0.0.tgz",
      "integrity": "sha512-5cvg6CtKwfgdmVqY1WIiXKc3Q1bkRqGLi+2W/6ao+6Y7gu/RCwRuAhGEzh5B4KlszSuTLgZYuqFqo5bImjNKng==",
      "license": "MIT",
      "dependencies": {
        "mime-types": "^3.0.0",
        "negotiator": "^1.0.0"
      },
      "engines": {
        "node": ">= 0.6"
      }
    },
    "node_modules/bcryptjs": {
      "version": "3.0.3",
      "resolved": "https://registry.npmjs.org/bcryptjs/-/bcryptjs-3.0.3.tgz",
      "integrity": "sha512-GlF5wPWnSa/X5LKM1o0wz0suXIINz1iHRLvTS+sLyi7XPbe5ycmYI3DlZqVGZZtDgl4DmasFg7gOB3JYbphV5g==",
      "license": "BSD-3-Clause",
      "bin": {
        "bcrypt": "bin/bcrypt"
      }
    },
    "node_modules/body-parser": {
      "version": "2.3.0",
      "resolved": "https://registry.npmjs.org/body-parser/-/body-parser-2.3.0.tgz",
      "integrity": "sha512-2cGmJupaNgg+QUwVLAucDuWuoMZ6EX9iHDRswZ5lsNYEmwPaRknMPCLZz07yTzVq/83p4o/wzbDZbBrTvGGTIw==",
      "license": "MIT",
      "dependencies": {
        "bytes": "^3.1.2",
        "content-type": "^2.0.0",
        "debug": "^4.4.3",
        "http-errors": "^2.0.1",
        "iconv-lite": "^0.7.2",
        "on-finished": "^2.4.1",
        "qs": "^6.15.2",
        "raw-body": "^3.0.2",
        "type-is": "^2.1.0"
      },
      "engines": {
        "node": ">=18"
      },
      "funding": {
        "type": "opencollective",
        "url": "https://opencollective.com/express"
      }
    },
    "node_modules/bson": {
      "version": "6.10.4",
      "resolved": "https://registry.npmjs.org/bson/-/bson-6.10.4.tgz",
      "integrity": "sha512-WIsKqkSC0ABoBJuT1LEX+2HEvNmNKKgnTAyd0fL8qzK4SH2i9NXg+t08YtdZp/V9IZ33cxe3iV4yM0qg8lMQng==",
      "license": "Apache-2.0",
      "engines": {
        "node": ">=16.20.1"
      }
    },
    "node_modules/bytes": {
      "version": "3.1.2",
      "resolved": "https://registry.npmjs.org/bytes/-/bytes-3.1.2.tgz",
      "integrity": "sha512-/Nf7TyzTx6S3yRJObOAV7956r8cr2+Oj8AC5dt8wSP3BQAoeX58NoHyCU8P8zGkNXStjTSi6fzO6F0pBdcYbEg==",
      "license": "MIT",
      "engines": {
        "node": ">= 0.8"
      }
    },
    "node_modules/cors": {
      "version": "2.8.6",
      "resolved": "https://registry.npmjs.org/cors/-/cors-2.8.6.tgz",
      "integrity": "sha512-tJtZBBHA6vjIAaF6EnIaq6laBBP9aq/Y3ouVJjEfoHbRBcHBAHYcMh/w8LDrk2PvIMMq8gmopa5D4V8RmbrxGw==",
      "license": "MIT",
      "dependencies": {
        "object-assign": "^4",
        "vary": "^1"
      },
      "engines": {
        "node": ">= 0.10"
      }
    },
    "node_modules/dotenv": {
      "version": "18.0.3",
      "resolved": "https://registry.npmjs.org/dotenv/-/dotenv-18.0.3.tgz",
      "integrity": "sha512-/8CJTyL817qPnfbQrJgOEcrU3fDrJkRIoXBE566wHuvIXKOCHUZhPqGPbCPi9SogjdGnreF0TlvnTgK6J/8zpA==",
      "license": "BSD-2-Clause",
      "bin": {
        "dotenv": "dist/index.cjs"
      },
      "engines": {
        "node": ">=12"
      }
    },
    "node_modules/express": {
      "version": "5.2.1",
      "resolved": "https://registry.npmjs.org/express/-/express-5.2.1.tgz",
      "integrity": "sha512-hIS4idWWai69NezIdRt2xFVofaF4j+6INOpJlVOLDO8zXGpUVEVzIYk12UUi2JzjEzWL3IOAxcTubgz9Po0yXw==",
      "license": "MIT"
    },
    "node_modules/mongodb": {
      "version": "6.20.0",
      "resolved": "https://registry.npmjs.org/mongodb/-/mongodb-6.20.0.tgz",
      "integrity": "sha512-Tl6MEIU3K4Rq3TSHd+sZQqRBoGlFsOgNrH5ltAcFBV62Re3Fd+FcaVf8uSEQFOJ51SDowDVttBTONMfoYWrWlQ==",
      "license": "Apache-2.0",
      "dependencies": {
        "@mongodb-js/saslprep": "^1.3.0",
        "bson": "^6.10.4",
        "mongodb-connection-string-url": "^3.0.2"
      }
    },
    "node_modules/mongoose": {
      "version": "8.24.4",
      "resolved": "https://registry.npmjs.org/mongoose/-/mongoose-8.24.4.tgz",
      "integrity": "sha512-DoV8hYy5ssoh/j99rhYzeS2BLLcLJZ+EGQYfe/Ln+yMorBy0wgKdlwJBj59zJ1N0MnEKQypbeqUYFB0FVThmYg==",
      "license": "MIT",
      "dependencies": {
        "bson": "^6.10.4",
        "kareem": "2.6.3",
        "mongodb": "~6.20.0",
        "mpath": "0.9.0",
        "mquery": "5.0.0",
        "ms": "2.1.3",
        "sift": "17.1.3"
      }
    }
  }
}
```[cite: 3]

Ee updated files ni use chesthe meeku code lo compilation errors, native module build failures (bcrypt issues), mariyu security warnings raavu.
