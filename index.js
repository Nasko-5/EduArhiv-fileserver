const crypto = require("crypto");
const express = require("express");
const fs = require("fs");
const fsPromises = require("fs").promises;
const cors = require("cors");
const path = require("path");
require('dotenv').config();
const pool = require('./db');
const app = express();
require('./auth')(app);

const ACTIVE_ROOT = "/data/active";
const ARCHIVE_ROOT = "/data/archive/file-archive";
const AUDIT_ROOT = "/data/archive/audit";



const basicAuth = require('express-basic-auth');
// Password protection (optional - only if BASIC_AUTH_PASSWORD is set)
if (process.env.BASIC_AUTH_PASSWORD) {
  app.use(basicAuth({
    users: { 'demo': process.env.BASIC_AUTH_PASSWORD },
    challenge: true,
    realm: 'EduArhiv Demo'
  }));
}

app.use(cors());
app.use(express.raw({ type: "*/*", limit: "50mb" }));

async function initDatabase() {
  try {
    const sql = fs.readFileSync('./init.sql', 'utf8');
    
    // Split by semicolons and filter out empty statements
    const statements = sql
      .split(';')
      .map(stmt => stmt.trim())
      .filter(stmt => stmt.length > 0 && !stmt.startsWith('--'));
    
    // Execute each statement one by one
    for (const statement of statements) {
      await pool.query(statement);
    }
    
    console.log('✓ Database tables ready!');
  } catch (error) {
    console.error('Database init error:', error);
  }
}
initDatabase();  

// basic route
app.get("/", (req, res) => {
  res.send(`
    <h1>EduArhiv File Server API</h1>
    <p>This is not intended for public usage! Turn back now!</p>
  `);
});

// basic path traversal prevention
// resolve is used here to find the absolute path of both root and targetPath
// then we check if the resolved targetPath starts with the resolved root path
// if it does, it means targetPath is within root, otherwise it's outside
function isPathGood(root, targetPath) {
    const resolvedPath = path.resolve(root, targetPath);
    const resolvedRoot = path.resolve(root);
    return resolvedPath.startsWith(resolvedRoot + path.sep) || resolvedPath === resolvedRoot;
}

// get x-api-key header and compare it to the value of the .env API_KEY variable
function validateKey(req, res) {
    const apiKey = req.headers["x-api-key"];

    if (!apiKey || apiKey !== process.env.API_KEY) {
        console.log(`Invalid API key attempt from ${req.ip}: ${apiKey ? 'key provided but incorrect' : 'no key provided'}`);
        console.log(`provided; ${apiKey}\nneeded ; ${process.env.API_KEY}`);
        res.status(401).json({ error: "Invalid API key!" });
        return false;
    }

    return true;
}

// parse the file path from the request and validate it
function parsePath(req, res) {
    let file_path = req.path.substring(1); 
    // Remove the endpoint prefix (everything up to and including the first slash)
    const firstSlashIndex = file_path.indexOf('/');
    if (firstSlashIndex !== -1) {
        file_path = file_path.substring(firstSlashIndex + 1);
    }
    
    console.log(file_path);
    if (!isPathGood(ACTIVE_ROOT, file_path)) {
        res.status(400).json({ error: "Bad file path! Get outta here you smelly hacker!" });
        console.log(file_path);
        return null;
    }

    return file_path;
}

async function writeAudit(operation, file_path, file_data) {
    // save log to audit.log on AUDIT_ROOT/YYYYMMDD.log
    try {
        const auditPath = path.join(AUDIT_ROOT, `${new Date().toISOString().split("T")[0]}.log`);
        
        const auditLog = {
            timestamp: new Date().toISOString(),
            action: operation,
            hash: crypto.createHash("sha256").update(file_data).digest("hex"),
            path: file_path,
        };

        await fsPromises.appendFile(auditPath, JSON.stringify(auditLog) + "\n");
    } catch (error) {
        console.error("Error writing audit log:", error);
    }
} 

async function saveToArchive(file_path, file_data) {
    const new_file_name = `${path.basename(file_path, path.extname(file_path))}_${Date.now()}${path.extname(file_path)}`;
    const archive_path = path.join(ARCHIVE_ROOT, path.dirname(file_path), new_file_name);
    const archive_dir = path.dirname(archive_path);

    await fsPromises.mkdir(archive_dir, { recursive: true });
    await fsPromises.writeFile(archive_path, file_data);
}


app.post("/upload/{*path}", async (req, res) => {
    
    if (!validateKey(req, res)) return;

    const file_path = parsePath(req, res);
    if (!file_path) return;

    const full_path = path.join(ACTIVE_ROOT, file_path);
    const dir = path.dirname(full_path);
    
    if (fs.existsSync(full_path)) {
        return res.status(409).json({ error: "File already exists! Consider using the /replace endpoint" });
    }

    const file_data = req.body;
    if (!file_data || file_data.length === 0) {
        return res.status(400).json({ error: "No file data provided!" });
    }

    try {
        await fsPromises.mkdir(dir, { recursive: true });
        await fsPromises.writeFile(full_path, file_data);

        await writeAudit("upload", file_path, file_data);

        res.json({ status: "success", path: file_path });
    } catch (error) {
        console.error("Error during upload:", error);
        res.status(500).json({ error: "Server failed to upload the file." });
    }
});


app.get("/download/{*path}", async (req, res) => {
    
    if (!validateKey(req, res)) return;

    const file_path = parsePath(req, res);
    if (!file_path) return;

    const full_path = path.join(ACTIVE_ROOT, file_path);

    try {
        const file_data = await fsPromises.readFile(full_path);

        await writeAudit("download", file_path, file_data);

        res.send(file_data);

    } catch (error) {
        if (error.code === "ENOENT") {
            return res.status(404).json({ error: "File not found!" });
        }
        console.error("Error during download:", error);
        res.status(500).json({ error: "Server failed to fetch the file" });
    }
});


app.delete("/delete/{*path}", async (req, res) => {

    if (!validateKey(req, res)) return;
    const file_path = parsePath(req, res);
    if (!file_path) return;

    const full_path = path.join(ACTIVE_ROOT, file_path);

    try {
        // save file hash before deletion
        const file_data = await fsPromises.readFile(full_path);

        await fsPromises.rm(full_path);

        await writeAudit("delete", file_path, file_data);

        res.json({ status: "success", path: file_path });
    } catch (error) {
        if (error.code === "ENOENT") {
            return res.status(404).json({ error: "File not found!" });
        }
        if (error.code === "ENOTEMPTY") {
            return res.status(400).json({ error: "Directory is not empty!" });
        }
        console.error("Error during delete:", error);
        res.status(500).json({ error: "Server failed to delete the file." });
    }
});

app.put("/replace/{*path}", async (req, res) => {
    if (!validateKey(req, res)) return;
    const file_path = parsePath(req, res);
    if (!file_path) return;

    const full_path = path.join(ACTIVE_ROOT, file_path);

    const new_file_data = req.body;
    if (!new_file_data || new_file_data.length === 0) {
        return res.status(400).json({ error: "No replacement file data provided!" });
    }

    try {
        const old_file_data = await fsPromises.readFile(full_path);
        await saveToArchive(file_path, old_file_data);

        // overwrite the file with new data
        await fsPromises.writeFile(full_path, new_file_data);

        await writeAudit("replace", file_path, new_file_data);

        res.json({ status: "success", path: file_path });
    } catch (error) {
        if (error.code === "ENOENT") {
            return res.status(404).json({ error: "The file you are trying to replace was not found, consider using /upload instead" });
        }
        console.error("Error during replace:", error);
        res.status(500).json({ error: "Server failed to replace the file." });
    }
});

app.get("/list-versions/{*path}", async (req, res) => {
    if (!validateKey(req, res)) return;

    const file_path = parsePath(req, res);
    if (!file_path) return;

    const archive_dir = path.join(ARCHIVE_ROOT, path.dirname(file_path));
    const base_name = path.basename(file_path, path.extname(file_path));
    const ext_name = path.extname(file_path);

    try {
        const files = await fsPromises.readdir(archive_dir);
        const versions = files.filter(f => f.startsWith(base_name + "_") && f.endsWith(ext_name));

        if (versions.length === 0) {
            return res.status(404).json({ error: "No archived versions found for this file!" });
        }

        // Sort versions by timestamp (ascending: oldest first)
        versions.sort((a, b) => parseInt(a.match(/_(\d+)\./)[1]) - parseInt(b.match(/_(\d+)\./)[1]));

        const versionList = {};
        versions.forEach((file, index) => {
            const timestamp = parseInt(file.match(/_(\d+)\./)[1]);
            versionList[index + 1] = {
                file: file,
                date: new Date(timestamp).toISOString().split("T")[0],
                timestamp: timestamp
            };
        });
        res.json(versionList);
    } catch (error) {
        console.error("Error during list-versions:", error);
        res.status(500).json({ error: "Server failed to list versions." });
    }
});

app.post("/rollback/{*path}", async (req, res) => {
    if (!validateKey(req, res)) return;

    const file_path = parsePath(req, res);
    if (!file_path) return;

    const archive_dir = path.join(ARCHIVE_ROOT, path.dirname(file_path));
    const base_name = path.basename(file_path, path.extname(file_path));
    const ext_name = path.extname(file_path);

    try {
        const files = await fsPromises.readdir(archive_dir);
        const versions = files.filter(f => f.startsWith(base_name + "_") && f.endsWith(ext_name));

        if (versions.length === 0) {
            return res.status(404).json({ error: "No archived versions found for this file!" });
        }

        // Sort versions by timestamp (ascending: oldest first)
        versions.sort((a, b) => parseInt(a.match(/_(\d+)\./)[1]) - parseInt(b.match(/_(\d+)\./)[1]));

        let version;
        try {
            const body = JSON.parse(req.body.toString());
            version = body.version;
        } catch (parseError) {
            return res.status(400).json({ error: "Invalid JSON in request body!" });
        }
        if (!version) {
            return res.status(400).json({ error: "Version parameter required for rollback!" });
        }
        
        // Rollback to specified version
        const versionIndex = parseInt(version) - 1;
        if (versionIndex < 0 || versionIndex >= versions.length) {
            return res.status(400).json({ error: "Invalid version number!" });
        }

        const archive_file = path.join(archive_dir, versions[versionIndex]);
        const full_path = path.join(ACTIVE_ROOT, file_path);
        const archived_data = await fsPromises.readFile(archive_file);

        await fsPromises.writeFile(full_path, archived_data);
        await writeAudit("rollback", file_path, archived_data);

        res.json({ status: "success", path: file_path, version: versionIndex + 1 });
    } catch (error) {
        console.error("Error during rollback:", error);
        res.status(500).json({ error: "Server failed to process rollback." });
    }
});

app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://eduarhiv.com', 'https://www.eduarhiv.com']
    : true, // Allow all origins in development
  credentials: true
}));

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`API running on port ${PORT}`);
  fs.mkdirSync(ACTIVE_ROOT, { recursive: true });
  fs.mkdirSync(AUDIT_ROOT, { recursive: true });
  fs.mkdirSync(ARCHIVE_ROOT, { recursive: true });
});
