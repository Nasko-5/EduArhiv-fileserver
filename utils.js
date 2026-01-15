const fsPromises = require("fs").promises;
const fs = require("fs");
const path = require("path"); // 1. Missing import
const crypto = require("crypto"); 

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

module.exports = {
  isPathGood,
  validateKey,
  parsePath,
  writeAudit,
  saveToArchive
};