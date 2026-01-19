const fsPromises = require("fs").promises;
const fs = require("fs");
const path = require("path"); // 1. Missing import
const crypto = require("crypto"); 

const ACTIVE_ROOT = "/data/active";
const ARCHIVE_ROOT = "/data/archive/file-archive";
const AUDIT_ROOT = "/data/archive/audit";

// basic path traversal prevention
// resolve is used here to find the absolute path of both root and targetPath
// then we check if the resolved targetPath starts with the resolved root path
// if it does, it means targetPath is within root, otherwise it's outside
function isPathGood(root, targetPath) {
    const resolvedPath = path.resolve(root, targetPath);
    const resolvedRoot = path.resolve(root);
    return resolvedPath.startsWith(resolvedRoot + path.sep) || resolvedPath === resolvedRoot;
}

// midelware to validate 'path' query parameter
// utils.js

const validatePath = (req, res, next) => {
  let file_path = req.query.path;

  // 1. Check if the parameter is missing completely
  if (file_path === undefined || file_path === null) {
    return res.status(400).json({ error: "Path parameter is required" });
  }

  // 2. FIX: If the user sends "/", treat it as the root of the active directory
  if (file_path === '/') {
    file_path = '.';
  }

  if (!isPathGood(ACTIVE_ROOT, file_path)) {
    console.log(`Invalid path attempt: ${file_path}`);
    return res.status(400).json({ error: "Bad file path! Get outta here you smelly hacker!" });
  }
  
  req.file_path = file_path;
  next();
};


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

// middleware to check API key
const checkKey = (req, res, next) => {
  if (!validateKey(req, res)) return;
  next();
};


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
  writeAudit,
  saveToArchive,

  validatePath,
  checkKey,

  ACTIVE_ROOT,
  ARCHIVE_ROOT,
  AUDIT_ROOT,
};