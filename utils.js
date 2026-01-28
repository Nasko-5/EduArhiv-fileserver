const fsPromises = require("fs").promises;
const fs = require("fs");
const path = require("path"); 
const crypto = require("crypto"); 

const ACTIVE_ROOT = "/data/active";
const ARCHIVE_ROOT = "/data/archive/file-archive";
const AUDIT_ROOT = "/data/archive/audit";

console.log("[UTILS] Initializing utilities...");
console.log(`[UTILS] ACTIVE_ROOT: ${ACTIVE_ROOT}`);
console.log(`[UTILS] ARCHIVE_ROOT: ${ARCHIVE_ROOT}`);
console.log(`[UTILS] AUDIT_ROOT: ${AUDIT_ROOT}`);

// basic path traversal prevention
function isPathGood(root, targetPath) {
    const resolvedPath = path.resolve(root, targetPath);
    const resolvedRoot = path.resolve(root);
    
    // Log details of the check
    const isGood = resolvedPath.startsWith(resolvedRoot + path.sep) || resolvedPath === resolvedRoot;
    
    if (!isGood) {
        console.log(`[SECURITY] Path Traversal Attempt Detected!`);
        console.log(`[SECURITY] Root: ${resolvedRoot}`);
        console.log(`[SECURITY] Target: ${resolvedPath}`);
    }

    return isGood;
}

// middleware to validate 'path' query parameter
const validatePath = (req, res, next) => {
  let file_path = req.query.path;

  console.log(`[PATH_VALIDATOR] Raw Path Query: ${file_path}`);

  // 1. Check if the parameter is missing completely
  if (file_path === undefined || file_path === null) {
    console.log("[PATH_VALIDATOR] Error: Path parameter missing.");
    return res.status(400).json({ error: "Path parameter is required" });
  }

  // 2. FIX: If the user sends "/", treat it as the root of the active directory
  if (file_path === '/') {
    console.log("[PATH_VALIDATOR] Normalizing '/' to '.'");
    file_path = '.';
  } 
  else if (file_path.startsWith('/')) {
      file_path = file_path.substring(1);
      console.log(`[PATH_VALIDATOR] Stripped leading slash. New Path: ${file_path}`);
  }

  if (!isPathGood(ACTIVE_ROOT, file_path)) {
    console.log(`[PATH_VALIDATOR] Rejected Invalid Path: ${file_path}`);
    return res.status(400).json({ error: "Bad file path! Get outta here you smelly hacker!" });
  }
  
  console.log(`[PATH_VALIDATOR] Path Validated: ${file_path}`);
  req.file_path = file_path;
  next();
};

// get x-api-key header and compare it to the value of the .env API_KEY variable
function validateKey(req, res) {
    const apiKey = req.headers["x-api-key"];
    console.log("[KEY_VALIDATOR] Checking API Key...");
    
    // Only log if provided, for security don't log the actual value if possible, or log truncated
    if (apiKey) {
        console.log(`[KEY_VALIDATOR] Key Provided: ${apiKey.substring(0, 10)}...`);
    } else {
        console.log(`[KEY_VALIDATOR] Key Missing!`);
    }

    if (!apiKey || apiKey !== process.env.API_KEY) {
        console.log(`[KEY_VALIDATOR] Access Denied from ${req.ip}`);
        console.log(`[KEY_VALIDATOR] Reason: ${apiKey ? 'Key mismatch' : 'No key provided'}`);
        res.status(401).json({ error: "Invalid API key!" });
        return false;
    }

    console.log("[KEY_VALIDATOR] Access Granted.");
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
        const dateStr = new Date().toISOString().split("T")[0];
        const auditPath = path.join(AUDIT_ROOT, `${dateStr}.log`);
        
        const auditLog = {
            timestamp: new Date().toISOString(),
            action: operation,
            hash: crypto.createHash("sha256").update(file_data).digest("hex"),
            path: file_path,
        };

        console.log(`[AUDIT] Writing log: ${operation} on ${file_path}`);
        
        await fsPromises.appendFile(auditPath, JSON.stringify(auditLog) + "\n");
    } catch (error) {
        console.error("[AUDIT] Error writing audit log:", error);
    }
} 

async function saveToArchive(file_path, file_data) {
    const new_file_name = `${path.basename(file_path, path.extname(file_path))}_${Date.now()}${path.extname(file_path)}`;
    const archive_path = path.join(ARCHIVE_ROOT, path.dirname(file_path), new_file_name);
    const archive_dir = dirname = path.dirname(archive_path);

    console.log(`[ARCHIVE] Saving snapshot of ${file_path} to ${archive_path}`);

    await fsPromises.mkdir(archive_dir, { recursive: true });
    await fsPromises.writeFile(archive_path, file_data);
    console.log(`[ARCHIVE] Snapshot saved.`);
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