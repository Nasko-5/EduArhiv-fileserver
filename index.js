const crypto = require("crypto");
const express = require("express");
const fs = require("fs");
const fsPromises = require("fs").promises;
const cors = require("cors");
const path = require("path");
const os = require("os");
require("dotenv").config();

const pool = require("./db");
const basicAuth = require("express-basic-auth");
require("./utils");

// Constants
const ACTIVE_ROOT = "/data/active";
const ARCHIVE_ROOT = "/data/archive/file-archive";
const AUDIT_ROOT = "/data/archive/audit";
const PORT = process.env.PORT || 3000;

const app = express();

// =============================================================================
// Middleware Setup
// =============================================================================

// Basic authentication (if enabled)
if (process.env.BASIC_AUTH_PASSWORD) {
  app.use(
    basicAuth({
      users: { demo: process.env.BASIC_AUTH_PASSWORD },
      challenge: true,
      realm: "EduArhiv Demo",
    })
  );
}

// CORS
app.use(
  cors({
    origin:
      process.env.NODE_ENV === "production"
        ? ["https://eduarhiv.com", "https://www.eduarhiv.com"]
        : true,
    credentials: true,
  })
);

// Body parser
app.use(express.raw({ type: "*/*", limit: "50mb" }));

// Key validation middleware
const checkKey = (req, res, next) => {
  if (!validateKey(req, res)) return;
  next();
};

// Auth routes
require("./auth")(app);

// Protected routes
app.use("/auth", checkKey);
app.use("/fs", checkKey);

// =============================================================================
// Database Initialization
// =============================================================================

async function initDatabase() {
  try {
    const sql = fs.readFileSync("./init.sql", "utf8");

    const statements = sql
      .split(";")
      .map((stmt) => stmt.trim())
      .filter((stmt) => stmt.length > 0 && !stmt.startsWith("--"));

    for (const statement of statements) {
      await pool.query(statement);
    }

    console.log("✓ Database tables ready!");
  } catch (error) {
    console.error("Database init error:", error);
  }
}

initDatabase();

// =============================================================================
// Routes
// =============================================================================

app.get("/", (req, res) => {
  res.send(`
    <h1>EduArhiv File Server API</h1>
    <p>This is not intended for public usage! Turn back now!</p>
  `);
});

app.get("/health", (req, res) => {
  const uptime = process.uptime();
  const memUsage = process.memoryUsage();
  const cpuUsage = process.cpuUsage();
  const loadAvg = os.loadavg();

  const html = `
    <html>
      <head><title>EduArhiv Health</title></head>
      <body>
        <h1>Server Health Status</h1>
        <hr>
        <p><strong>Uptime:</strong> ${Math.floor(uptime)}s</p>
        <p><strong>Memory Usage:</strong> ${(memUsage.heapUsed / 1024 / 1024).toFixed(2)} MB / ${(memUsage.heapTotal / 1024 / 1024).toFixed(2)} MB</p>
        <p><strong>CPU Usage:</strong> ${((cpuUsage.user / 1000000) * 100).toFixed(2)}% user, ${((cpuUsage.system / 1000000) * 100).toFixed(2)}% system</p>
        <p><strong>Load Average:</strong> ${loadAvg[0].toFixed(2)}, ${loadAvg[1].toFixed(2)}, ${loadAvg[2].toFixed(2)}</p>
      </body>
    </html>
  `;
  res.status(200).send(html);
});

// =============================================================================
// File System Routes
// =============================================================================

app.post("/fs/upload/{*path}", async (req, res) => {
  const file_path = parsePath(req, res);
  if (!file_path) return;

  const full_path = path.join(ACTIVE_ROOT, file_path);
  const dir = path.dirname(full_path);

  if (fs.existsSync(full_path)) {
    return res.status(409).json({
      error: "File already exists! Consider using the /replace endpoint",
    });
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

app.get("/fs/download/{*path}", async (req, res) => {
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

app.delete("/fs/delete/{*path}", async (req, res) => {
  const file_path = parsePath(req, res);
  if (!file_path) return;

  const full_path = path.join(ACTIVE_ROOT, file_path);

  try {
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

app.put("/fs/replace/{*path}", async (req, res) => {
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
    await fsPromises.writeFile(full_path, new_file_data);
    await writeAudit("replace", file_path, new_file_data);

    res.json({ status: "success", path: file_path });
  } catch (error) {
    if (error.code === "ENOENT") {
      return res.status(404).json({
        error: "The file you are trying to replace was not found, consider using /upload instead",
      });
    }
    console.error("Error during replace:", error);
    res.status(500).json({ error: "Server failed to replace the file." });
  }
});

// =============================================================================
// Version Management Routes
// =============================================================================

app.get("/list-versions/{*path}", async (req, res) => {
  const file_path = parsePath(req, res);
  if (!file_path) return;

  const archive_dir = path.join(ARCHIVE_ROOT, path.dirname(file_path));
  const base_name = path.basename(file_path, path.extname(file_path));
  const ext_name = path.extname(file_path);

  try {
    const files = await fsPromises.readdir(archive_dir);
    const versions = files
      .filter((f) => f.startsWith(base_name + "_") && f.endsWith(ext_name))
      .sort((a, b) => parseInt(a.match(/_(\d+)\./)[1]) - parseInt(b.match(/_(\d+)\./)[1]));

    if (versions.length === 0) {
      return res.status(404).json({ error: "No archived versions found for this file!" });
    }

    const versionList = {};
    versions.forEach((file, index) => {
      const timestamp = parseInt(file.match(/_(\d+)\./)[1]);
      versionList[index + 1] = {
        file: file,
        date: new Date(timestamp).toISOString().split("T")[0],
        timestamp: timestamp,
      };
    });

    res.json(versionList);
  } catch (error) {
    console.error("Error during list-versions:", error);
    res.status(500).json({ error: "Server failed to list versions." });
  }
});

app.post("/fs/rollback/{*path}", async (req, res) => {
  const file_path = parsePath(req, res);
  if (!file_path) return;

  const archive_dir = path.join(ARCHIVE_ROOT, path.dirname(file_path));
  const base_name = path.basename(file_path, path.extname(file_path));
  const ext_name = path.extname(file_path);

  try {
    const files = await fsPromises.readdir(archive_dir);
    const versions = files
      .filter((f) => f.startsWith(base_name + "_") && f.endsWith(ext_name))
      .sort((a, b) => parseInt(a.match(/_(\d+)\./)[1]) - parseInt(b.match(/_(\d+)\./)[1]));

    if (versions.length === 0) {
      return res.status(404).json({ error: "No archived versions found for this file!" });
    }

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

// =============================================================================
// Server Startup
// =============================================================================

app.listen(PORT, () => {
  console.log(`API running on port ${PORT}`);
  fs.mkdirSync(ACTIVE_ROOT, { recursive: true });
  fs.mkdirSync(AUDIT_ROOT, { recursive: true });
  fs.mkdirSync(ARCHIVE_ROOT, { recursive: true });
});