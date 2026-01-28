const bcrypt = require('bcrypt');  

console.log("[AUTH] Auth module loaded.");

module.exports = function(app, pool) {

// =============================================================================
// REGISTER/CREATE USER (for teachers to create student accounts)
// POST /auth/register
// Body: { username, password, role, classId }
// =============================================================================
app.post('/auth/register', async (req, res) => {
  console.log("[AUTH] POST /auth/register request received.");
  try {
    const { username, password, role, classId } = req.body;
    
    console.log(`[AUTH] Registration Attempt - Username: ${username}, Role: ${role}, ClassId: ${classId}`);

    // hash the password 
    console.log("[AUTH] Hashing password...");
    const passwordHash = await bcrypt.hash(password, 10);
    console.log("[AUTH] Password hashed successfully.");
    
    // insert into database
    console.log("[AUTH] Inserting user into DB...");
    const [result] = await pool.query(
      'INSERT INTO users (username, password_hash, role, created_by) VALUES (?, ?, ?, ?)',
      [username, passwordHash, role, req.user?.id || null]  // req.user.id = whoever is logged in
    );
    
    const userId = result.insertId;  // get the ID of the new user
    console.log(`[AUTH] User created with ID: ${userId}`);
    
    // if this is a student and they gave a classId, add them to the class
    if (role === 'student' && classId) {
      console.log(`[AUTH] Adding student ${userId} to class ${classId}...`);
      await pool.query(
      'INSERT INTO class_members (class_id, user_id) VALUES (?, ?)',
      [classId, userId]
      );
      console.log("[AUTH] Student added to class successfully.");
    }
    
    res.json({ 
      success: true, 
      userId: userId,
      message: 'User created!' 
    });
    
    } catch (error) {
    console.error('[AUTH] Register error:', error);
    console.trace('[AUTH] Error trace:', error);
    
    // check if username already exists
    if (error.code === 'ER_DUP_ENTRY') {
      console.log("[AUTH] Registration failed: Username already exists.");
      return res.status(400).json({ error: 'Username already exists' });
    }
    
    res.status(500).json({ error: 'Registration failed' });
    }
});

// =============================================================================
// LOGIN
// POST /auth/login
// Body: { username, password }
// =============================================================================
app.post('/auth/login', async (req, res) => {
  console.log("[AUTH] POST /auth/login request received.");
  try {
    const { username, password } = req.body;
    
    console.log(`[AUTH] Login attempt for username: ${username}`);
    
    // find user by username
    console.log("[AUTH] Querying database for user...");
    const [rows] = await pool.query(
      'SELECT * FROM users WHERE username = ?',
      [username]
    );
    
    // STEP 2: Check if user exists
    if (rows.length === 0) {
      console.log("[AUTH] Login failed: User not found.");
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    
    const user = rows[0];  // rows is an array, get the first one
    console.log(`[AUTH] User found (ID: ${user.id}). Comparing password...`);
    
    // bcrypt.compare compares the plain password with the hashed one
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    
    if (!passwordMatch) {
      console.log("[AUTH] Login failed: Password mismatch.");
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    
    // login successful! return user info
    console.log("[AUTH] Login successful!");
    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    });
    
  } catch (error) {
    console.error('[AUTH] Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// =============================================================================
// GET USER INFO (check who's logged in)
// =============================================================================
app.get('/auth/me/:userId', async (req, res) => {
  console.log("[AUTH] GET /auth/me/:userId");
  try {
    const userId = req.params.userId;
    console.log(`[AUTH] Fetching info for User ID: ${userId}`);
    
    // SELECT specific columns, and JOIN to get class info
    console.log("[AUTH] Executing user query with joins...");
    const [rows] = await pool.query(`
      SELECT 
        u.id, 
        u.username, 
        u.role,
        c.id as class_id,
        c.name as class_name
      FROM users u
      LEFT JOIN class_members cm ON u.id = cm.user_id
      LEFT JOIN classes c ON cm.class_id = c.id
      WHERE u.id = ?
    `, [userId]);
    
    if (rows.length === 0) {
      console.log("[AUTH] User not found.");
      return res.status(404).json({ error: 'User not found' });
    }
    
    console.log(`[AUTH] User data retrieved for: ${rows[0].username}`);
    res.json(rows[0]);
    
  } catch (error) {
    console.error('[AUTH] Get user error:', error);
    res.status(500).json({ error: 'Failed to get user' });
  }
});

}