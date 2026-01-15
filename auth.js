
const bcrypt = require('bcrypt');  
const pool = require('./db');  

module.exports = function(app) {
// REGISTER/CREATE USER (for teachers to create student accounts)
// POST /api/auth/register
// Body: { username, password, email, role, classId }
app.post('/auth/register', async (req, res) => {
  try {
    const { username, password, role, classId } = req.body;
    
    // hash the password 
    const passwordHash = await bcrypt.hash(password, 10);
    
    // insert into database
    const [result] = await pool.query(
      'INSERT INTO users (username, password_hash, role, created_by) VALUES (?, ?, ?, ?, ?)',
      [username, passwordHash, role, req.user?.id || null]  // req.user.id = whoever is logged in
    );
    
    const userId = result.insertId;  // get the ID of the new user
    
    // if this is a student and they gave a classId, add them to the class
    if (role === 'student' && classId) {
      await pool.query(
        'INSERT INTO class_members (class_id, user_id) VALUES (?, ?)',
        [classId, userId]
      );
    }
    
    res.json({ 
      success: true, 
      userId: userId,
      message: 'User created!' 
    });
    
  } catch (error) {
    console.error('Register error:', error);
    
    // check if username already exists
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ error: 'Username already exists' });
    }
    
    res.status(500).json({ error: 'Registration failed' });
  }
});

// LOGIN
// POST /api/auth/login
// Body: { username, password }
app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // STEP 1: Find user by username
    // SELECT * means "get all columns"
    // WHERE username = ? means "only rows where username matches"
    const [rows] = await pool.query(
      'SELECT * FROM users WHERE username = ?',
      [username]
    );
    
    // STEP 2: Check if user exists
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    
    const user = rows[0];  // rows is an array, get the first one
    
    // bcrypt.compare compares the plain password with the hashed one
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    
    // login successful! return user info
    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// GET USER INFO (check who's logged in)
app.get('/auth/me/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    
    // SELECT specific columns, and JOIN to get class info
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
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(rows[0]);
    
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Failed to get user' });
  }
});
}