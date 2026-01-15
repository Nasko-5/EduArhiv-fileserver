-- Users table 
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,  -- unique ID for each user
  username VARCHAR(50) NOT NULL UNIQUE,  -- login name 
  password_hash VARCHAR(255) NOT NULL,  -- password hash
  role ENUM('student', 'student_admin', 'teacher') NOT NULL,  -- What type of user?
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  -- when account was created
  created_by INT,  -- which teacher created this account? (links to users.id)
  FOREIGN KEY (created_by) REFERENCES users(id)  -- 
);

-- Classes table
CREATE TABLE IF NOT EXISTS classes (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL, 
  teacher_id INT NOT NULL,  -- which teacher owns this class?
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (teacher_id) REFERENCES users(id)  -- link to users table
);

-- Link students to classes
CREATE TABLE IF NOT EXISTS class_members (
  id INT AUTO_INCREMENT PRIMARY KEY,
  class_id INT NOT NULL,  -- Which class?
  user_id INT NOT NULL,  -- Which student?
  joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (class_id) REFERENCES classes(id),
  FOREIGN KEY (user_id) REFERENCES users(id),
  UNIQUE KEY unique_membership (class_id, user_id)  -- a student can't join the same class twice
);

