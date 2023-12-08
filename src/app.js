const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const bcrypt = require('bcrypt');


// Validation schemas using Joi
const signupSchema = Joi.object({
  name: Joi.string().required(),
  location: Joi.string().required(),
  email: Joi.string().email().required(),
  password: Joi.string().required(),
  role: Joi.string().valid('employee', 'manager'),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});

const departmentSchema = Joi.object({
  name: Joi.string().required(),
  manager_id: Joi.number().integer(),
});

const employeeSchema = Joi.object({
  name: Joi.string().required(),
  location: Joi.string().required(),
  email: Joi.string().email().required(),
  password: Joi.string().required(),
  department_id: Joi.number().integer(),
});



const app = express();
app.use(express.json());

// Database connection

const db = mysql.createConnection({
  host     : '103.228.83.115',
  user     : 'root',
  password : 'Cylsys@678',
  database : 'company_db'
});

db.connect(err => {
  if (err) {
    console.error('Database connection error:', err);
  } else {
    console.log('Connected to the database');
  }
});

// Middleware for token validation
const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).send('Access denied');

  jwt.verify(token, 'your_jwt_secret', (err, user) => {
    if (err) return res.status(403).send('Invalid token');
    req.user = user;
    next();
  });
};

// Middleware for request validation
const validateRequest = schema => (req, res, next) => {
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).send(error.details[0].message);
  }
  next();
};


// JWT token generation function
const generateToken = user => {
  return jwt.sign(user, 'your_jwt_secret', { expiresIn: '1h' });
};

// Hash password function
const hashPassword = async password => {
  const saltRounds = 10;
  return bcrypt.hash(password, saltRounds);
};

// Routes

// Signup API
app.post('/signup', validateRequest(signupSchema), async (req, res) => {
  try {
    const hashedPassword = await hashPassword(req.body.password);
    const user = {
      name: req.body.name,
      location: req.body.location,
      email: req.body.email,
      password: hashedPassword,
      role: req.body.role || 'employee',
    };

    db.query('INSERT INTO employees SET ?', user, (error, results) => {
      if (error) {
        console.error('Error creating user:', error);
        return res.status(500).send('Error creating user');
      }

      user.id = results.insertId;
      const token = generateToken({ id: user.id, role: user.role });
      res.status(201).json({ user, token });
    });
  } catch (error) {
    console.error('Error signing up:', error);
    res.status(500).send('Error signing up');
  }
});

// Login API
app.post('/login', validateRequest(loginSchema), async (req, res) => {
  const { email, password } = req.body;

  db.query('SELECT * FROM employees WHERE email = ?', [email], async (error, results) => {
    if (error) {
      console.error('Error during login:', error);
      return res.status(500).send('Error during login');
    }

    if (results.length === 0) {
      return res.status(401).send('Invalid email or password');
    }

    const user = results[0];
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).send('Invalid email or password');
    }

    const token = generateToken({ id: user.id, role: user.role });
    res.json({ user, token });
  });
});

// Department routes (CRUD operations - only accessible to managers)
app.get('/departments', authenticateToken, (req, res) => {
  // Implement logic to get all departments
});

app.post('/departments', authenticateToken, validateRequest(departmentSchema), (req, res) => {
  // Implement logic to create a department
});

app.put('/departments/:id', authenticateToken, validateRequest(departmentSchema), (req, res) => {
  // Implement logic to update a department
});

app.delete('/departments/:id', authenticateToken, (req, res) => {
  // Implement logic to delete a department
});

// Employee routes (CRUD operations - update and delete only accessible to managers)
app.get('/employees', authenticateToken, (req, res) => {
  // Implement logic to get all employees
});

app.post('/employees', authenticateToken, validateRequest(employeeSchema), (req, res) => {
  // Implement logic to create an employee
});

app.put('/employees/:id', authenticateToken, validateRequest(employeeSchema), (req, res) => {
  // Implement logic to update an employee (only accessible to managers)
});

app.delete('/employees/:id', authenticateToken, (req, res) => {
  // Implement logic to delete an employee (only accessible to managers)
});

// Employee filter endpoints
app.get('/employees/location', authenticateToken, (req, res) => {
  // Implement logic to get employees by location in ascending order
});

app.get('/employees/name', authenticateToken, (req, res) => {
  // Implement logic to get employees by name in ascending or descending order
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

