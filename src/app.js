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
  let token;

  // Check if the token is in the Authorization header
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }
  // Check if the token is in the request body
  else if (req.body.token) {
    token = req.body.token;
  }

  if (!token) return res.status(401).send('Access denied: Missing token');

  console.log('Received token:', token); // Add this line for debugging

  jwt.verify(token, 'your_jwt_secret', (err, user) => {
    if (err) {
      console.error('Invalid token:', err);
      return res.status(403).send('Invalid token');
    }
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

// Get all departments
app.get('/departments', authenticateToken, (req, res) => {
  // Implement logic to get all departments
  db.query('SELECT * FROM departments', (error, results) => {
    if (error) {
      console.error('Error fetching departments:', error);
      return res.status(500).send('Error fetching departments');
    }
    res.json(results);
  });
});

// Create a department
app.post('/departments', authenticateToken, validateRequest(departmentSchema), (req, res) => {
  const department = {
    name: req.body.name,
    manager_id: req.user.id, // The manager's ID is extracted from the token
  };

  db.query('INSERT INTO departments SET ?', department, (error, results) => {
    if (error) {
      console.error('Error creating department:', error);
      return res.status(500).send('Error creating department');
    }

    department.id = results.insertId;
    res.status(201).json(department);
  });
});

// Update a department
app.put('/departments/:id', authenticateToken, validateRequest(departmentSchema), (req, res) => {
  const departmentId = req.params.id;
  const updatedDepartment = {
    name: req.body.name,
    manager_id: req.user.id, // Ensure that only the manager of the department can update it
  };

  db.query('UPDATE departments SET ? WHERE id = ?', [updatedDepartment, departmentId], (error) => {
    if (error) {
      console.error('Error updating department:', error);
      return res.status(500).send('Error updating department');
    }

    res.status(200).send('Department updated successfully');
  });
});

// Delete a department
app.delete('/departments/:id', authenticateToken, (req, res) => {
  const departmentId = req.params.id;

  db.query('DELETE FROM departments WHERE id = ?', [departmentId], (error) => {
    if (error) {
      console.error('Error deleting department:', error);
      return res.status(500).send('Error deleting department');
    }

    res.status(200).send('Department deleted successfully');
  });
});

// Employee routes (CRUD operations - update and delete only accessible to managers)

// Get all employees
app.get('/employees', authenticateToken, (req, res) => {
  // Implement logic to get all employees
  db.query('SELECT * FROM employees', (error, results) => {
    if (error) {
      console.error('Error fetching employees:', error);
      return res.status(500).send('Error fetching employees');
    }
    res.json(results);
  });
});

// Create an employee
app.post('/employees', authenticateToken, validateRequest(employeeSchema), (req, res) => {
  const employee = {
    name: req.body.name,
    location: req.body.location,
    email: req.body.email,
    password: req.body.password, // You may want to hash this password before saving
    department_id: req.body.department_id,
  };

  db.query('INSERT INTO employees SET ?', employee, (error, results) => {
    if (error) {
      console.error('Error creating employee:', error);
      return res.status(500).send('Error creating employee');
    }

    employee.id = results.insertId;
    res.status(201).json(employee);
  });
});

// Update an employee (only accessible to managers)
app.put('/employees/:id', authenticateToken, validateRequest(employeeSchema), (req, res) => {
  const employeeId = req.params.id;
  const { name, location, email, department_id } = req.body;

  const updatedEmployee = {
    name,
    location,
    email,
    department_id,
  };

  console.log('Updating employee with ID:', employeeId);
  console.log('Updated employee data:', updatedEmployee);

  db.query('UPDATE employees SET ? WHERE id = ?', [updatedEmployee, employeeId], (error, results) => {
    if (error) {
      console.error('Error updating employee:', error);
      return res.status(500).send('Error updating employee');
    }

    if (results.affectedRows === 0) {
      // No rows were affected, indicating that the employee with the given ID was not found
      return res.status(404).send('Employee not found');
    }

    res.status(200).send('Employee updated successfully');
  });
});




// Delete an employee (only accessible to managers)
app.delete('/employees/:id', authenticateToken, (req, res) => {
  const employeeId = req.params.id;

  db.query('DELETE FROM employees WHERE id = ?', [employeeId], (error) => {
    if (error) {
      console.error('Error deleting employee:', error);
      return res.status(500).send('Error deleting employee');
    }

    res.status(200).send('Employee deleted successfully');
  });
});

// Employee filter endpoints

// Get employees by location in ascending order
app.get('/employees/location', authenticateToken, (req, res) => {
  // Implement logic to get employees by location in ascending order
  db.query('SELECT * FROM employees ORDER BY location ASC', (error, results) => {
    if (error) {
      console.error('Error fetching employees by location:', error);
      return res.status(500).send('Error fetching employees by location');
    }
    res.json(results);
  });
});

// Get employees by name in ascending or descending order
app.get('/employees/name', authenticateToken, (req, res) => {
  // Implement logic to get employees by name in ascending or descending order
  const order = req.query.order || 'ASC';
  db.query(`SELECT * FROM employees ORDER BY name ${order}`, (error, results) => {
    if (error) {
      console.error('Error fetching employees by name:', error);
      return res.status(500).send('Error fetching employees by name');
    }
    res.json(results);
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
