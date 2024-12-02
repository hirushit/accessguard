// Import required modules
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
require('dotenv').config(); // Load environment variables from .env file

// Initialize the Express app
const app = express();

// Middleware for enabling Cross-Origin Resource Sharing (CORS)
app.use(cors());

// Middleware for parsing cookies
app.use(cookieParser());

// Middleware for parsing JSON and URL-encoded data in requests
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Set the view engine to EJS for server-side rendering
app.set('view engine', 'ejs');

// Middleware to set default local variables for EJS templates
app.use((req, res, next) => {
  res.locals.errorMessage = null; 
  res.locals.successMessage = null; 
  next();
});

// Connect to MongoDB using the connection URI from the environment variables
mongoose
  .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));

// Define the root route
app.get("/", (req, res) => {
  res.render("index"); 
});

// Define route handlers for authentication and role-specific functionalities
app.use('/auth', require('./routes/auth')); // Authentication-related routes
app.use('/admin', require('./routes/admin')); // Admin-specific routes
app.use('/user', require('./routes/user')); // User-specific routes
app.use('/moderator', require('./routes/moderator')); // Moderator-specific routes

// Start the server on the specified port
const PORT = process.env.X_ZOHO_CATALYST_LISTEN_PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
