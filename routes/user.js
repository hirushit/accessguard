//User side routes

// Note: This app uses `res.render` for server-side rendering with templating engines, unlike `res.json`, which is for API responses.

// Required modules and configurations
const express = require("express");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const argon2 = require("argon2"); 
const NewsPost = require("../models/NewsPost");
const router = express.Router();

// JWT and email configurations
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware to authenticate the user based on JWT token
const authenticate = (req, res, next) => {
  const token = req.cookies.authToken; 

  if (!token) {
    return res.status(401).send("Access denied: No token provided");
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; 
    next(); 
  } catch (err) {
    return res.status(400).send("Invalid token");
  }
};

// Middleware to check if the user is a standard user (not admin or moderator)
const isUser = (req, res, next) => {
  if (req.user.role !== "user") {
    return res.status(403).send("Access forbidden: Not a user");
  }
  next();
};

// Middleware to check if the user has permission to post news
const canPostNews = (req, res, next) => {
  if (!req.user.canPostNews) {
    return res
      .status(403)
      .send("Access forbidden: You are not allowed to post news");
  }
  next();
};

// Get the user's dashboard with news posts
router.get("/dashboard", authenticate, isUser, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password"); 
    if (!user) return res.status(404).send("User not found");

    const newsPosts = await NewsPost.find({ visibility: true }) 
    .populate("uploadedBy", "name role") 
    .sort({ priority: 1, datePosted: -1 }); 

    const { alertMessage } = req.query;

    res.render("userDashboard", { user, newsPosts, alertMessage });
  } catch (err) {
    console.error("Error fetching user details or news posts:", err);
    res.status(500).send("Server error");
  }
});

// Get the user's profile page
router.get("/profile", authenticate, isUser, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password"); 
    if (!user) return res.status(404).send("User not found");

    const { alertMessage } = req.query;

    res.render("userProfile", { user, alertMessage }); 
  } catch (err) {
    console.error("Error fetching user profile:", err);
    res.status(500).send("Server error");
  }
});

// Update the user's profile (name and/or password)
router.post("/profile", authenticate, isUser, async (req, res) => {
  try {
    const { name, oldPassword, newPassword } = req.body;

    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).send("User not found");

    let alertMessage = "";

    if (name) {
      user.name = name;
      alertMessage = "Profile updated successfully!";
    }

    if (oldPassword && newPassword) {
      const isMatch = await argon2.verify(user.password, oldPassword);
      if (!isMatch) return res.status(400).send("Old password is incorrect");

      user.password = await argon2.hash(newPassword);
      alertMessage = "Password updated successfully!";
    }

    await user.save();

    res.redirect(`/user/dashboard?alertMessage=${alertMessage}`);
  } catch (err) {
    console.error("Error updating profile:", err);
    res.status(500).send("Server error");
  }
});

// Render the page to add a new news post (only if the user can post news)
router.get("/add-news", authenticate, canPostNews, (req, res) => {
  res.render("addNewsPost", { user: req.user });
});

// Add a new news post (content, priority, and visibility)
router.post("/add-news", authenticate, canPostNews, async (req, res) => {
  try {
    const { content } = req.body;

    const newPost = new NewsPost({
      content,
      priority: "medium",
      visibility: true, 
      uploadedBy: req.user.id,
    });

    await newPost.save(); 

    const alertMessage = "News post added successfully!";

    res.redirect(
      `/user/dashboard?alertMessage=${encodeURIComponent(alertMessage)}`
    );
  } catch (err) {
    console.error("Error adding news post:", err);
    res.status(500).send("Server error");
  }
});

module.exports = router;
