//Moderator side routes

// Note: This app uses `res.render` for server-side rendering with templating engines, unlike `res.json`, which is for API responses.

// Required modules and configurations
const express = require("express");
const jwt = require("jsonwebtoken");
const argon2 = require("argon2");
const User = require("../models/User");
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

// Middleware to check if the user is a moderator 
const isModerator = (req, res, next) => {
  if (req.user.role !== "moderator") {
    return res.status(403).send("Access forbidden: Not a moderator");
  }
  next();
};

// Get the moderator's dashboard with news posts
router.get("/dashboard", authenticate, isModerator, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user) return res.status(404).send("User not found");

    const newsPosts = await NewsPost.find({ visibility: true })
      .populate("uploadedBy", "name role")
      .sort({ priority: 1, datePosted: -1 });

      const { alertMessage } = req.query;


    res.render("moderatorDashboard", { user, newsPosts, alertMessage });
  } catch (err) {
    console.error("Error fetching moderator details or news posts:", err);
    res.status(500).send("Server error");
  }
});

// Update the priority of a news post
router.post("/update-priority/:id", authenticate, isModerator, async (req, res) => {
    try {
      const post = await NewsPost.findById(req.params.id);
      if (!post) return res.status(404).send("Post not found");

      post.priority = req.body.priority;
      await post.save();

      const alertMessage = "Priority updated successfully!";

      res.redirect(
        `/moderator/dashboard?alertMessage=${encodeURIComponent(alertMessage)}`
      );
    } catch (err) {
      console.error("Error updating priority:", err);
      res.status(500).send("Server error");
    }
  }
);

// Report or hide a news post (action can be "report" or "hide")
router.post("/report-hide-post", authenticate, isModerator, async (req, res) => {
  try {
    const { postId, action, reason } = req.body;
    const post = await NewsPost.findById(postId);
    if (!post) return res.status(404).json({ success: false, message: "Post not found" });

    if (action === "report") {
      post.reported = true;
      post.reportReason = reason || "No reason provided";
      post.reportedBy = req.user.id;
      post.visibility = false;
    }

    await post.save();

    let alertMessage = "";
    if (action === "report") {
      alertMessage = "Post reported successfully!";
    } else if (action === "hide") {
      alertMessage = "Post hidden successfully!";
    }

    res.json({ success: true, message: alertMessage }); 
  } catch (err) {
    console.error("Error reporting or hiding post:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Get the moderator's profile page
router.get("/profile", authenticate, isModerator, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password"); 
    if (!user) return res.status(404).send("User not found");

    const { alertMessage } = req.query;

    res.render("moderatorProfile", { user, alertMessage }); 
  } catch (err) {
    console.error("Error fetching moderator profile:", err);
    res.status(500).send("Server error");
  }
});

// Update the moderator's profile (name and/or password)
router.post("/profile", authenticate, isModerator, async (req, res) => {
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


    res.redirect(`/moderator/dashboard?alertMessage=${alertMessage}`);
  } catch (err) {
    console.error("Error updating profile:", err);
    res.status(500).send("Server error");
  }
});

// Render the page to add a new news post
router.get("/add-news", authenticate, isModerator, (req, res) => {
  const alertMessage = req.query.alertMessage ? JSON.parse(req.query.alertMessage) : null;

  res.render("moderatorAddNewsPost", { user: req.user, alertMessage });
});

// Add a new news post (content, priority, and visibility)
router.post("/add-news", authenticate, isModerator, async (req, res) => {
  try {
    const { content, priority } = req.body;

    if (!content.trim()) {
      return res.render("moderatorAddNewsPost", {
        user: req.user,
        alertMessage: {
          message: "Content cannot be empty.",
          type: "error"
        }
      });
    }

    const newPost = new NewsPost({
      content,
      priority: priority || "high",
      visibility: true,
      uploadedBy: req.user.id,
    });

    await newPost.save();

    const alertMessage = "News post added successfully!";

    res.redirect(`/moderator/dashboard?alertMessage=${alertMessage}`);
  } catch (err) {
    console.error("Error adding news post:", err);
    res.status(500).send("Server error");
  }
});

module.exports = router;
