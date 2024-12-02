//Admin side routes

// Note: This app uses `res.render` for server-side rendering with templating engines, unlike `res.json`, which is for API responses.

// Required modules and configurations
const express = require("express");
const router = express.Router();
const argon2 = require("argon2");
const User = require("../models/User");
const NewsPost = require("../models/NewsPost");
const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware to authenticate users using JWT token from cookies
const authenticate = (req, res, next) => {
  const token = req.cookies.authToken;
  if (!token) {
    return res.status(401).redirect("/auth/login");
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    console.error("Invalid token:", err);
    return res.status(400).redirect("/auth/login");
  }
};

// Middleware to check if the user is an Admin
const isAdmin = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).send("Access forbidden: Not an admin");
  }
  next();
};

// Route for rendering the admin dashboard
router.get("/dashboard", authenticate, isAdmin, async (req, res) => {
  try {
    const users = await User.find().select("-password");
    const newsPosts = await NewsPost.find()
      .populate("uploadedBy", "name")
      .sort({ datePosted: -1 });

    const message = req.query.message || ''; 
    res.render("adminDashboard", { user: req.user, users, newsPosts, message });
  } catch (err) {
    console.error("Error fetching data:", err);
    res.status(500).send("Server error");
  }
});

// Route to update user roles (Moderator, User)
router.post("/update-role/:userId", authenticate, isAdmin, async (req, res) => {
  try {
    const { role } = req.body;
    const user = await User.findById(req.params.userId);

    if (!user) {
      return res.status(404).send("User not found");
    }

    user.role = role;
    await user.save();

    res.redirect("/admin/dashboard");
  } catch (err) {
    console.error("Error updating user role:", err);
    res.status(500).send("Server error");
  }
});

// Route to update the visibility and priority of a news post
router.post("/update-news/:id", authenticate, isAdmin, async (req, res) => {
  const { visibility, priority } = req.body;
  try {
    const newsPost = await NewsPost.findByIdAndUpdate(
      req.params.id,
      { visibility, priority },
      { new: true }
    );
    res.redirect("/admin/dashboard");
  } catch (err) {
    console.error("Error updating news post:", err);
    res.status(500).send("Server error");
  }
});

// Route to render the "Create User" page
router.get("/create-user", authenticate, isAdmin, async (req, res) => {
  res.render("createUser");
});

// Route for creating a new user 
router.post("/create-user", authenticate, isAdmin, async (req, res) => {
  const { name, email, password, role } = req.body;

  try {
    const hashedPassword = await argon2.hash(password);

    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      role,
    });

    await newUser.save();

    res.redirect("/admin/dashboard?message=User created successfully");
  } catch (err) {
    console.error("Error creating user:", err);
    res.status(500).send("Server Error");
  }
});

// Route to render the "Create News" page
router.get("/create-news", authenticate, isAdmin, async (req, res) => {
  res.render("createNews");
});

// Route for creating a new news post
router.post("/create-news", authenticate, isAdmin, async (req, res) => {
  const { content, priority } = req.body;

  try {
    const newsPost = new NewsPost({
      content,
      priority,
      uploadedBy: req.user.id,
    });
    await newsPost.save();
    res.redirect("/admin/dashboard");
  } catch (err) {
    console.error("Error creating news post:", err);
    res.status(500).send("Failed to create news post");
  }
});

// Route to render the "Change Password" page
router.get("/change-password", authenticate, isAdmin, (req, res) => {
  res.render("changePassword");
});

// Route for changing password 
router.post("/change-password", authenticate, isAdmin, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).send("User not found");
    }

    const isPasswordValid = await argon2.verify(user.password, currentPassword);
    if (!isPasswordValid) {
      return res.redirect('/admin/change-password?errorMessage=' + encodeURIComponent('Current password is incorrect.'));
    }

    const hashedPassword = await argon2.hash(newPassword);
    user.password = hashedPassword;
    await user.save();

    res.redirect('/admin/dashboard?successMessage=' + encodeURIComponent('Password changed successfully!'));

  } catch (err) {
    console.error("Error changing password:", err);
    res.status(500).send("Server error");
  }
});

// Route to render the "Edit User" page
router.get("/edit-user/:id", authenticate, isAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).send("User not found");
    }
    res.render("editUser", { user });
  } catch (err) {
    console.error("Error fetching user for edit:", err);
    res.status(500).send("Server error");
  }
});

// Route for updating user information 
router.post("/edit-user/:id", authenticate, isAdmin, async (req, res) => {
  const { name, email, role, password, canPostNews, canViewNews } = req.body;
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).send("User not found");
    }

    user.name = name;
    user.email = email;
    user.role = role;

    user.canPostNews = canPostNews === "on";
    user.canViewNews = canViewNews === "on";

    if (password) {
      user.password = await argon2.hash(password);
    }

    await user.save();
    
    res.redirect("/admin/dashboard?message=User updated successfully");
  } catch (err) {
    console.error("Error updating user:", err);
    res.status(500).send("Server error");
  }
});

// Route to view reported posts 
router.get("/view-reported-posts", authenticate, isAdmin, async (req, res) => {
  try {
    const reportedPosts = await NewsPost.find({ reported: true })
      .sort({ datePosted: -1 })
      .populate("uploadedBy", "name")
      .exec();

    const alertMessage = req.query.alertMessage; 

    res.render("viewReportedPosts", { reportedPosts, alertMessage });
  } catch (err) {
    console.error("Error fetching reported posts:", err);
    res.status(500).send("Server error");
  }
});

// Route for updating reported post 
router.post("/update-reported-post/:id", authenticate, isAdmin, async (req, res) => {
    try {
      const { visibility, reported } = req.body;
      const postId = req.params.id;

      const post = await NewsPost.findById(postId);
      if (!post) return res.status(404).send("Post not found");

      post.visibility = visibility === "true";
      post.reported = reported === "true";

      await post.save();

      const alertMessage = "Post updated successfully!";
      res.redirect(
        `/admin/view-reported-posts?alertMessage=${encodeURIComponent(
          alertMessage
        )}`
      );
    } catch (err) {
      console.error("Error updating reported post:", err);
      res.status(500).send("Server error");
    }
  }
);

// Route to delete user
router.get('/delete-user/:id', authenticate, isAdmin, async (req, res) => {
  const userId = req.params.id;

  try {
    if (req.user && req.user.id.toString() === userId) {
      return res.status(400).send("You cannot delete yourself.");
    }

    await User.findByIdAndDelete(userId);
    res.redirect('/admin/dashboard?message=User deleted successfully');
  } catch (err) {
    console.error("Error deleting user:", err);
    res.status(500).send("Failed to delete user.");
  }
});

// Route to delete news post 
router.get('/delete-news/:id', authenticate, isAdmin, async (req, res) => {
  const postId = req.params.id;
  try {
    await NewsPost.findByIdAndDelete(postId);
    res.redirect('/admin/dashboard?message=News post deleted successfully');
  } catch (err) {
    console.error("Error deleting news post:", err);
    res.status(500).send("Failed to delete news post.");
  }
});

module.exports = router;
