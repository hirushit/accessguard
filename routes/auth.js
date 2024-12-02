// Authentication routes

// Note: This app uses `res.render` for server-side rendering with templating engines, unlike `res.json`, which is for API responses.

// Required modules and configurations
const express = require("express");
const argon2 = require("argon2");
const jwt = require("jsonwebtoken");
const User = require("../models/User"); 
const nodemailer = require('nodemailer'); 
const crypto = require('crypto');
const UAParser = require("ua-parser-js");
const moment = require("moment-timezone");
const router = express.Router();

// JWT and email configurations
const JWT_SECRET = process.env.JWT_SECRET;
const { EMAIL_USER, EMAIL_PASSWORD } = process.env;

// Transporter for sending email notifications
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASSWORD,
  },
});

// Function to send email when login happens from a new device
const sendNewDeviceLoginEmail = async (user, clientIp, userAgent) => {
  const parser = new UAParser(userAgent);
  const browser = parser.getBrowser();
  const os = parser.getOS();

  const currentISTTime = moment().tz("Asia/Kolkata").format("YYYY-MM-DD HH:mm:ss");

  const mailOptions = {
    from: EMAIL_USER,
    to: user.email,
    subject: "New Device Login Notification",
    text: `
    Hi ${user.name},

    A login was detected from a new device or browser. Here are the details:

    - Browser: ${browser.name || "Unknown"} ${browser.version || ""}
    - Operating System: ${os.name || "Unknown"} ${os.version || ""}
    - IP Address: ${clientIp}
    - Login Time (IST): ${currentISTTime}

    If this was not you, please reset your password immediately to secure your account.
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
  } catch (err) {
    console.error("Error sending login notification email:", err);
  }
};

// Render login page
router.get('/login', (req, res) => {
  const successMessage = req.query.success === 'passwordReset' 
    ? 'Password has been reset successfully. Please log in.' 
    : null;

  res.render('login', { 
    errorMessage: null, 
    successMessage 
  });
});


// Handle login logic, authentication, JWT token generation and send mail if login from new device
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).render("login", { errorMessage: "Email and password are required." });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).render("login", { errorMessage: "Invalid email or password." });
    }

    const isMatch = await argon2.verify(user.password, password);
    if (!isMatch) {
      return res.status(400).render("login", { errorMessage: "Invalid email or password." });
    }

    const token = jwt.sign(
      {
        id: user._id,
        role: user.role,
        canPostNews: user.canPostNews,
        canViewNews: user.canViewNews,
      },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.cookie("authToken", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
    });

    if (user.role === "admin") {
      res.redirect("/admin/dashboard");
    } else if (user.role === "moderator") {
      res.redirect("/moderator/dashboard");
    } else {
      res.redirect("/user/dashboard");
    }

    const clientIp = req.headers["x-forwarded-for"] || req.connection.remoteAddress || "::1";
    const userAgent = req.headers["user-agent"] || "";

    setImmediate(async () => {
      try {
        const knownDevice = user.loginDevices.find((device) => device.ip === clientIp);
        const currentISTTime = moment().tz("Asia/Kolkata").format("YYYY-MM-DD HH:mm:ss");

        if (!knownDevice) {
          user.loginDevices.push({ ip: clientIp, lastUsed: currentISTTime });
          await user.save();

          await sendNewDeviceLoginEmail(user, clientIp, userAgent);
        } else {
          knownDevice.lastUsed = currentISTTime;
          await user.save();
        }
      } catch (error) {
        console.error("Error in asynchronous device check/email notification:", error);
      }
    });
  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).render("login", { errorMessage: "An error occurred while processing your request. Please try again later." });
  }
});

// Render signup page
router.get("/signup", (req, res) => {
  res.render("signup", { errorMessage: null });
});

// Handle user signup and creation
router.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).render("signup", { errorMessage: "All fields are required." });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).render("signup", { errorMessage: "User with this email already exists." });
    }

    if (password.length < 6) {
      return res.status(400).render("signup", { errorMessage: "Password must be at least 6 characters long." });
    }

    const hashedPassword = await argon2.hash(password);

    const user = new User({ name, email, password: hashedPassword });
    await user.save();

    res.status(201).redirect("/auth/login"); 
  } catch (err) {
    console.error("Error signing up:", err);
    res.status(500).render("signup", { errorMessage: "An error occurred. Please try again later." });
  }
});

// Render forgot password page
router.get('/forgot-password', (req, res) => {
  res.render('forgotPassword', { 
    otpRequested: false, 
    errorMessage: null, 
    successMessage: null 
  });
});

// Handle forgot password OTP generation and email sending
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.render('forgotPassword', {
        otpRequested: false,
        errorMessage: 'No user found with this email. Please try again.',
        successMessage: null,
      });
    }

    const otp = crypto.randomInt(100000, 999999);
    user.passwordResetOtp = otp;
    user.passwordResetOtpExpires = Date.now() + 3600000; 
    await user.save();

    const mailOptions = {
      from: EMAIL_USER,
      to: email,
      subject: 'Password Reset OTP',
      text: `Your OTP for resetting your password is: ${otp}`,
    };

    try {
      await transporter.sendMail(mailOptions); 
      return res.render('forgotPassword', {
        otpRequested: true,
        errorMessage: null,
        successMessage: 'OTP sent successfully to your email.',
      });
    } catch (emailError) {
      console.error('Error sending OTP email:', emailError);
      return res.render('forgotPassword', {
        otpRequested: false,
        errorMessage: 'Failed to send OTP email. Please try again later.',
        successMessage: null,
      });
    }
  } catch (err) {
    console.error('Unexpected error in forgot-password:', err);
    return res.render('forgotPassword', {
      otpRequested: false,
      errorMessage: 'An unexpected error occurred. Please try again later.',
      successMessage: null,
    });
  }
});

// Handle password reset logic and updating the password
router.post('/reset-password', async (req, res) => {
  const { otp, newPassword } = req.body;

  try {
    const user = await User.findOne({
      passwordResetOtp: otp,
      passwordResetOtpExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.render('forgotPassword', { 
        otpRequested: true, 
        errorMessage: 'Invalid or expired OTP.', 
        successMessage: null 
      });
    }

    const hashedPassword = await argon2.hash(newPassword);
    user.password = hashedPassword;
    user.passwordResetOtp = undefined;
    user.passwordResetOtpExpires = undefined;
    await user.save();

    res.redirect('/auth/login?success=passwordReset');
  } catch (err) {
    console.error("Error in reset-password:", err);
    res.render('forgotPassword', { 
      otpRequested: true, 
      errorMessage: 'An error occurred while resetting the password.', 
      successMessage: null 
    });
  }
});

// Handle logout and clear auth token
router.get("/logout", (req, res) => {
  res.clearCookie("authToken", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
  });

  res.redirect("/auth/login"); 
});

module.exports = router;
