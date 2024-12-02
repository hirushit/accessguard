const mongoose = require("mongoose");
const { Schema } = mongoose;

const userSchema = new Schema(
  {
    name: {
      type: String,
      required: true,
    },

    // User's email address, should be unique for each user
    email: {
      type: String,
      required: true,
      unique: true,
    },

    role: {
      type: String,
      enum: ["admin", "moderator", "user"],
      default: "user",
    },

    password: {
      type: String,
      required: true,
    },

    lastLogin: {
      type: Date,
      default: null,
    },

    // Boolean to indicate whether the user can post news or not
    canPostNews: {
      type: Boolean,
      default: true,
    },

    // Boolean to indicate whether the user can view news or not
    canViewNews: {
      type: Boolean,
      default: true,
    },

    // OTP used for password reset
    passwordResetOtp: {
      type: Number,
      default: null,
    },

    // Expiry time for the OTP
    passwordResetOtpExpires: {
      type: Date,
      default: null,
    },

    // List of devices the user has logged in from, storing IP addresses and timestamps
    loginDevices: [
      {
        ip: { type: String, required: true },
        lastUsed: { type: Date, default: Date.now },
      },
    ],
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);

module.exports = User;
