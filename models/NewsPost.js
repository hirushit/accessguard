const mongoose = require("mongoose");
const { Schema } = mongoose;

const newsPostSchema = new Schema(
  {
    content: {
      type: String,
      required: true,
    },

    // User ID of the person who uploaded the news post
    uploadedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    datePosted: {
      type: Date,
      default: Date.now,
    },

    priority: {
      type: String,
      enum: ["high", "medium", "low"],
      default: "medium",
    },

    // Visibility of the news post (whether it is visible to the public or not)
    visibility: {
      type: Boolean,
      default: true,
    },

    // Indicates whether the post has been reported
    reported: {
      type: Boolean,
      default: false,
    },

    // Reason for the report (if applicable)
    reportReason: {
      type: String,
      default: "",
    },

    // User ID of the person who uploaded the news post
    reportedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
  },
  { timestamps: true }
);

const NewsPost = mongoose.model("NewsPost", newsPostSchema);

module.exports = NewsPost;
