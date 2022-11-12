const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const ForgotPasswordSchema = new Schema({
  userId: String,
  resetString: String,
  createdAt: Date,
  expiresAt: Date
});

const ForgotPassword = mongoose.model(
  "ForgotPassword",
  ForgotPasswordSchema
);

module.exports = ForgotPassword;
