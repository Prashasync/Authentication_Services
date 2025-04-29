const jwt = require("jsonwebtoken");

exports.generateToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "1d" });
};

exports.generateTempToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: "5m" });
}