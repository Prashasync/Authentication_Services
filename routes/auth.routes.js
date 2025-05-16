const express = require("express");
const router = express.Router();
const auth = require("../controllers/auth.controller");
// const authMiddleware = require("../middlewares/auth");

router.use("/create-google-account", (req, res, next) => {
  res.setHeader("Cross-Origin-Opener-Policy", "unsafe-none");
  res.setHeader("Cross-Origin-Embedder-Policy", "unsafe-none");  
  next();
});

// router.get("/profile", authMiddleware, auth.getUser)/;

router.post("/login", auth.loginUser);
router.post("/register", auth.registerUser);
router.post("/verify-otp", auth.verifyOtp);
router.post("/send-otp", auth.sendOtp);
router.post("/create-google-account", auth.createGoogleUser);
router.post("/reset-password", auth.resetPassword);
router.post("/verify-password-recovery-otp", auth.verifyRecoveryOTP);
router.post("/send-password-recovery", auth.sendPasswordRecoveryEmail);

module.exports = router;
