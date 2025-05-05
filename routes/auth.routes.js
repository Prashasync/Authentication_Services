const express = require("express");
const router = express.Router();
const auth = require("../controllers/auth.controller");
const authMiddleware = require("../middlewares/auth");

router.get("/profile", authMiddleware, auth.getUser);

router.post("/login", auth.loginUser);
router.post("/register", auth.registerUser);
router.post("/verify-otp", auth.verifyOtp);
router.post("/create-google-account", auth.createGoogleUser);
router.post("/send-password-recovery-otp", auth.verifyRecoveryOTP);
router.post("/password-recovery", auth.sendPasswordRecoveryEmail);

module.exports = router;
