const express = require('express');
const router = express.Router();
const auth = require('../controllers/auth.controller');

router.post('/register', auth.register);
router.post('/verify', auth.verifyOtp);
router.post('/login', auth.login);
router.post("/create-google-account", auth.createGoogleUser);
router.post("/send-password-recovery-otp", auth.verifyRecoveryOTP);
router.post("/password-recovery", authsendPasswordRecoveryEmail);

module.exports = router;
