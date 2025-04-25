const jwt = require("jsonwebtoken");
const AuthService = require("../services/auth.services");

exports.register = async (req, res) => {
  const { email, password, phone, title, given_name, family_name, gender } =
    req.body;

  try {
    const { status, message, otpId } = await AuthService.registerUser({
      email,
      password,
      phone,
      title,
      given_name,
      family_name,
      gender,
    });

    return res.status(status).json(otpId ? { message, otpId } : { message });
  } catch (err) {
    return res.status(500).json({ error: "Internal server error" });
  }
};

exports.verifyOtp = async (req, res) => {
  const { email, otp } = req.body;

  try {
    const { status, data } = await AuthService.verifyOtp(email, otp);
    return res.status(status).json(data);
  } catch (error) {
    console.error("There was an error verifying the OTP code", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

exports.loginUser = async (req, res) => {
  const { email, password } = req.body;

  try {
    const { status, data } = await AuthService.loginWithOtp(email, password);
    return res.status(status).json(data);
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

exports.createGoogleUser = async (req, res) => {
  const { credential, clientId } = req.body;
  if (!credential)
    return res.status(400).json({ message: "No token provided" });

  try {
    const { token, user } = await AuthService.loginWithGoogle(credential, clientId);

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 15 * 60 * 1000,
      sameSite: "lax",
    });

    res.status(200).json({ user });
  } catch (error) {
    console.error("Google auth error:", error);
    res.status(500).json({ message: "Token verification failed" });
  }
};

exports.verifyRecoveryOTP = async (req, res) => {
  const { email, otp } = req.body;

  try {
    const result = await AuthService.verifyRecoveryOTP(email, otp);
    return res
      .status(result.status)
      .json(result.data || { message: result.message });
  } catch (error) {
    console.error("OTP verification error:", error);
    return res
      .status(500)
      .json({ error: error.message || "Internal Server Error" });
  }
};

exports.sendPasswordRecoveryEmail = async (req, res) => {
  const { email } = req.body;
  try {
    const result = await AuthService.sendPasswordRecoveryEmail(email);
    return res
      .status(result.status)
      .json(result.data || { message: result.message });
  } catch (error) {
    console.error("Recovery email error:", error);
    res.status(500).json({ error: error.message || "Internal Server Error" });
  }
};
