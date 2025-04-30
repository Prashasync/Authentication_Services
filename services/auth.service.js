const { SQSClient, SendMessageCommand } = require("@aws-sdk/client-sqs");
const { OAuth2Client } = require("google-auth-library");
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const bcrypt = require("bcrypt");
const logger = require("../utils/logger");
const db = require("../models");
const jwt = require("jsonwebtoken");
const sendEmail = require("../utils/mailer");
const { generateToken, generateTempToken } = require("../utils/jwt");
require("dotenv").config();

// AWS SQS setup
// const sqsClient = new SQSClient({ region: process.env.AWS_REGION });

const AuthService = {
  async getUser(user_id) {
    const user = await db.User.findOne({
      where: { user_id },
    });
    if (!user) {
      return { status: 404, data: { message: "User not found" } };
    }
    return {
      status: 200,
      data: {
        user_id: user.user_id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
        phone: user.phone,
        title: user.title,
      },
    };
  },

  async registerUser(
    email,
    password,
    phone,
    title,
    first_name,
    last_name,
    gender
  ) {
    const user = await db.User.findOne({ where: { email } });
    if (user) {
      return { status: 400, message: "User already exists" };
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000);

    const newUser = await db.User.create({
      email,
      first_name,
      last_name,
      password_hash: hashedPassword,
      phone,
      title,
      gender,
    });

    const newOtp = await db.Otp.create({
      otp_text: otp,
      user_id: newUser.dataValues.user_id,
      valid_until: otpExpiresAt,
      status: "pending",
      created_at: new Date(),
    });

    await sendEmail(
      newUser.dataValues.email,
      "OTP Verification",
      newOtp.dataValues.otp_text
    );
    // if (phone) await sendOTPSMS(phone, otp);

    return {
      status: 200,
      message: "User registered, OTP sent",
      isVerified: newUser.dataValues.isVerified,
      token: newUser.dataValues.email,
    };
  },

  async sendEmailOTP(to, otp, method = "email") {
    const otpId = Math.random().toString(36).substr(2, 9);

    const messageBody = {
      to,
      otp,
      method,
      otpId,
      type: "otp_verification",
    };

    const command = new SendMessageCommand({
      QueueUrl: process.env.SQS_QUEUE_URL,
      MessageBody: JSON.stringify(messageBody),
    });

    await sqsClient.send(command);
    logger.info(`OTP message pushed to SQS for: ${to}, OTP ID: ${otpId}`);

    return otpId;
  },

  async verifyOtp(email, otp) {
    const user = await db.User.findOne({ where: { email } });

    if (!user) {
      return { status: 400, data: { message: "User not found" } };
    }

    const userOtp = await db.Otp.findOne({
      where: { user_id: user.user_id },
    });

    if (!userOtp) {
      return { status: 400, data: { message: "OTP not found" } };
    }

    if (
      userOtp.dataValues.blocked_until &&
      new Date() < new Date(userOtp.dataValues.blocked_until)
    ) {
      return {
        status: 403,
        data: { message: "Too many failed attempts. Try again later." },
      };
    }

    const isOtpInvalid =
      !userOtp.dataValues.otp_text ||
      userOtp.dataValues.otp_text !== otp ||
      new Date() > userOtp.valid_until;

    if (isOtpInvalid) {
      userOtp.dataValues.otp_attempts += 1;
      await userOtp.save();

      if (userOtp.dataValues.otp_attempts >= 5) {
        const blockTime = new Date(Date.now() + 15 * 60 * 1000);
        userOtp.dataValues.blocked_until = blockTime;
        await userOtp.save();

        return {
          status: 403,
          data: { message: "Too many failed attempts. Try after 15 mins." },
        };
      }

      return { status: 400, data: { message: "Invalid or expired OTP" } };
    }

    user.status = true;
    user.otp_text = null;
    user.otp_attempts = 0;
    user.created_at = null;
    user.isVerified = true;
    await user.save();

    const token = generateToken({ id: user.dataValues.user_id });
    return {
      status: 200,
      message: "OTP verified successfully",
      token,
    };
  },

  async loginUser(email, password) {
    const user = await db.User.findOne({ where: { email } });

    if (!user) {
      return {
        status: 400,
        message: "INVALID_CREDENTIALS",
      };
    }

    const isMatch = await bcrypt.compare(
      password,
      user.dataValues.password_hash
    );
    if (!isMatch) {
      return {
        status: 400,
        message: "INVALID_CREDENTIALS",
      };
    }

    if (!user.dataValues.isVerified) {
      return {
        status: 400,
        message: "NOT_VERIFIED",
      };
    }

    const userOtp = await db.Otp.findOne({
      where: { user_id: user.dataValues.user_id },
    });

    if (
      userOtp?.dataValues.created_at &&
      userOtp?.dataValues.valid_until &&
      new Date() < new Date(userOtp.dataValues.valid_until)
    ) {
      const timeDiff =
        new Date().getTime() -
        new Date(userOtp.dataValues.created_at).getTime();

      if (timeDiff < 60000) {
        return {
          status: 429,
          message: "OTP request limit exceeded. Try after 1 min.",
        };
      }
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    if (userOtp) {
      userOtp.otp_text = otp;
      userOtp.valid_until = new Date(Date.now() + 5 * 60 * 1000);
      userOtp.created_at = new Date();
      await userOtp.save();
    } else {
      await db.Otp.create({
        user_id: user.dataValues.user_id,
        otp_text: otp,
        valid_until: new Date(Date.now() + 5 * 60 * 1000),
        created_at: new Date(),
      });
    }
    // await sendEmail(user.dataValues.email, otp, "OTP Verification");
    // if (user.phone) await sendOTPSMS(user.phone, otp);

    const token = generateToken({ id: user.dataValues.user_id });

    return {
      status: 200,
      message: "LOGIN_SUCCESSFUL",
      token,
    };
  },

  async loginWithGoogle(credential, clientId) {
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: clientId,
    });

    const payload = ticket.getPayload();
    const { email, given_name, family_name, sub } = payload;
    const normalizedEmail = email.toLowerCase();

    let user = await db.User.findOne({
      where: { email: normalizedEmail, provider: "google" },
    });

    if (user.rows.length === 0) {
      const newUser = await db.Users.findOne({
        normalizedEmail,
        given_name,
        family_name,
        provider: "google",
        google_id: sub,
      });
      user = newUser;

      await db.Patients.create({
        user_id: newUser.user_id,
        first_name: newUser.given_name,
        last_name: newUser.family_name,
        email: normalizedEmail,
      });
    }

    const jwtToken = jwt.sign(
      { id: user.rows[0].user_id, email: user.rows[0].email },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    return {
      token: jwtToken,
      user: user.rows[0],
    };
  },

  async verifyRecoveryOTP(email, otp) {
    const userCheck = await db.User.findOne({ where: { email } });
    if (userCheck.rows.length === 0) {
      return { status: 400, message: "Invalid OTP or email" };
    }

    const userId = userCheck.rows[0].user_id;
    const otpCheck = await verifyOTP(userId, otp);

    if (otpCheck === "INVALID_OTP") {
      return { status: 400, message: "Invalid OTP code. Please try again" };
    }
    if (otpCheck === "OTP_EXPIRED") {
      return { status: 400, message: "OTP expired." };
    }

    const status = await sendEmail(email, "Prasha Sync Password Reset.");
    if (!status) {
      return {
        status: 400,
        message:
          "There was an error sending the password reset email. Please try again",
      };
    }

    return {
      status: 200,
      data: { message: "OTP verified successfully", otp: otpCheck },
    };
  },

  async sendPasswordRecoveryEmail(email) {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    const userCheck = await db.User.findOne({ where: { email } });
    const emailStatus = await sendEmail(email, otp);
    if (!emailStatus) {
      return {
        status: 400,
        message:
          "There was an error sending the recovery OTP. Please try again",
      };
    }

    return {
      status: 200,
      data: {
        message:
          "If an account exists for that email, a password reset link has been sent.",
        status: emailStatus,
      },
    };
  },
};

module.exports = AuthService;
