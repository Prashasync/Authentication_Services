const { SQSClient, SendMessageCommand } = require("@aws-sdk/client-sqs");
const { OAuth2Client } = require("google-auth-library");
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const bcrypt = require("bcrypt");
const logger = require("../utils/logger");
const db = require("../models");
const { sendEmail } = require("../utils/mailer");
require("dotenv").config();


// AWS SQS setup
const sqsClient = new SQSClient({ region: process.env.AWS_REGION });

const AuthService = {
  async sendEmailOTP(to, otp, method = "email") {
    try {
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
    } catch (error) {
      logger.error(`Failed to queue OTP message: ${error.message}`);
      throw new Error("OTP queueing failed");
    }
  },

  async registerUser(
    email,
    password,
    phone,
    title,
    first_name,
    family_name,
    gender
  ) {
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return { status: 400, message: "User already exists" };
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000);

    const newUser = await User.create({
      email,
      given_name,
      family_name,
      hashedPassword,
      title,
      gender,
      otp,
      otpExpiresAt,
    });

    await sendEmailOTP(email, otp);
    if (phone) await sendOTPSMS(phone, otp);

    return {
      status: 200,
      message: "User registered, OTP sent",
      otpId: newUser.id,
    };
  },

  async verifyOtp(email, otp) {
    const user = await User.findOne({ where: { email } });

    if (!user) {
      return { status: 400, data: { message: "User not found" } };
    }

    if (user.blockeduntil && new Date() < new Date(user.blockeduntil)) {
      return {
        status: 403,
        data: { message: "Too many failed attempts. Try again later." },
      };
    }

    const isOtpInvalid =
      !user.otp || user.otp !== otp || new Date() > user.otpExpiresAt;

    if (isOtpInvalid) {
      user.otpattempts += 1;
      await user.save();

      if (user.otpattempts >= 5) {
        const blockTime = new Date(Date.now() + 15 * 60 * 1000);
        user.blockeduntil = blockTime;
        user.otpblockeduntil = blockTime;
        await user.save();

        return {
          status: 403,
          data: { message: "Too many failed attempts. Try after 15 mins." },
        };
      }

      return { status: 400, data: { message: "Invalid or expired OTP" } };
    }

    user.isVerified = true;
    user.otp = null;
    user.otpattempts = 0;
    user.otpRequestedAt = null;
    await user.save();

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    return {
      status: 200,
      data: { message: "OTP verified successfully", token },
    };
  },

  async loginWithOtp(email, password) {
    const user = await User.findOne({ where: { email } });

    if (!user || !user.isVerified) {
      return {
        status: 400,
        data: { message: "User not found or not verified" },
      };
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return {
        status: 400,
        data: { message: "Wrong password" },
      };
    }

    if (
      user.otpRequestedAt &&
      user.otpExpiresAt &&
      new Date() < new Date(user.otpExpiresAt)
    ) {
      const timeDiff =
        new Date().getTime() - new Date(user.otpRequestedAt).getTime();

      if (timeDiff < 60000) {
        return {
          status: 429,
          data: { message: "OTP request limit exceeded. Try after 1 min." },
        };
      }
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    user.otp = otp;
    user.otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000);
    user.otpRequestedAt = new Date();
    await user.save();

    await sendEmailOTP(email, otp);
    if (user.phone) await sendOTPSMS(user.phone, otp);

    return {
      status: 200,
      data: { message: "User logged in, OTP sent", otpId: user.id },
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
