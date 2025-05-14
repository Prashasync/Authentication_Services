const { SQSClient, SendMessageCommand } = require("@aws-sdk/client-sqs");
const { OAuth2Client } = require("google-auth-library");
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const bcrypt = require("bcrypt");
const logger = require("../utils/logger");
const db = require("../models");
const jwt = require("jsonwebtoken");
const sendEmail = require("../utils/mailer");
const { generateToken } = require("../utils/jwt");
require("dotenv").config();

const AuthService = {
  async getUser(user_id) {
    const user = await db.Patient.findOne({
      where: { user_id },
    });
    if (!user) {
      return { status: 404, data: { message: "User not found" } };
    }
    return {
      data: user,
    };
  },

  async registerUser(email, password, title, first_name, last_name, gender) {
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

    const now = new Date();

    if (userOtp.blocked_until && now < new Date(userOtp.blocked_until)) {
      return {
        status: 403,
        data: { message: "Too many failed attempts. Try again later." },
      };
    }

    const isOtpInvalid =
      !userOtp.otp_text ||
      userOtp.otp_text !== otp ||
      now > new Date(userOtp.valid_until);

    if (isOtpInvalid) {
      userOtp.otp_attempts += 1;

      if (userOtp.otp_attempts >= 5) {
        userOtp.blocked_until = new Date(now.getTime() + 15 * 60 * 1000);
      }

      await userOtp.save();

      const message =
        userOtp.otp_attempts >= 5
          ? "Too many failed attempts. Try after 15 mins."
          : "Invalid or expired OTP";

      return { status: 400, data: { message } };
    }

    userOtp.otp_text = otp;
    userOtp.otp_attempts = 0;
    userOtp.blocked_until = null;
    userOtp.status = true;
    await userOtp.save();

    user.isVerified = true;
    await user.save();

    await db.Patient.create({
      first_name: user.dataValues.first_name,
      last_name: user.dataValues.last_name,
      user_id: user.dataValues.user_id,
      gender: user.dataValues.gender,
      title: user.dataValues.title,
    });

    const token = generateToken({ id: user.user_id });

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

    // if (
    //   userOtp?.dataValues.created_at &&
    //   userOtp?.dataValues.valid_until &&
    //   new Date() < new Date(userOtp.dataValues.valid_until)
    // ) {
    //   const timeDiff =
    //     new Date().getTime() -
    //     new Date(userOtp.dataValues.created_at).getTime();

    //   if (timeDiff < 60000) {
    //     return {
    //       status: 429,
    //       message: "OTP request limit exceeded. Try after 1 min.",
    //     };
    //   }
    // }

    // const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // if (userOtp) {
    //   userOtp.otp_text = otp;
    //   userOtp.valid_until = new Date(Date.now() + 5 * 60 * 1000);
    //   userOtp.created_at = new Date();
    //   await userOtp.save();
    // } else {
    //   await db.Otp.create({
    //     user_id: user.dataValues.user_id,
    //     otp_text: otp,
    //     valid_until: new Date(Date.now() + 5 * 60 * 1000),
    //     created_at: new Date(),
    //   });
    // }
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
    try {
      const ticket = await client.verifyIdToken({
        idToken: credential,
        audience: clientId,
      });

      const payload = ticket.getPayload();
      const { email, given_name, family_name, sub } = payload;
      const normalizedEmail = email.toLowerCase();

      let socialLogin = await db.SocialLogins.findOne({
        where: { provider_id: sub, provider_name: "google" },
      });

      let userId;

      if (!socialLogin) {
        const newPatient = await db.Patient.create({
          first_name: given_name,
          last_name: family_name,
          email: normalizedEmail,
        });

        socialLogin = await db.SocialLogins.create({
          email: normalizedEmail,
          provider_name: "google",
          provider_id: sub,
          user_id: newPatient.patient_id,
        });

        userId = newPatient.patient_id;
      } else {
        userId = socialLogin.user_id;
      }

      const jwtToken = jwt.sign({ id: userId }, process.env.JWT_SECRET, {
        expiresIn: "1d",
      });

      return {
        token: jwtToken,
        user: {
          id: userId,
          email: normalizedEmail,
        },
      };
    } catch (error) {
      console.error("Error verifying Google token:", error);
      throw new Error("Google token verification failed");
    }
  },

  async verifyRecoveryOTP(email, otp) {
    try {
      const userCheck = await db.User.findOne({ where: { email } });
      if (!userCheck) {
        return { status: 400, message: "Invalid OTP or email" };
      }

      const userId = userCheck.user_id;
      const otpRecord = await db.Otp.findOne({
        where: {
          user_id: userId,
          status: "pending",
        },
      });
      if (!otpRecord) {
        return { status: 400, message: "Invalid OTP or email" };
      }
      if (otpRecord.otp_text !== otp) {
        return { status: 400, message: "Invalid OTP code. Please try again" };
      }
      if (new Date() > otpRecord.valid_until) {
        return { status: 400, message: "OTP expired" };
      }

      otpRecord.status = "validated";
      otpRecord.validated_at = new Date();
      await otpRecord.save();

      return {
        status: 200,
        data: { message: "OTP verified successfully" },
      };
    } catch (error) {
      console.error("Error verifying OTP:", error);
      return {
        status: 500,
        message: "Internal server error. Please try again later.",
      };
    }
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

    const otpRecord = await db.Otp.findOne({
      where: { user_id: userCheck.user_id },
    });

    if (otpRecord) {
      otpRecord.otp_text = otp;
      otpRecord.valid_until = expiresAt;
      otpRecord.status = "pending";
      await otpRecord.save();
    } else {
      await db.Otp.create({
        user_id: userCheck.user_id,
        otp_text: otp,
        valid_until: expiresAt,
        created_at: new Date(),
        status: "pending",
      });
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

  async resetPassword(email, password) {
    console.log("Resetting password for email:", email);
    console.log("New password", password);



    const user = await db.User.findOne({ where: { email } });
    if (!user) {
      return { status: 400, error: "Invalid user" };
    }

    const otpRecord = await db.Otp.findOne({
      where: {
        user_id: user.user_id,
        status: "validated",
      },
    });

    if (!otpRecord) {
      return { status: 400, error: "OTP not validated" };
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    user.password_hash = hashedPassword;
    await user.save();

    otpRecord.status = "used";
    await otpRecord.save();

    return { status: 200, user };
  },
};

module.exports = AuthService;
