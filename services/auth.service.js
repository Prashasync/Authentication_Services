const { SQSClient, SendMessageCommand } = require("@aws-sdk/client-sqs");
const { OAuth2Client } = require("google-auth-library");
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const bcrypt = require("bcrypt");
const logger = require("../utils/logger");
const db = require("../models");
const jwt = require("jsonwebtoken");
const { generateToken, generateTempToken } = require("../utils/jwt");
require("dotenv").config();

// AWS SQS setup
const sqsClient = new SQSClient(
  { 
    region: process.env.AWS_REGION,
    // MessageGroupId: "otp-emails",
    // MessageDeduplicationId: `${Date.now()}`,
     credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  }
  }
);

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
    });

    logger.info(`OTP for ${newUser.dataValues.email}: ${otp}`)

    await this.sendEmailOTP(
      newUser.dataValues.email,
      newOtp.dataValues.otp_text,
      "email",
      newUser.dataValues.phone 
    );
    // if (phone) await sendOTPSMS(phone, otp);

    return {
      status: 200,
      message: "User registered, OTP sent",
      isVerified: newUser.dataValues.isVerified,
      token: newUser.dataValues.email,
    };
  },

  async Verify(email) {
    console.log("email here", email);
  try{
   const user = await db.User.findOne({ where: { email } });
    if (!user) {
      return { status: 400, message: "User does`t exist" };
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000);


  
    const newOtp = await db.Otp.create({
      otp_text: otp,
      user_id: user.dataValues.user_id,
      valid_until: otpExpiresAt,
      status: "pending",
    });

    logger.info(`OTP for ${user.dataValues.email}: ${otp}`)

    await this.sendEmailOTP(
      email,
      newOtp.dataValues.otp_text,
      "email",
    );
    // if (phone) await sendOTPSMS(phone, otp);
   
    return {
      status: 200,
      message: "verifyication OTP sent",
      isVerified: user.dataValues.isVerified,
      token: user.dataValues.email,
    };
  }catch(error){
    console.error("error here is authservice",error);
    throw error;
  }
  },

  async sendEmailOTP(to, otp, method = "email",phone = null) {
    const otpId = "123";
    const messageBody = {
      to,
      otp,
      method,
      otpId,
      type: "otp_verification",
      phone,
    };

    const command = new SendMessageCommand({
      QueueUrl: process.env.SQS_QUEUE_URL,
      MessageBody: JSON.stringify(messageBody),
      MessageGroupId: "otp-emails",
      MessageDeduplicationId: `${Date.now()}`,
    });

    await sqsClient.send(command);
    console.log("coomand for sws", command);
    logger.info(`OTP message pushed to SQS for: ${to}, OTP ID: ${otpId}`);

    return otpId;
  },
    
  

    async verifyOtp(email, otp) {
      
    try{
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
      
      console.log("userotp", userOtp);
      console.log("user",user);
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
  } catch(error){
      console.error("auth service error", error);
      throw error;
  }
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

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    userOtp.otp_text = otp;
    userOtp.valid_until = new Date(Date.now() + 5 * 60 * 1000);
    userOtp.created_at = new Date();
    await userOtp.save();

    await this.sendEmailOTP(
      user.dataValues.email,
      userOtp.otp_text,
      "OTP Verification",
      user.dataValues.phone 
    );
    // if (user.phone) await sendOTPSMS(user.phone, otp);

    const token = generateToken({ id: user.dataValues.user_id });

    return {
      status: 200,
      message: "LOGIN_SUCCESSFUL",
      token,
    };
  },

  // async loginWithGoogle(credential, clientId) {
  //   const ticket = await client.verifyIdToken({
  //     idToken: credential,
  //     audience: clientId,
  //   });

  //   const payload = ticket.getPayload();
  //   const { email, given_name, family_name, sub } = payload;
  //   const normalizedEmail = email.toLowerCase();

  //   let user = await db.User.findOne({
  //     where: { email: normalizedEmail, provider: "google" },
  //   });

  //   if (user.rows.length === 0) {
  //     const newUser = await db.Users.findOne({
  //       normalizedEmail,
  //       given_name,
  //       family_name,
  //       provider: "google",
  //       google_id: sub,
  //     });
  //     user = newUser;

  //     await db.Patients.create({
  //       user_id: newUser.user_id,
  //       first_name: newUser.given_name,
  //       last_name: newUser.family_name,
  //       email: normalizedEmail,
  //     });
  //   }

  //   const jwtToken = jwt.sign(
  //     { id: user.rows[0].user_id, email: user.rows[0].email },
  //     process.env.JWT_SECRET,
  //     { expiresIn: "1d" }
  //   );

  //   return {
  //     token: jwtToken,
  //     user: user.rows[0],
  //   };
  // },


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

  async sendPasswordRecoveryEmail(email) {
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

  const userCheck = await db.User.findOne({ where: { email } });
  if (!userCheck) {
    // For security, do not reveal email existence
    return {
      status: 200,
      data: {
        message: "If an account exists for that email, a password reset link has been sent.",
        status: "OTP sent via SQS",
      },
    };
  }

  // Send OTP via SQS (do not use sendEmail directly)
  await this.sendEmailOTP(email, otp, "OTP", userCheck.phone);

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
      message: "If an account exists for that email, a password reset link has been sent.",
      status: "OTP sent via SQS",
    },
  };
},


  // async verifyRecoveryOTP(email, otp) {
  //   const userCheck = await db.User.findOne({ where: { email } });
  //   if (userCheck.rows.length === 0) {
  //     return { status: 400, message: "Invalid OTP or email" };
  //   }

  //   const userId = userCheck.rows[0].user_id;
  //   const otpCheck = await verifyOTP(userId, otp);

  //   if (otpCheck === "INVALID_OTP") {
  //     return { status: 400, message: "Invalid OTP code. Please try again" };
  //   }
  //   if (otpCheck === "OTP_EXPIRED") {
  //     return { status: 400, message: "OTP expired." };
  //   }

  //   const status = await this.sendEmailOTP(email, "Prasha Sync Password Reset.");
  //   if (!status) {
  //     return {
  //       status: 400,
  //       message:
  //         "There was an error sending the password reset email. Please try again",
  //     };
  //   }

  //   return {
  //     status: 200,
  //     data: { message: "OTP verified successfully", otp: otpCheck },
  //   };
  // },


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

    // OPTIONAL: Notify user via SQS
    await this.sendEmailOTP(email, null, "OTP_VERIFIED", userCheck.phone);

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

  // OPTIONAL: Notify user via SQS
  await this.sendEmailOTP(email, null, "PASSWORD_RESET", user.phone);

  return { status: 200, user };
},


  // async sendPasswordRecoveryEmail(email) {
  //   const otp = Math.floor(100000 + Math.random() * 900000).toString();
  //   const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

  //   const userCheck = await db.User.findOne({ where: { email } });
  //   await this.sendEmailOTP(email, otp, "email");

    
  //   // const emailStatus = await this.sendEmailOTP(email, otp);
  //   // if (!emailStatus) {
  //   //   return {
  //   //     status: 400,
  //   //     message:
  //   //       "There was an error sending the recovery OTP. Please try again",
  //   //   };
  //   // }

  //   return {
  //     status: 200,
  //     data: {
  //       message:
  //         "If an account exists for that email, a password reset link has been sent.",
  //       status: emailStatus,
  //     },
  //   };
  // },
};

module.exports = AuthService;