const { SQSClient, SendMessageCommand } = require('@aws-sdk/client-sqs');
const { OAuth2Client } = require('google-auth-library');
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const bcrypt = require('bcrypt');
const logger = require('../utils/logger');
const db = require('../models');
const jwt = require('jsonwebtoken');
const { generateToken } = require('../utils/jwt');
require('dotenv').config();

// AWS SQS setup
const sqsClient = new SQSClient({
  region: process.env.AWS_REGION,
  // MessageGroupId: "otp-emails",
  // MessageDeduplicationId: `${Date.now()}`,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

const AuthService = {
  async getUser(user_id) {
    const user = await db.Patient.findOne({
      where: { user_id },
    });
    if (!user) {
      return { status: 404, data: { message: 'User not found' } };
    }
    return {
      data: user,
    };
  },

  async registerUser(email, password, title, first_name, last_name, gender) {
    const user = await db.User.findOne({ where: { email } });
    if (user) {
      return { status: 400, message: 'User already exists' };
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
      status: 'pending',
      roles: 'ACCOUNT_VERIFICATION',
      otp_attempts: 0,
    });

    logger.info(`OTP for ${newUser.dataValues.email}: ${otp}`);

    await this.sendEmailOTP(
      newUser.dataValues.email,
      newOtp.dataValues.otp_text,
      'email',
      newUser.dataValues.phone,
      newOtp.dataValues.otp_id,
      'account_verification'
    );
    // if (phone) await sendOTPSMS(phone, otp);

    return {
      status: 200,
      message: 'User registered, OTP sent',
      isVerified: newUser.dataValues.isVerified,
      token: newUser.dataValues.email,
    };
  },

  async generateNewOtp(email) {
    logger.info('generating Otp for the eamil', email);
    try {
      const user = await db.User.findOne({ where: { email } });
      if (!user) {
        return { status: 400, message: 'User doesn`t exist' };
      }

      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000);
      const newOtp = await db.Otp.create({
        otp_text: otp,
        user_id: user.dataValues.user_id,
        otp_attempts: 0,
        valid_until: otpExpiresAt,
        status: null,
        roles: 'ACCOUNT_VERIFICATION',
      });

      logger.info(`OTP for ${user.dataValues.email}: ${otp}`);

      await this.sendEmailOTP(
        email,
        newOtp.dataValues.otp_text,
        'email',
        (phone = null),
        newOtp.dataValues.otp_id,
        'account_verification'
      );
      // if (phone) await sendOTPSMS(phone, otp);

      return {
        status: 200,
        message: 'verifyication OTP sent',
        isVerified: user.dataValues.isVerified,
        token: user.dataValues.email,
      };
    } catch (error) {
      console.error('error here is authservice', error);
      throw error;
    }
  },

  async updateUser(user_id, currentPassword, newPassword) {
    const user = await db.User.findOne({ where: { user_id } });
    if (!user) {
      return { status: 404, message: 'User not found' };
    }

    if (!currentPassword || !newPassword) {
      return { status: 400, message: 'Current and new passwords are required' };
    }

    const passwordRegex =
      /^(?=.*[0-9])(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,}$/;
    if (!passwordRegex.test(newPassword)) {
      return {
        status: 400,
        message:
          'Password must be at least 8 characters long and contain at least one number and one special character',
      };
    }

    const isMatch = await bcrypt.compare(
      currentPassword,
      user.dataValues.password_hash
    );
    if (!isMatch) {
      return { status: 400, message: 'Current password is incorrect' };
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    user.password_hash = hashedNewPassword;
    await user.save();

    return {
      status: 200,
      message: 'Password updated successfully',
      data: {
        user_id: user.user_id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
      },
    };
  },

  async sendEmailOTP(
    to,
    otp,
    method = 'email',
    phone,
    otpId,
    type = 'otp_verification'
  ) {
    const messageBody = {
      to,
      otp,
      method,
      otpId,
      type,
      phone,
    };
    // logger.info('SQS message payload message body', messageBody);
    logger.info(`SQS message payload: ${JSON.stringify(messageBody)}`);

    const command = new SendMessageCommand({
      QueueUrl: process.env.SQS_QUEUE_URL,
      MessageBody: JSON.stringify(messageBody),
      MessageGroupId: 'otp-emails',
      MessageDeduplicationId: `${Date.now()}`,
    });

    await sqsClient.send(command);
    const userOtp = await db.Otp.findOne({
      where: { otp_id: otpId },
    });

    if (userOtp) {
      userOtp.status = 'pending';
      userOtp.updatedAt = new Date();
      await userOtp.save();
    }

    logger.info(`OTP message pushed to SQS for: ${to}, OTP ID: ${otpId}`);
    return otpId;
  },

  async verifyOtp(email, otp, role) {
    try {
      const user = await db.User.findOne({ where: { email } });

      if (!user) {
        return { status: 400, message: 'User not found' };
      }

      const userOtp = await db.Otp.findOne({
        where: {
          user_id: user.user_id,
          roles: role,
          status: 'pending',
        },
        order: [['createdAt', 'DESC']],
      });

      if (!userOtp) {
        return { status: 400, data: { message: 'OTP not found' } };
      }
      const now = new Date();

      if (
        userOtp.dataValues.blocked_until &&
        now < new Date(userOtp.dataValues.blocked_until)
      ) {
        return {
          status: 403,
          data: { message: 'Too many failed attempts. Try again later.' },
        };
      }

      const isValidOtp = userOtp.otp_text === otp;

      if (!isValidOtp) {
        userOtp.otp_attempts += 1;

        if (userOtp.otp_attempts >= 5) {
          userOtp.blocked_until = new Date(now.getTime() + 15 * 60 * 1000);
        }

        const message =
          userOtp.otp_attempts >= 5
            ? 'Too many failed attempts. Try after 15 mins.'
            : 'Invalid or expired OTP';

        return { status: 400, message };
      }

      userOtp.otp_text = otp;
      userOtp.blocked_until = null;
      userOtp.status = 'validated';
      userOtp.roles = 'ACCOUNT_VERIFICATION';
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
        message: 'OTP verified successfully',
        token,
      };
    } catch (error) {
      console.error('auth service error', error);
      throw error;
    }
  },

  async loginUser(email, password) {
    const user = await db.User.findOne({ where: { email } });
    console.log('Queried user:', user?.dataValues);

    if (!user) {
      console.log('User not found.');
      return {
        status: 400,
        message: 'INVALID_CREDENTIALS',
      };
    }

    const isMatch = await bcrypt.compare(
      password,
      user.dataValues.password_hash
    );
    console.log('Password match:', isMatch);
    if (!isMatch) {
      console.log('Password is incorrect.');
      return {
        status: 400,
        message: 'INVALID_CREDENTIALS',
      };
    }

    if (!user.dataValues.isVerified) {
      console.log('User is not verified.');
      return {
        status: 400,
        message: 'NOT_VERIFIED',
      };
    }

    const token = generateToken({ id: user.dataValues.user_id });
    return {
      status: 200,
      message: 'LOGIN_SUCCESSFUL',
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
        where: { provider_id: sub, provider_name: 'google' },
      });

      let user;

      if (socialLogin) {
        user = await db.User.findOne({
          where: { email: normalizedEmail },
        });
        if (!user) {
          user = await db.User.create({
            email: normalizedEmail,
            first_name: given_name,
            last_name: family_name,
          });
        }
      } else {
        user = await db.User.findOne({
          where: { email: normalizedEmail },
        });
        if (!user) {
          user = await db.User.create({
            email: normalizedEmail,
            first_name: given_name,
            last_name: family_name,
          });

          await db.Patient.create({
            first_name: given_name,
            last_name: family_name,
            email: normalizedEmail,
            user_id: user.user_id,
          });
        }

        socialLogin = await db.SocialLogins.create({
          email: normalizedEmail,
          provider_name: 'google',
          provider_id: sub,
          user_id: user.user_id,
        });
      }

      const jwtToken = jwt.sign({ id: user.user_id }, process.env.JWT_SECRET, {
        expiresIn: '1d',
      });

      return {
        token: jwtToken,
        user: {
          id: user.user_id,
          email: normalizedEmail,
        },
      };
    } catch (error) {
      console.error('Error verifying Google token:', error);
      throw new Error('Google token verification failed');
    }
  },

  async sendPasswordRecoveryEmail(email) {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    const userCheck = await db.User.findOne({ where: { email } });
    if (!userCheck) {
      return {
        status: 200,
        data: {
          message:
            'If an account exists for that email, a password reset link has been sent.',
          status: 'OTP sent via SQS',
        },
      };
    }

    await this.sendEmailOTP(
      email,
      otp,
      'OTP',
      userCheck.phone,
      otpRecord.otp_id,
      'forgot_password'
    );

    const otpRecord = await db.Otp.findOne({
      where: { user_id: userCheck.user_id },
    });

    if (otpRecord) {
      otpRecord.otp_text = otp;
      otpRecord.valid_until = expiresAt;
      otpRecord.status = 'pending';
      otpRecord.roles = 'FORGET_PASSWORD';
      await otpRecord.save();
    } else {
      await db.Otp.create({
        user_id: userCheck.user_id,
        otp_text: otp,
        otp_attempts: 0,
        valid_until: expiresAt,
        created_at: new Date(),
        status: 'pending',
        roles: 'FORGET_PASSWORD',
      });
    }

    return {
      status: 200,
      data: {
        message:
          'If an account exists for that email, a password reset link has been sent.',
        status: 'OTP sent via SQS',
      },
    };
  },

  async verifyRecoveryOTP(email, otp) {
    try {
      const userCheck = await db.User.findOne({ where: { email } });
      if (!userCheck) {
        return { status: 400, message: 'Invalid OTP or email' };
      }

      const userId = userCheck.user_id;
      const otpRecord = await db.Otp.findOne({
        where: {
          user_id: userId,
          status: 'pending',
        },
      });
      if (!otpRecord) {
        return { status: 400, message: 'Invalid OTP or email' };
      }
      if (otpRecord.otp_text !== otp) {
        return { status: 400, message: 'Invalid OTP code. Please try again' };
      }
      if (new Date() > otpRecord.valid_until) {
        return { status: 400, message: 'OTP expired' };
      }

      otpRecord.status = 'validated';
      otpRecord.validated_at = new Date();
      await otpRecord.save();

      // OPTIONAL: Notify user via SQS
      await this.sendEmailOTP(email, null, 'OTP_VERIFIED', userCheck.phone);

      return {
        status: 200,
        data: { message: 'OTP verified successfully' },
      };
    } catch (error) {
      console.error('Error verifying OTP:', error);
      return {
        status: 500,
        message: 'Internal server error. Please try again later.',
      };
    }
  },

  async resetPassword(email, password) {
    const user = await db.User.findOne({ where: { email } });
    if (!user) {
      return { status: 400, error: 'Invalid user' };
    }

    const otpRecord = await db.Otp.findOne({
      where: {
        user_id: user.user_id,
        status: 'validated',
      },
    });

    if (!otpRecord) {
      return { status: 400, error: 'OTP not validated' };
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    user.password_hash = hashedPassword;
    await user.save();

    otpRecord.status = 'used';
    await otpRecord.save();

    // OPTIONAL: Notify user via SQS
    await this.sendEmailOTP(
      email,
      null,
      'PASSWORD_RESET',
      user.phone,
      'password_reset'
    );

    return { status: 200, user };
  },
};

module.exports = AuthService;
