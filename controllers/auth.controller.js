const AuthService = require('../services/auth.service');

exports.getUser = async (req, res) => {
  const { user } = req;
  try {
    const { data } = await AuthService.getUser(user.id);
    return res.status(200).json(data);
  } catch (error) {
    console.error('Error fetching user:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

exports.registerUser = async (req, res) => {
  const { email, password, phone, title, first_name, last_name, gender } =
    req.body;
  try {
    const { status, message, token } = await AuthService.registerUser(
      email,
      password,
      phone,
      title,
      first_name,
      last_name,
      gender
    );

    return res.status(status).json({ message, token });
  } catch (error) {
    console.error('Error registering user:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

exports.sendOtp = async (req, res) => {
  const email = req.body.data;

  try {
    const response = await AuthService.generateNewOtp(email);

    res.status(200).json({ message: 'successfully send the OTP', response });
  } catch (error) {
    console.log('problem sending the otp', error);
    throw error;
  }
};

exports.verifyOtp = async (req, res) => {
  const { email, otp, role } = req.body;
  console.log('vjkacv', req.body);
  try {
    const { status, message, token } = await AuthService.verifyOtp(
      email,
      otp,
      role
    );

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 15 * 60 * 10000,
      sameSite: 'lax',
    });

    return res.status(status).json(message);
  } catch (error) {
    console.error('There was an error verifying the OTP code', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};

exports.loginUser = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res
      .status(400)
      .json({ message: 'Email and password are required.' });
  }

  try {
    const { status, message, token } = await AuthService.loginUser(
      email,
      password
    );

    const errorMessages = [
      'INVALID_CREDENTIALS',
      'NOT_VERIFIED',
      'OTP request limit exceeded. Try after 1 min.',
    ];

    if (errorMessages.includes(message)) {
      return res.status(status).json({ message });
    }

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 15 * 60 * 100000,
      sameSite: 'lax',
    });

    return res.status(status).json({ message });
  } catch (error) {
    console.error('Login error:', error.message || error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};

exports.createGoogleUser = async (req, res) => {
  const { credential, clientId } = req.body;
  if (!credential)
    return res.status(400).json({ message: 'No token provided' });

  try {
    const { token, user } = await AuthService.loginWithGoogle(
      credential,
      clientId
    );

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 15 * 60 * 1000,
      sameSite: 'lax',
    });

    res.status(200).json({ user });
  } catch (error) {
    console.error('Google auth error:', error);
    res.status(500).json({ message: 'Token verification failed' });
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
    console.error('OTP verification error:', error);
    return res
      .status(500)
      .json({ error: error.message || 'Internal Server Error' });
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
    console.error('Recovery email error:', error);
    res.status(500).json({ error: error.message || 'Internal Server Error' });
  }
};

exports.resetPassword = async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await AuthService.resetPassword(email, password);

    if (result.status !== 200) {
      return res.status(result.status).json({ message: result.error });
    }

    return res.status(200).json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Password reset error:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};
