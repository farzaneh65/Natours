const { promisify } = require('util');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const catchAsync = require('../../utils/catchAsync');
const AppError = require('../../utils/appError');
const sendEmail = require('../../utils/email');

const cookieOptions = {
  expires: new Date(
    Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
  ),
  httpOnly: true
};

const signToken = id => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN
  });
};

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);
  if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;
  res.cookie('jwt', token, cookieOptions);

  //Remove user password from displaying output
  user.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user
    }
  });
};

exports.signup = catchAsync(async (req, res, next) => {
  const newUser = await User.create(req.body);
  createSendToken(newUser, 201, res);
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  //1)Check if email and password exist
  if (!email || !password)
    return next(new AppError('Please provide email and password', 400));

  //2)Check if user exists and password is correct
  const user = await User.findOne({ email }).select('+password');
  if (!user || !(await user.correctPassword(password, user.password)))
    return next(new AppError('Invalid email or password!', 401));

  //3)If everything is OK, send token to the client
  createSendToken(user, 200, res);
});

exports.logout = (req, res, next) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true
  });
  res.status(200).json({ status: 'success' });
};

exports.protect = catchAsync(async (req, res, next) => {
  //1) Getting token and check if it's there
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }

  console.log(token);

  if (!token) {
    return next(
      new AppError('You are not logged in! Please log in to get access', 401)
    );
  }
  //2) Verification Token
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
  console.log(decoded);

  //3) Check if user still exists
  const currentUser = await User.findById(decoded.id);
  if (!currentUser)
    return next(new AppError('User does not exist anymore!', 401));
  //4)Check if user's password has been changed after the token was issued
  if (currentUser.changedPasswordAfter(decoded.iat)) {
    console.log(decoded.iat);
    return next(
      new AppError('Password has been changed! Please login again', 401)
    );
  }

  // Grant Access to protected routes
  req.user = currentUser;
  res.locals.user = currentUser;
  next();
});

////// Protect Just for Rendered Pages
exports.loggedIn = async (req, res, next) => {
  try {
    console.log(req.cookies.jwt);
    //1) Getting token and check if it's there
    if (req.cookies.jwt) {
      //2) Verification Token
      const decoded = await promisify(jwt.verify)(
        req.cookies.jwt,
        process.env.JWT_SECRET
      );
      console.log(decoded);

      //3) Check if user still exists
      const currentUser = await User.findById(decoded.id);
      if (!currentUser) return next();
      //4)Check if user's password has been changed after the token was issued
      if (currentUser.changedPasswordAfter(decoded.iat)) {
        console.log(decoded.iat);
        return next(new AppError());
      }

      // There is  a logged in user
      res.locals.user = currentUser;
      return next();
    }
  } catch (err) {
    return next();
  }
  next();
};

exports.restrictTo = (...role) => {
  return (req, res, next) => {
    console.log(req.user.role);
    //role is an array as an parameters and includes allowed roles, so logged in user's role must be in this array
    if (!role.includes(req.user.role))
      return next(new AppError('You dont have permission', 403));
    next();
  };
};

exports.forgotPassword = catchAsync(async (req, res, next) => {
  //1) Get user based on Posted email

  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return next(new AppError('There is no user with this email address', 404));
  }

  //2) Generate the random reset Token

  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  //3)Send it to the user's email

  const resetURL = `${req.protocol}://${req.get(
    'host'
  )}/api/v1/users/resetPassword/${resetToken}`;

  const message = `Forgot your password? Submit a PATCH request with your new password and
   passwordConfirm to: ${resetURL}.\nIf you didn't forget your password, please ignore this email!`;

  try {
    await sendEmail({
      email: user.email,
      subject: 'Your password reset token(valid for 10 min)',
      message
    });
    res.status(200).json({
      status: 'success',
      message: 'Token sent to email'
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });
    console.log(err);
    return next(
      new AppError(
        'There was and error sending the email! please try again.',
        500
      )
    );
  }
});
exports.resetPassword = catchAsync(async (req, res, next) => {
  //1)Get user based on the Token
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');
  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() }
  });

  //2)If token has not expired, and there is user, set the new password
  if (!user)
    return next(new AppError('Invalid token or token has been expired!', 400));
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();
  //3)Update changedPasswordAt property for the user
  //4)log the user in, send JWT
  createSendToken(user, 200, res);
});

exports.updatePassword = catchAsync(async (req, res, next) => {
  //1)Get user from collection
  const user = await User.findById(req.user.id).select('+password');

  //2)Check if the POSTed current password is correct
  if (!(await user.correctPassword(req.body.currentPassword, user.password)))
    return next(new AppError('Invalid Password! try again', 401));

  //3)If so, update password
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  await user.save();
  // User.findByIdAndUpdate does not use because 1: this.password not working in update event(check password confirm)
  //2: non of pre save middlewear functions gonna work!(not encrypted and not set change password time)

  //4)Log user in, send jwt
  createSendToken(user, 200, res);
});
