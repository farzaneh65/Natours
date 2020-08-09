/* eslint-disable no-lonely-if */
const AppError = require('../../utils/appError');

const handleCastErrorDB = err => {
  const message = `Invalid ${err.path}: ${err.value}`;
  return new AppError(message, 400);
};

const handleDuplicateFieldDB = err => {
  const value = err.errmsg.match(/(["'])(.*?[^\\])\1/)[0];
  const message = `Duplicate field value: ${value}. Please use another one`;
  return new AppError(message, 400);
};

const handleValidationErrorDB = err => {
  const errors = Object.values(err.errors).map(el => el.message);
  const message = `Invalid Input Data: ${errors.join('. ')}`;
  return new AppError(message, 400);
};
const handleJWTError = () =>
  new AppError('Invalid Token! Please login again', 401);

const handleJWTExpiredError = () =>
  new AppError('Your token has expired! Please login again.', 401);

const sendErrorDev = (res, req, err) => {
  ///A)API
  if (req.originalUrl.startsWith('/api')) {
    return res.status(err.statusCode).json({
      status: err.status,
      error: err,
      message: err.message,
      stack: err.stack
    });
  }
  ///B)RENDERED WEBSITE
  return res.status(err.statusCode).render('error', {
    title: 'Something went wrong!',
    msg: err.message
  });
};

const sendErrorProd = (res, req, err) => {
  ///A)API
  if (req.originalUrl.startsWith('/api')) {
    // Operational, trusted error:send message to client
    if (err.isOperational) {
      return res.status(err.statusCode).json({
        status: err.status,
        message: err.message
      });
      //B) Programming or other unknown error: dont leak error details
    }
    //1)Log Error
    console.log('Error!', err);
    //2) Send generic message
    return res.status(500).json({
      status: 'error',
      message: 'Something went so wrong!'
    });
  }
  ///B)RENDERED
  if (err.isOperational) {
    return res.status(err.statusCode).render('error', {
      title: 'Something went wrong!',
      msg: err.message
    });
    // Programming or other unknown error: dont leak error details
  }
  //1)Log Error
  console.log('Error!', err);
  //2)Send generic message
  return res.status(err.statusCode).render('error', {
    title: 'Something went wrong!',
    msg: 'Please try again later.'
  });
};

module.exports = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';
  if (process.env.NODE_ENV === 'development') {
    sendErrorDev(res, req, err);
  } //if (process.env.NODE_ENV === 'production')
  else {
    let error = { ...err };
    error.message = err.message;
    if (error.name === 'CastError') error = handleCastErrorDB(error);
    if (error.code === 11000) error = handleDuplicateFieldDB(error);
    if (error.name === 'ValidationError')
      error = handleValidationErrorDB(error);
    if (error.name === 'JsonWebTokenError') error = handleJWTError();
    if (error.name === 'TokenExpiredError') error = handleJWTExpiredError();
    sendErrorProd(res, req, error);
  }
};
