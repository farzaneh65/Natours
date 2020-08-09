const path = require('path');
const express = require('express');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const cookieParser = require('cookie-parser');
//const expressBrute = require('express-brute');
//const redisStore = require('express-brute-redis');

const tourRouter = require('./dev-data/routes/tourRoutes');
const userRouter = require('./dev-data/routes/userRoutes');
const reviewRouter = require('./dev-data/routes/reviewRoutes');
const viewRouter = require('./dev-data/routes/viewRoutes');

const AppError = require('./utils/appError');
const globalErrorHandler = require('./dev-data/controllers/errorController');

const app = express();

app.set('view engine', 'pug');
app.set('views', path.join(`${__dirname}/dev-data`, 'views'));
// 1)GLOBAL MIDDLEWARES

//Serving static files
app.use(express.static(path.join(__dirname, 'public')));
// Set Security HTTP headers
app.use(helmet());

//Limit requests from same APIs
const limiter = rateLimit({
  max: 100,
  windowMs: 60 * 60 * 1000,
  message: 'Too many requests from this IP, please try again'
});
app.use('/api', limiter);

//Limit Login attempts
// if (process.env.NODE_ENV === 'development') {
//   const store = new expressBrute.MemoryStore();
// }

// const store = new redisStore({
//   host: '127.0.0.1',
//   port: 3000
// });
// const bruteforce = new expressBrute(store);
// app.use('/api/v1/users/login', bruteforce.prevent);

//Body parser, reading data from body into req.body
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

//Data sanizitation against NoSQL query injection
app.use(mongoSanitize());

//Data sanizitation against XSS
app.use(xss());

//Prevent parameter pollution
app.use(
  hpp({
    whitelist: [
      'duration',
      'ratingsAverage',
      'ratingsQuantity',
      'maxGroupSize',
      'difficulty',
      'price'
    ]
  })
);

// Develplment Logging
console.log(process.env.NODE_ENV);
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

//Test Middleware
app.use((req, res, next) => {
  req.requestTime = new Date().toISOString();
  console.log(req.cookies);
  next();
});
/////// Routing ///////////

app.use('/', viewRouter);
app.use('/api/v1/tours', tourRouter);
app.use('/api/v1/users', userRouter);
app.use('/api/v1/reviews', reviewRouter);

app.all('*', (req, res, next) => {
  // const err = new Error(`Cant find ${req.originalUrl}`);
  // err.statusCode = 404;
  // err.status = 'fail';
  next(new AppError(`Cant find ${req.originalUrl}`, 404));
});

//////// Error Handling Middlewear
app.use(globalErrorHandler);

module.exports = app;
