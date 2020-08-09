const Tour = require('../models/tourModel');
//const User = require('../models/userModel');
const catchAsycn = require('../../utils/catchAsync');
const AppError = require('../../utils/appError');
//const factory = require('./handlerFactory');

//exports.getOverview = factory.getAll(Tour);

exports.getOverview = catchAsycn(async (req, res) => {
  //1)Get tour data from collection
  const tours = await Tour.find();

  //2)Build template
  //3)Render that template using tour data from 1)
  res.status(200).render('overview', {
    title: 'All Tours',
    tours
  });
});

exports.getTour = catchAsycn(async (req, res, next) => {
  //1)Get the data,for the requested tour (including reviews and guides)
  const tour = await Tour.findOne({ slug: req.params.slug }).populate({
    path: 'reviews',
    fields: 'review rating user'
  });

  if (!tour) {
    return next(new AppError('There is no tour with that name.', 404));
  }
  //2)Build template

  //3)Render template using data from 1
  res.status(200).render('tour', {
    title: `${tour.name} Tour`,
    tour
  });
});

exports.getLoginForm = (req, res) => {
  res.status(200).render('login', {
    title: 'Log into your account'
  });
};

exports.getAccount = (req, res) => {
  res.status(200).render('account', {
    title: 'Your Account'
  });
};

/// IF Not Using API To Change User Data

// exports.updateUserData = catchAsycn(async (req, res, next) => {
//   const updatedUser = await User.findByIdAndUpdate(
//     req.user.id,
//     {
//       name: req.body.name,
//       email: req.body.email
//     },
//     {
//       new: true,
//       runValidators: true
//     }
//   );
//   res.status(200).render('account', {
//     title: 'Your Account',
//     user: updatedUser
//   });
// });
