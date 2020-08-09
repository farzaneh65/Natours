const express = require('express');

const viewController = require('../controllers/viewController');

const authController = require('../controllers/authController');

const router = express.Router();

router.get('/', authController.loggedIn, viewController.getOverview);

router.get('/tour/:slug', authController.loggedIn, viewController.getTour);

router.get('/login', authController.loggedIn, viewController.getLoginForm);

router.get('/me', authController.protect, viewController.getAccount);

/// IF Not Using API To Change User Data

// router.post(
//   '/submit-user-data',
//   authController.protect,
//   viewController.updateUserData
// );

module.exports = router;
