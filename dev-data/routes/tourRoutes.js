const express = require('express');

const tourController = require('../controllers/tourController');

const router = express.Router();

const authController = require('../controllers/authController');

const reviewRouter = require('./reviewRoutes');

//router.param('id', tourController.checkID);

// Nested Route /tours/tourId/reviews
router.use('/:tourId/reviews', reviewRouter);

router
  .route('/top-5-cheaps')
  .get(tourController.aliasTopTours, tourController.getAllTours);

router.route('/tour-stats').get(tourController.getTourStats);
router
  .route('/monthly-plan/:year')
  .get(
    authController.protect,
    authController.restrictTo('admin', 'lead-guid', 'guid'),
    tourController.monthlyPlan
  );

router
  .route('/tours-within/:distance/center/:latlng/unit/:unit')
  .get(tourController.getTourWithin);
// /tours-within/233/center/-40,45/unit/mi --> better way of query string
// /tours-within?distance=233&center=-40,45&unit=mi   ---> another way of query string

router.route('/distances/:latlng/unit/:unit').get(tourController.getDistances);

router
  .route('/')
  .get(tourController.getAllTours)
  .post(
    authController.protect,
    authController.restrictTo('admin', 'lead-guid'),
    tourController.createTour
  );

router
  .route('/:id')
  .get(tourController.getTour)
  .patch(
    authController.protect,
    authController.restrictTo('admin', 'lead-guid'),
    tourController.uploadTourImages,
    tourController.resizeTourImages,
    tourController.updateTour
  )
  .delete(
    authController.protect,
    authController.restrictTo('admin', 'lead-guid'),
    tourController.deleteTour
  );

module.exports = router;
