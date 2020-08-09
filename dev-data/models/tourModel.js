const mongoose = require('mongoose');
const slugify = require('slugify');
//const User = require('./userModel');
//const validator = require('validator');

const tourSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'A tour must have a name'],
      unique: true,
      trim: true,
      maxlength: [
        40,
        'A tour name must have less or equal then 40 characteres'
      ],
      minlength: [10, 'A tour name must have more or equal then 10 characteres']
      //validate: [validator.isAlpha, 'Tour name must be only contain characters']
    },
    slug: String,
    duration: {
      type: Number,
      required: [true, 'A tour must have a duration']
    },
    maxGroupSize: {
      type: Number,
      required: [true, 'A tour must have a maxGroupSize']
    },
    difficulty: {
      type: String,
      required: [true, ''],
      enum: {
        values: ['easy', 'medium', 'difficult'],
        message: 'Difficulty is either:easy,medium,difficult'
      }
    },
    ratingsAverage: {
      type: Number,
      default: 4.5,
      min: [1, 'Rating must be above 1.0'],
      max: [5, 'Rating must be below 5.0'],
      set: val => Math.round(val * 10) / 10 //4.66666, 46.6666, 47, 4.7
    },
    ratingsQuantity: {
      type: Number,
      default: 0
    },
    price: {
      type: Number,
      required: [true, 'A tour must have a price']
    },
    priceDiscount: {
      type: Number,
      validate: {
        validator: function(val) {
          //this only points to current doc on NEW document creation !!Not working for UPDATE
          return val < this.price;
        },
        message: 'Discount price ({VALUE}) should be below reqular price'
      }
    },
    summary: {
      type: String,
      trim: true,
      required: [true, 'A tour must have a summary']
    },
    description: {
      type: String,
      trim: true
    },
    imageCover: {
      type: String,
      required: [true, 'A tour must have a Cover Image']
    },
    images: [String],
    Createdat: {
      type: Date,
      default: Date.now()
    },
    startDates: [Date],
    secretTour: {
      type: Boolean,
      default: false
    },
    startLocation: {
      //GeoJSON
      type: {
        type: String,
        default: 'Point',
        enum: ['Point']
      },
      coordinates: [Number],
      address: String,
      description: String
    },
    locations: [
      {
        type: {
          type: String,
          default: 'Point',
          enum: ['Point']
        },
        coordinates: [Number],
        address: String,
        description: String,
        day: Number
      }
    ],
    guides: [{ type: mongoose.Schema.ObjectId, ref: 'User' }]
  },
  {
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
  }
);

//tourSchema.index({ price: 1 });
tourSchema.index({ price: 1, ratingsAverage: -1 });
tourSchema.index({ slug: 1 });
tourSchema.index({ startLocation: '2dsphere' });

tourSchema.virtual('durationWeek').get(function() {
  if (this.duration >= 7) {
    return this.duration / 7;
  }
});

/// virtual populate
tourSchema.virtual('reviews', {
  ref: 'Review',
  foreignField: 'tour',
  localField: '_id'
});

/// DOCUMENT MIDDLEWARE: run before .save() and .create()   !!! Not before insertMany
tourSchema.pre('save', function(next) {
  this.slug = slugify(this.name, { lower: true });
  next();
});

// EMBEDING Guides in Toures
// tourSchema.pre('save', async function(next) {
//   const guidesPromises = this.guides.map(async id => await User.findById(id));
//   this.guides = await Promise.all(guidesPromises);
// });

/// DOCUMENT MIDDLEWARE: run after .save() and .create()   !!! Not after insertMany
// tourSchema.post('save', function(doc, next) {
//   console.log('will save document...');
//   next();
// });
// tourSchema.post('save', function(doc, next) {
//   console.log(doc);
//   next();
// });

//////////////Query Middlewares /////////////
tourSchema.pre(/^find/, function(next) {
  this.find({ secretTour: { $ne: true } });
  this.start = Date.now();
  next();
});

tourSchema.pre(/^find/, function(next) {
  this.populate({
    path: 'guides',
    select: '-__v -passwordChangedAt'
  });
  next();
});

tourSchema.post(/^find/, function(docs, next) {
  console.log(`The query took ${Date.now() - this.start} milliseconds`);
  next();
});

/////////Aggregation Middlwares ////////////////
// tourSchema.pre('aggregate', function(next) {
//   this.pipeline().unshift({ $match: { secretTour: { $ne: true } } });
//   next();
// });

const Tour = mongoose.model('Tour', tourSchema);

module.exports = Tour;
