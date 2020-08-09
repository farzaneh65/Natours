class APIFeatures {
  constructor(query, queryString) {
    this.query = query;
    this.queryString = queryString;
  }

  filter() {
    const queryObj = { ...this.queryString };
    const excludedFields = ['page', 'sort', 'limit', 'fields'];
    excludedFields.forEach(el => delete queryObj[el]);

    ///1B)Advanced Filtering
    let queryStr = JSON.stringify(queryObj);
    queryStr = queryStr.replace(/\b(gte|gt|lt|lte)\b/g, match => `$${match}`);
    //console.log(JSON.parse(queryStr));

    this.query.find(JSON.parse(queryStr));
    return this;
  }

  sort() {
    if (this.queryString.sort) {
      const sortBy = this.queryString.sort.split(',').join(' ');
      //sotr(price,ratingsAverage)==>price ratingsAverage
      this.query = this.query.sort(sortBy);
    } else {
      this.query = this.query.sort('Createdat');
    }
    return this;
  }

  limitFields() {
    if (this.queryString.fields) {
      const fields = this.queryString.fields.split(',').join(' ');
      //Like we did in sort
      this.query = this.query.select(fields);
    } else {
      this.query = this.query.select('-__v');
    }
    return this;
  }

  paginate() {
    const page = this.queryString.page * 1 || 1;
    const limit = this.queryString.limit * 1 || 100;
    const skip = (page - 1) * limit;
    //skip(0):Page1:1-10,skip(10)Page2:11-20,skip(20)Page3:21-30
    this.query = this.query.skip(skip).limit(limit);
    // if (this.queryString.page) {
    //   const numTours = await Tour.countDocuments();
    //   if (skip >= numTours) {
    //     throw new Error('This page is not exist');
    //   }
    // }
    return this;
  }
}

module.exports = APIFeatures;
