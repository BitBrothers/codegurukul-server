var mongoose = require('mongoose');
var Course = require('./Course');

var leadSchema = new mongoose.Schema({
  name: String,
  email: String,
  createDate: {
    type: Date,
    default: Date.now()
  },
  courses: [{
    _id : {type: mongoose.Schema.Types.ObjectId, ref: 'Course' }
  }]
})

module.exports = mongoose.model('Lead', leadSchema);