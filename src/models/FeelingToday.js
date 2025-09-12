const mongoose = require('mongoose');

const feelingTodaySchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  feeling: {
    type: String,
    enum: ['excellent', 'good', 'okay', 'not-great', 'unsatisfied'],
    required: true
  },
  emoji: {
    type: String,
    required: true
  },
  notes: {
    type: String,
    maxlength: 500
  },
  date: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

feelingTodaySchema.index({ user: 1, date: -1 });

module.exports = mongoose.model('FeelingToday', feelingTodaySchema);