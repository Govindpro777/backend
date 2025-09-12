const mongoose = require('mongoose');

const scheduleSlotSchema = new mongoose.Schema({
  day: {
    type: String,
    enum: ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'],
    required: true
  },
  startTime: {
    type: String,
    required: true
  },
  endTime: {
    type: String,
    required: true
  },
  isAvailable: {
    type: Boolean,
    default: true
  }
});

const psychologistSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true
  },
  degree: {
    type: String,
    required: true
  },
  experience: {
    type: Number,
    required: true,
    min: 0
  },
  about: {
    type: String,
    maxlength: 2000
  },
  rating: {
    type: Number,
    min: 0,
    max: 5,
    default: 0
  },
  specializations: [{
    type: String,
    enum: [
      'Anxiety', 'Depression', 'PTSD', 'Relationships', 'Family Therapy',
      'Child Psychology', 'Addiction', 'Eating Disorders', 'Sleep Disorders',
      'Stress Management', 'Grief Counseling', 'Behavioral Issues'
    ]
  }],
  schedule: [scheduleSlotSchema],
  isActive: {
    type: Boolean,
    default: true
  },
  profileImage: {
    type: String
  },
  languages: [String],
  sessionRate: {
    type: Number,
    min: 0
  },
  totalSessions: {
    type: Number,
    default: 0
  },
  reviews: [{
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    rating: {
      type: Number,
      min: 1,
      max: 5
    },
    comment: {
      type: String,
      maxlength: 500
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }]
}, {
  timestamps: true
});

psychologistSchema.virtual('averageRating').get(function() {
  if (this.reviews.length === 0) return 0;
  const sum = this.reviews.reduce((acc, review) => acc + review.rating, 0);
  return Math.round((sum / this.reviews.length) * 10) / 10;
});

psychologistSchema.set('toJSON', { virtuals: true });

module.exports = mongoose.model('Psychologist', psychologistSchema);