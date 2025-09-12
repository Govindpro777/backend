const mongoose = require('mongoose');

const moodLogSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  emoji: {
    type: String,
    required: true
  },
  scale: {
    type: Number,
    required: true,
    min: 1,
    max: 5
  },
  emotions: [{
    type: String,
    enum: [
      'happy', 'sad', 'angry', 'anxious', 'excited', 'calm', 'frustrated',
      'grateful', 'lonely', 'confident', 'overwhelmed', 'peaceful', 'stressed',
      'hopeful', 'disappointed', 'energetic', 'tired', 'content', 'worried'
    ]
  }],
  notes: {
    type: String,
    maxlength: 1000
  },
  triggers: [{
    type: String,
    maxlength: 50
  }],
  logDate: {
    type: Date,
    default: Date.now
  },
  isDeleted: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true
});

moodLogSchema.index({ user: 1, logDate: -1 });
moodLogSchema.index({ user: 1, createdAt: -1 });

module.exports = mongoose.model('MoodLog', moodLogSchema);