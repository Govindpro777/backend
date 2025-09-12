const mongoose = require('mongoose');

const parentConsentSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  parentEmail: {
    type: String,
    required: true,
    lowercase: true
  },
  parentPassword: {
    type: String,
    required: true
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  verifiedAt: {
    type: Date
  },
  otp: {
    code: String,
    expiresAt: Date,
    attempts: { type: Number, default: 0 }
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('ParentConsent', parentConsentSchema);