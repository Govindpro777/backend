// const mongoose = require('mongoose');

// const parentConsentSchema = new mongoose.Schema({
//   userId: {
//     type: mongoose.Schema.Types.ObjectId,
//     ref: 'User',
//     required: true
//   },
//   parentEmail: {
//     type: String,
//     required: true,
//     lowercase: true
//   },
//   parentPassword: {
//     type: String,
//     required: true
//   },
//   isVerified: {
//     type: Boolean,
//     default: false
//   },
//   verifiedAt: {
//     type: Date
//   },
//   otp: {
//     code: String,
//     expiresAt: Date,
//     attempts: { type: Number, default: 0 }
//   }
// }, {
//   timestamps: true
// });

// module.exports = mongoose.model('ParentConsent', parentConsentSchema);

const mongoose = require('mongoose');

const parentConsentSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  parentEmail: {
    type: String,
    required: true,
    lowercase: true,
    trim: true
  },
  parentContact: {
    type: String,
    required: true
  },
  emailOtp: {
    code: {
      type: String,
      required: true
    },
    expiresAt: {
      type: Date,
      required: true
    },
    attempts: {
      type: Number,
      default: 0,
      max: 3
    },
    verified: {
      type: Boolean,
      default: false
    }
  },
  contactOtp: {
    code: {
      type: String,
      required: true
    },
    expiresAt: {
      type: Date,
      required: true
    },
    attempts: {
      type: Number,
      default: 0,
      max: 3
    },
    verified: {
      type: Boolean,
      default: false
    }
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  verifiedAt: {
    type: Date
  }
}, {
  timestamps: true
});

// Index for efficient lookups
parentConsentSchema.index({ userId: 1 });
parentConsentSchema.index({ parentEmail: 1 });
parentConsentSchema.index({ createdAt: 1 });

// Clean up expired OTPs
parentConsentSchema.index({ 'emailOtp.expiresAt': 1 }, { expireAfterSeconds: 0 });
parentConsentSchema.index({ 'contactOtp.expiresAt': 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('ParentConsent', parentConsentSchema);