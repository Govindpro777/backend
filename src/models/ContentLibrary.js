const mongoose = require('mongoose');

const contentSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    maxlength: 1000
  },
  type: {
    type: String,
    enum: ['music', 'meditation', 'article', 'podcast', 'video', 'reel', 'note', 'journal'],
    required: true
  },
  category: {
    type: String,
    enum: [
      'stress-relief', 'anxiety', 'depression', 'sleep', 'mindfulness',
      'self-care', 'relationships', 'productivity', 'motivation', 'general'
    ]
  },
  url: {
    type: String
  },
  duration: {
    type: Number
  },
  author: {
    type: String
  },
  tags: [String],
  difficulty: {
    type: String,
    enum: ['beginner', 'intermediate', 'advanced']
  },
  isPublished: {
    type: Boolean,
    default: false
  },
  publishedAt: {
    type: Date
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  metadata: {
    fileSize: Number,
    format: String,
    thumbnail: String
  },
  engagement: {
    views: { type: Number, default: 0 },
    likes: { type: Number, default: 0 },
    shares: { type: Number, default: 0 },
    completions: { type: Number, default: 0 }
  }
}, {
  timestamps: true
});

contentSchema.index({ type: 1, category: 1 });
contentSchema.index({ tags: 1 });
contentSchema.index({ isPublished: 1, publishedAt: -1 });

module.exports = mongoose.model('ContentLibrary', contentSchema);