const mongoose = require('mongoose');

const questionSchema = new mongoose.Schema({
  text: {
    type: String,
    required: true
  },
  type: {
    type: String,
    enum: ['multiple-choice', 'rating', 'text'],
    default: 'multiple-choice'
  },
  options: [String],
  required: {
    type: Boolean,
    default: true
  }
});

const questionnaireSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    default: 'Mental Health Assessment'
  },
  description: {
    type: String,
    default: 'Please answer the following questions to help us understand your current mental health status.'
  },
  questions: [questionSchema],
  isActive: {
    type: Boolean,
    default: true
  },
  version: {
    type: Number,
    default: 1
  }
}, {
  timestamps: true
});

const responseSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  questionnaire: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Questionnaire',
    required: true
  },
  responses: [{
    questionId: mongoose.Schema.Types.ObjectId,
    answer: mongoose.Schema.Types.Mixed
  }],
  score: {
    type: Number
  },
  category: {
    type: String,
    enum: ['low', 'moderate', 'high', 'severe']
  },
  recommendations: [String]
}, {
  timestamps: true
});

const Questionnaire = mongoose.model('Questionnaire', questionnaireSchema);
const QuestionnaireResponse = mongoose.model('QuestionnaireResponse', responseSchema);

module.exports = { Questionnaire, QuestionnaireResponse };