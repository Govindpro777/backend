const mongoose = require('mongoose');

const appointmentSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  psychologist: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Psychologist',
    required: true
  },
  dateTime: {
    type: Date,
    required: true
  },
  duration: {
    type: Number,
    default: 60
  },
  status: {
    type: String,
    enum: ['scheduled', 'completed', 'cancelled', 'no-show'],
    default: 'scheduled'
  },
  notes: {
    type: String,
    maxlength: 500
  },
  sessionNotes: {
    type: String,
    maxlength: 2000
  },
  rating: {
    type: Number,
    min: 1,
    max: 5
  },
  feedback: {
    type: String,
    maxlength: 1000
  },
  meetingLink: {
    type: String
  },
  cancellationReason: {
    type: String,
    maxlength: 300
  },
  cancelledBy: {
    type: String,
    enum: ['user', 'psychologist', 'admin']
  }
}, {
  timestamps: true
});

appointmentSchema.index({ user: 1, dateTime: -1 });
appointmentSchema.index({ psychologist: 1, dateTime: 1 });

module.exports = mongoose.model('Appointment', appointmentSchema);