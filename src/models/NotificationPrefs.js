const mongoose = require('mongoose');

const notificationPrefsSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  email: {
    appointments: { type: Boolean, default: true },
    reminders: { type: Boolean, default: true },
    posts: { type: Boolean, default: false },
    newsletters: { type: Boolean, default: false }
  },
  sms: {
    appointments: { type: Boolean, default: true },
    reminders: { type: Boolean, default: false },
    emergencies: { type: Boolean, default: true }
  },
  push: {
    moodReminders: { type: Boolean, default: true },
    appointments: { type: Boolean, default: true },
    posts: { type: Boolean, default: false }
  },
  frequency: {
    moodReminders: {
      type: String,
      enum: ['daily', 'weekly', 'never'],
      default: 'daily'
    },
    weeklyReports: { type: Boolean, default: true }
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('NotificationPrefs', notificationPrefsSchema);