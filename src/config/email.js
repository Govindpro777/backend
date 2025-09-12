const emailConfig = {
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  from: process.env.EMAIL_FROM || 'Mental Health Platform <noreply@mentalhealthplatform.com>',
  templates: {
    otpSubject: 'Your OTP Verification Code',
    adminInviteSubject: 'Admin Account Invitation'
  }
};

module.exports = emailConfig;