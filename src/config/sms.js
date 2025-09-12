const smsConfig = {
  provider: process.env.SMS_PROVIDER || 'mock',
  twilio: {
    accountSid: process.env.TWILIO_SID,
    authToken: process.env.TWILIO_TOKEN,
    from: process.env.TWILIO_FROM
  },
  templates: {
    otpMessage: 'Your Mental Health Platform verification code is: {otp}. Valid for 10 minutes.'
  }
};

module.exports = smsConfig;