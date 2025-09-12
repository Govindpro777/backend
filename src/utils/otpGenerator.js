const crypto = require('crypto');

const generateOTP = (length = 6) => {
  const digits = '0123456789';
  let otp = '';
  
  for (let i = 0; i < length; i++) {
    otp += digits[Math.floor(Math.random() * digits.length)];
  }
  
  return otp;
};

const generateOTPExpiry = (minutes = 10) => {
  return new Date(Date.now() + minutes * 60 * 1000);
};

const isOTPExpired = (expiry) => {
  return new Date() > new Date(expiry);
};

module.exports = {
  generateOTP,
  generateOTPExpiry,
  isOTPExpired
};