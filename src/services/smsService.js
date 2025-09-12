const smsConfig = require('../config/sms');
const logger = require('../utils/logger');

class SMSService {
  constructor() {
    this.provider = smsConfig.provider;
    
    if (this.provider === 'twilio') {
      this.initializeTwilio();
    }
  }

  initializeTwilio() {
    try {
      this.twilio = require('twilio')(smsConfig.twilio.accountSid, smsConfig.twilio.authToken);
      logger.info('✅ Twilio SMS service initialized');
    } catch (error) {
      logger.error('❌ Twilio initialization failed:', error);
      this.provider = 'mock'; // Fallback to mock
    }
  }

  async sendOTP(phoneNumber, otp) {
    const message = smsConfig.templates.otpMessage.replace('{otp}', otp);

    if (this.provider === 'mock') {
      return this.mockSend(phoneNumber, message);
    }

    if (this.provider === 'twilio') {
      return this.sendViaTwilio(phoneNumber, message);
    }

    throw new Error('Invalid SMS provider configuration');
  }

  async mockSend(phoneNumber, message) {
    // Mock SMS service for development
    logger.info(`📱 Mock SMS to ${phoneNumber}: ${message}`);
    
    // Simulate API delay
    await new Promise(resolve => setTimeout(resolve, 500));
    
    return {
      success: true,
      messageId: `mock-${Date.now()}`,
      provider: 'mock'
    };
  }

  async sendViaTwilio(phoneNumber, message) {
    try {
      const result = await this.twilio.messages.create({
        body: message,
        from: smsConfig.twilio.from,
        to: phoneNumber
      });

      logger.info(`📱 SMS sent via Twilio to ${phoneNumber}, SID: ${result.sid}`);
      
      return {
        success: true,
        messageId: result.sid,
        provider: 'twilio'
      };
    } catch (error) {
      logger.error('Twilio SMS failed:', error);
      throw error;
    }
  }
}

module.exports = new SMSService();