const nodemailer = require('nodemailer');
const emailConfig = require('../config/email');
const logger = require('../utils/logger');

class EmailService {
  constructor() {
    this.transporter = null;
    this.initialize();
  }

  async initialize() {
    try {
      this.transporter = nodemailer.createTransport({
        service: emailConfig.service,
        auth: emailConfig.auth
      });

      // Verify connection
      await this.transporter.verify();
      logger.info('✅ Email service initialized successfully');
    } catch (error) {
      logger.error('❌ Email service initialization failed:', error);
    }
  }

  async sendOTP(email, otp) {
    try {
      const mailOptions = {
        from: emailConfig.from,
        to: email,
        subject: emailConfig.templates.otpSubject,
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #333; text-align: center;">Email Verification</h2>
            <p>Your verification code is:</p>
            <div style="text-align: center; margin: 20px 0;">
              <span style="font-size: 32px; font-weight: bold; color: #007bff; letter-spacing: 5px;">${otp}</span>
            </div>
            <p>This code will expire in 10 minutes.</p>
            <p>If you didn't request this verification, please ignore this email.</p>
          </div>
        `
      };

      const result = await this.transporter.sendMail(mailOptions);
      logger.info(`OTP email sent to ${email}`);
      return result;
    } catch (error) {
      logger.error('Failed to send OTP email:', error);
      throw error;
    }
  }

  async sendParentConsentOTP(parentEmail, otp, childName) {
    try {
      const mailOptions = {
        from: emailConfig.from,
        to: parentEmail,
        subject: 'Parent Consent Verification',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #333;">Parent Consent Required</h2>
            <p>Your child <strong>${childName}</strong> has requested to join our Mental Health Platform.</p>
            <p>To provide consent, please enter this verification code:</p>
            <div style="text-align: center; margin: 20px 0;">
              <span style="font-size: 32px; font-weight: bold; color: #007bff; letter-spacing: 5px;">${otp}</span>
            </div>
            <p>This code will expire in 10 minutes.</p>
            <p>If you have any concerns, please contact our support team.</p>
          </div>
        `
      };

      const result = await this.transporter.sendMail(mailOptions);
      logger.info(`Parent consent OTP sent to ${parentEmail}`);
      return result;
    } catch (error) {
      logger.error('Failed to send parent consent OTP:', error);
      throw error;
    }
  }

  async sendAdminInvite(email, inviteToken) {
    try {
      const inviteUrl = `${process.env.APP_BASE_URL}/api/auth/admin/verify-invite?token=${inviteToken}`;

      const mailOptions = {
        from: emailConfig.from,
        to: email,
        subject: emailConfig.templates.adminInviteSubject,
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #333;">Admin Account Invitation</h2>
            <p>You have been invited to join as an administrator.</p>
            <p>Click the link below to complete your registration:</p>
            <div style="text-align: center; margin: 20px 0;">
              <a href="${inviteUrl}" style="background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px;">Accept Invitation</a>
            </div>
            <p>This invitation will expire in 24 hours.</p>
          </div>
        `
      };

      const result = await this.transporter.sendMail(mailOptions);
      logger.info(`Admin invite sent to ${email}`);
      return result;
    } catch (error) {
      logger.error('Failed to send admin invite:', error);
      throw error;
    }
  }
}

module.exports = new EmailService();