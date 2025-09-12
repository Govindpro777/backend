// const authService = require('../services/authService');
// const { successResponse, errorResponse } = require('../utils/response');
// const { signupSchema, loginSchema, otpSchema } = require('../utils/validators');
// const User = require('../models/User');
// const ParentConsent = require('../models/ParentConsent');
// const logger = require('../utils/logger');
// const { v4: uuidv4 } = require('uuid');

// class AuthController {
//   async signup(req, res) {
//     try {
//       const { error } = signupSchema.validate(req.body);
//       if (error) {
//         const errors = error.details.map(detail => ({
//           field: detail.path[0],
//           message: detail.message
//         }));
//         return errorResponse(res, 'Validation failed', 400, errors);
//       }

//       const result = await authService.register(req.body);

//       return successResponse(res, {
//         tempToken: result.tempToken,
//         message: result.message,
//         email: result.email,
//         contact: result.contact
//       }, 'User registered successfully', 201);
//     } catch (error) {
//       logger.error('Signup error:', error);
//       return errorResponse(res, error.message, 400);
//     }
//   }

//   async verifyContactOTP(req, res) {
//     try {
//       const { error } = otpSchema.validate(req.body);
//       if (error) {
//         return errorResponse(res, 'Invalid OTP format', 400);
//       }

//       const { otp, tempToken } = req.body;

//       if (!tempToken) {
//         return errorResponse(res, 'Verification token is required', 400);
//       }

//       await authService.verifyContactOTP(tempToken, otp);

//       return successResponse(res, null, 'Contact verified successfully');
//     } catch (error) {
//       logger.error('Contact OTP verification error:', error);
//       return errorResponse(res, error.message, 400);
//     }
//   }

//   async verifyEmailOTP(req, res) {
//     try {
//       const { error } = otpSchema.validate(req.body);
//       if (error) {
//         return errorResponse(res, 'Invalid OTP format', 400);
//       }

//       const { otp, tempToken } = req.body;

//       if (!tempToken) {
//         return errorResponse(res, 'Verification token is required', 400);
//       }

//       const result = await authService.verifyEmailOTP(tempToken, otp);

//       if (result.accountCreated) {
//         return successResponse(res, {
//           user: result.user,
//           accountCreated: true,
//           needsParentConsent: result.needsParentConsent
//         }, 'Email verified and account created successfully');
//       } else {
//         return successResponse(res, null, 'Email verified successfully');
//       }
//     } catch (error) {
//       logger.error('Email OTP verification error:', error);
//       return errorResponse(res, error.message, 400);
//     }
//   }

//   async login(req, res) {
//     try {
//       const { error } = loginSchema.validate(req.body);
//       if (error) {
//         return errorResponse(res, 'Invalid email or password format', 400);
//       }

//       const { email, password } = req.body;
//       const result = await authService.login(email, password);

//       return successResponse(res, result, 'Login successful');
//     } catch (error) {
//       logger.error('Login error:', error);
//       return errorResponse(res, error.message, 401);
//     }
//   }

//   async resendOTP(req, res) {
//     try {
//       const { type, tempToken } = req.body; // 'email' or 'contact'

//       if (!tempToken) {
//         return errorResponse(res, 'Verification token is required', 400);
//       }

//       await authService.resendOTP(tempToken, type);

//       return successResponse(res, null, `OTP resent to ${type}`);
//     } catch (error) {
//       logger.error('Resend OTP error:', error);
//       return errorResponse(res, error.message, 400);
//     }
//   }

//   async initiateParentConsent(req, res) {
//     try {
//       const { parentEmail, parentPassword } = req.body;
//       const userId = req.user.id;

//       await authService.initiateParentConsent(userId, parentEmail, parentPassword);

//       return successResponse(res, null, 'Parent consent initiated. OTP sent to parent email.');
//     } catch (error) {
//       logger.error('Parent consent initiation error:', error);
//       return errorResponse(res, error.message, 400);
//     }
//   }

//   async verifyParentOTP(req, res) {
//     try {
//       const { otp } = req.body;
//       const userId = req.user.id;

//       const parentConsent = await ParentConsent.findOne({ userId });
//       if (!parentConsent) {
//         return errorResponse(res, 'Parent consent not found', 404);
//       }

//       if (parentConsent.otp.code !== otp) {
//         return errorResponse(res, 'Invalid OTP', 400);
//       }

//       if (new Date() > parentConsent.otp.expiresAt) {
//         return errorResponse(res, 'OTP expired', 400);
//       }

//       // Mark as verified and activate user
//       parentConsent.isVerified = true;
//       parentConsent.verifiedAt = new Date();
//       await parentConsent.save();

//       await User.findByIdAndUpdate(userId, {
//         $set: { isActive: true },
//         parentConsent: parentConsent._id
//       });

//       return successResponse(res, null, 'Parent consent verified. Account activated.');
//     } catch (error) {
//       logger.error('Parent OTP verification error:', error);
//       return errorResponse(res, error.message, 400);
//     }
//   }

//   async inviteAdmin(req, res) {
//     try {
//       const { email } = req.body;

//       if (!email) {
//         return errorResponse(res, 'Email is required', 400);
//       }

//       // Check if user already exists
//       const existingUser = await User.findOne({ email });
//       if (existingUser) {
//         return errorResponse(res, 'User already exists with this email', 409);
//       }

//       // Generate invite token and store it temporarily
//       const inviteToken = uuidv4();

//       // In a real application, you'd store this in a separate collection or cache
//       // For now, we'll use a simple in-memory store
//       global.adminInvites = global.adminInvites || {};
//       global.adminInvites[inviteToken] = {
//         email,
//         expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
//       };

//       // Send invite email
//       const emailService = require('../services/emailService');
//       await emailService.sendAdminInvite(email, inviteToken);

//       return successResponse(res, { email }, 'Admin invitation sent successfully');
//     } catch (error) {
//       logger.error('Admin invite error:', error);
//       return errorResponse(res, error.message, 400);
//     }
//   }

//   async verifyAdminInvite(req, res) {
//     try {
//       const { token } = req.query;
//       const { password, name } = req.body;

//       if (!global.adminInvites || !global.adminInvites[token]) {
//         return errorResponse(res, 'Invalid or expired invite token', 400);
//       }

//       const invite = global.adminInvites[token];

//       if (new Date() > invite.expiresAt) {
//         delete global.adminInvites[token];
//         return errorResponse(res, 'Invite token expired', 400);
//       }

//       // Create admin user
//       const admin = await authService.createAdminUser(invite.email, password, 'admin');

//       // Update name if provided
//       if (name) {
//         admin.name = name;
//         await User.findByIdAndUpdate(admin._id, { name });
//       }

//       // Clean up invite token
//       delete global.adminInvites[token];

//       return successResponse(res, { user: admin }, 'Admin account created successfully');
//     } catch (error) {
//       logger.error('Admin invite verification error:', error);
//       return errorResponse(res, error.message, 400);
//     }
//   }
// }

// module.exports = new AuthController();

const authService = require('../services/authService');
const { successResponse, errorResponse } = require('../utils/response');
const { signupSchema, loginSchema, otpSchema } = require('../utils/validators');
const User = require('../models/User');
const ParentConsent = require('../models/ParentConsent');
const logger = require('../utils/logger');
const { v4: uuidv4 } = require('uuid');

class AuthController {
  async signup(req, res) {
    try {
      const { error } = signupSchema.validate(req.body);
      if (error) {
        const errors = error.details.map(detail => ({
          field: detail.path[0],
          message: detail.message
        }));
        return errorResponse(res, 'Validation failed', 400, errors);
      }

      const result = await authService.register(req.body);

      return successResponse(res, {
        tempToken: result.tempToken,
        message: result.message,
        email: result.email,
        contact: result.contact,
        requiresParentConsent: result.requiresParentConsent
      }, 'User registered successfully', 201);
    } catch (error) {
      logger.error('Signup error:', error);
      return errorResponse(res, error.message, 400);
    }
  }

  async verifyContactOTP(req, res) {
    try {
      const { error } = otpSchema.validate(req.body);
      if (error) {
        return errorResponse(res, 'Invalid OTP format', 400);
      }

      const { otp, tempToken } = req.body;

      if (!tempToken) {
        return errorResponse(res, 'Verification token is required', 400);
      }

      const result = await authService.verifyContactOTP(tempToken, otp);

      return successResponse(res, result, result.message || 'Contact verified successfully');
    } catch (error) {
      logger.error('Contact OTP verification error:', error);
      return errorResponse(res, error.message, 400);
    }
  }

  async verifyEmailOTP(req, res) {
    try {
      const { error } = otpSchema.validate(req.body);
      if (error) {
        return errorResponse(res, 'Invalid OTP format', 400);
      }

      const { otp, tempToken } = req.body;

      if (!tempToken) {
        return errorResponse(res, 'Verification token is required', 400);
      }

      const result = await authService.verifyEmailOTP(tempToken, otp);

      if (result.accountCreated) {
        if (result.autoLogin) {
          // For users 18+, return token for auto-login
          return successResponse(res, {
            user: result.user,
            token: result.token,
            accountCreated: true,
            autoLogin: true
          }, result.message);
        } else {
          // For users under 18, indicate parent consent needed
          return successResponse(res, {
            user: result.user,
            accountCreated: true,
            needsParentConsent: result.needsParentConsent
          }, result.message);
        }
      } else {
        return successResponse(res, result, result.message || 'Email verified successfully');
      }
    } catch (error) {
      logger.error('Email OTP verification error:', error);
      return errorResponse(res, error.message, 400);
    }
  }

  async login(req, res) {
    try {
      const { error } = loginSchema.validate(req.body);
      if (error) {
        return errorResponse(res, 'Invalid email or password format', 400);
      }

      const { email, password } = req.body;
      const result = await authService.login(email, password);

      return successResponse(res, {
        token: result.token,
        user: result.user
      }, 'Login successful');
    } catch (error) {
      logger.error('Login error:', error);
      return errorResponse(res, error.message, 401);
    }
  }

  async resendOTP(req, res) {
    try {
      const { type, tempToken } = req.body; // 'email' or 'contact'

      if (!tempToken) {
        return errorResponse(res, 'Verification token is required', 400);
      }

      if (!['email', 'contact'].includes(type)) {
        return errorResponse(res, 'Invalid OTP type. Must be "email" or "contact"', 400);
      }

      await authService.resendOTP(tempToken, type);

      return successResponse(res, null, `OTP resent to ${type}`);
    } catch (error) {
      logger.error('Resend OTP error:', error);
      return errorResponse(res, error.message, 400);
    }
  }

  async initiateParentConsent(req, res) {
    try {
      const { parentEmail, parentContact } = req.body;
      // const userId = req.user.id;

      if (!parentEmail || !parentContact) {
        return errorResponse(res, 'Parent email and contact are required', 400);
      }

      const result = await authService.initiateParentConsent(userId, parentEmail, parentContact);

      return successResponse(res, {
        parentEmail: result.parentEmail,
        parentContact: result.parentContact
      }, result.message);
    } catch (error) {
      logger.error('Parent consent initiation error:', error);
      return errorResponse(res, error.message, 400);
    }
  }

  async verifyParentEmailOTP(req, res) {
    try {
      const { otp } = req.body;
      const userId = req.user.id;

      if (!otp) {
        return errorResponse(res, 'OTP is required', 400);
      }

      const result = await authService.verifyParentEmailOTP(userId, otp);

      return successResponse(res, null, result.message);
    } catch (error) {
      logger.error('Parent email OTP verification error:', error);
      return errorResponse(res, error.message, 400);
    }
  }

  async verifyParentContactOTP(req, res) {
    try {
      const { otp } = req.body;
      const userId = req.user.id;

      if (!otp) {
        return errorResponse(res, 'OTP is required', 400);
      }

      const result = await authService.verifyParentContactOTP(userId, otp);

      if (result.accountActivated) {
        // Account activated and auto-logged in
        return successResponse(res, {
          token: result.token,
          user: result.user,
          accountActivated: true,
          autoLogin: true
        }, result.message);
      } else {
        return successResponse(res, null, result.message);
      }
    } catch (error) {
      logger.error('Parent contact OTP verification error:', error);
      return errorResponse(res, error.message, 400);
    }
  }

  async resendParentOTP(req, res) {
    try {
      const { type } = req.body; // 'email' or 'contact'
      const userId = req.user.id;

      if (!['email', 'contact'].includes(type)) {
        return errorResponse(res, 'Invalid OTP type. Must be "email" or "contact"', 400);
      }

      const parentConsent = await ParentConsent.findOne({ userId });
      if (!parentConsent) {
        return errorResponse(res, 'Parent consent not initiated', 404);
      }

      if (type === 'email') {
        await authService.sendParentEmailOTP(parentConsent);
      } else {
        await authService.sendParentContactOTP(parentConsent);
      }

      return successResponse(res, null, `Parent ${type} OTP resent successfully`);
    } catch (error) {
      logger.error('Resend parent OTP error:', error);
      return errorResponse(res, error.message, 400);
    }
  }

  async inviteAdmin(req, res) {
    try {
      const { email } = req.body;

      if (!email) {
        return errorResponse(res, 'Email is required', 400);
      }

      // Check if user already exists
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return errorResponse(res, 'User already exists with this email', 409);
      }

      // Generate invite token and store it temporarily
      const inviteToken = uuidv4();

      // In a real application, you'd store this in a separate collection or cache
      // For now, we'll use a simple in-memory store
      global.adminInvites = global.adminInvites || {};
      global.adminInvites[inviteToken] = {
        email,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
      };

      // Send invite email
      const emailService = require('../services/emailService');
      await emailService.sendAdminInvite(email, inviteToken);

      return successResponse(res, { email }, 'Admin invitation sent successfully');
    } catch (error) {
      logger.error('Admin invite error:', error);
      return errorResponse(res, error.message, 400);
    }
  }

  async verifyAdminInvite(req, res) {
    try {
      const { token } = req.query;
      const { password, name } = req.body;

      if (!global.adminInvites || !global.adminInvites[token]) {
        return errorResponse(res, 'Invalid or expired invite token', 400);
      }

      const invite = global.adminInvites[token];

      if (new Date() > invite.expiresAt) {
        delete global.adminInvites[token];
        return errorResponse(res, 'Invite token expired', 400);
      }

      // Create admin user
      const admin = await authService.createAdminUser(invite.email, password, 'admin');

      // Update name if provided
      if (name) {
        admin.name = name;
        await User.findByIdAndUpdate(admin._id, { name });
      }

      // Clean up invite token
      delete global.adminInvites[token];

      return successResponse(res, { user: admin }, 'Admin account created successfully');
    } catch (error) {
      logger.error('Admin invite verification error:', error);
      return errorResponse(res, error.message, 400);
    }
  }

  // Get current user info
  async getProfile(req, res) {
    try {
      const user = await User.findById(req.user.id).select('-password');
      return successResponse(res, { user: user }, 'Profile retrieved successfully');
    } catch (error) {
      logger.error('Get profile error:', error);
      return errorResponse(res, error.message, 400);
    }
  }
}

module.exports = new AuthController();