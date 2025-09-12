// const jwt = require('jsonwebtoken');
// const bcrypt = require('bcrypt');
// const User = require('../models/User');
// const PendingUser = require('../models/PendingUser');
// const ParentConsent = require('../models/ParentConsent');
// const jwtConfig = require('../config/jwt');
// const emailService = require('./emailService');
// const smsService = require('./smsService');
// const { generateOTP, generateOTPExpiry } = require('../utils/otpGenerator');
// const logger = require('../utils/logger');
// const { v4: uuidv4 } = require('uuid');

// class AuthService {
//   async generateToken(user) {
//     const payload = {
//       id: user._id,
//       email: user.email,
//       role: user.role
//     };

//     return jwt.sign(payload, jwtConfig.secret, {
//       expiresIn: jwtConfig.expiresIn,
//       issuer: jwtConfig.issuer,
//       audience: jwtConfig.audience
//     });
//   }

//   async verifyToken(token) {
//     try {
//       return jwt.verify(token, jwtConfig.secret);
//     } catch (error) {
//       throw new Error('Invalid token');
//     }
//   }

//   async register(userData) {
//     const { name, email, password, contact, age } = userData;

//     // Check if user already exists in main User collection
//     const existingUser = await User.findOne({
//       $or: [{ email }, { contact }]
//     });

//     if (existingUser) {
//       throw new Error('User with this email or contact already exists');
//     }

//     // Check if pending user already exists
//     const existingPendingUser = await PendingUser.findOne({
//       $or: [{ email }, { contact }]
//     });

//     if (existingPendingUser) {
//       // Delete existing pending user to allow re-registration
//       await PendingUser.deleteOne({ _id: existingPendingUser._id });
//     }

//     // Hash password
//     const hashedPassword = await bcrypt.hash(password, 12);

//     // Generate temporary token for verification process
//     const tempToken = uuidv4();

//     // Create pending user
//     const pendingUser = new PendingUser({
//       name,
//       email,
//       password: hashedPassword,
//       contact,
//       age,
//       tempToken
//     });

//     await pendingUser.save();
//     logger.info(`User registered: ${email}`);

//     // Send verification OTPs
//     await this.sendContactOTP(pendingUser);
//     await this.sendEmailOTP(pendingUser);

//     return {
//       tempToken,
//       message: 'Registration initiated. Please verify your contact and email.',
//       email,
//       contact
//     };
//   }

//   async login(email, password) {
//     const user = await User.findOne({ email, isActive: true });

//     if (!user) {
//       throw new Error('Invalid credentials');
//     }

//     const isPasswordValid = await user.comparePassword(password);

//     if (!isPasswordValid) {
//       throw new Error('Invalid credentials');
//     }

//     if (!user.isEmailVerified || !user.isContactVerified) {
//       throw new Error('Please verify your email and contact number first');
//     }

//     // Update last login
//     user.lastLogin = new Date();
//     await user.save();

//     const token = await this.generateToken(user);

//     logger.info(`User logged in: ${email}`);

//     return {
//       token,
//       user: user.toSafeObject()
//     };
//   }

//   async sendContactOTP(pendingUser) {
//     const otp = generateOTP();
//     const expiresAt = generateOTPExpiry();

//     // Store OTP in pending user document
//     await PendingUser.findByIdAndUpdate(pendingUser._id, {
//       $set: {
//         'verification.contact.otp': otp,
//         'verification.contact.expiresAt': expiresAt,
//         'verification.contact.attempts': 0
//       }
//     });

//     // Send SMS
//     await smsService.sendOTP(pendingUser.contact, otp);

//     return true;
//   }

//   async sendEmailOTP(pendingUser) {
//     const otp = generateOTP();
//     const expiresAt = generateOTPExpiry();

//     // Store OTP in pending user document
//     await PendingUser.findByIdAndUpdate(pendingUser._id, {
//       $set: {
//         'verification.email.otp': otp,
//         'verification.email.expiresAt': expiresAt,
//         'verification.email.attempts': 0
//       }
//     });

//     // Send email
//     await emailService.sendOTP(pendingUser.email, otp);

//     return true;
//   }

//   async verifyContactOTP(tempToken, otp) {
//     const pendingUser = await PendingUser.findOne({ tempToken });

//     if (!pendingUser) {
//       throw new Error('Invalid verification session');
//     }

//     const verification = pendingUser.verification?.contact;

//     if (!verification || verification.otp !== otp) {
//       throw new Error('Invalid OTP');
//     }

//     if (new Date() > verification.expiresAt) {
//       throw new Error('OTP expired');
//     }

//     // Mark contact as verified
//     await PendingUser.findByIdAndUpdate(pendingUser._id, {
//       $set: { 'verification.contact.verified': true },
//       $unset: {
//         'verification.contact.otp': 1,
//         'verification.contact.expiresAt': 1
//       }
//     });

//     return true;
//   }

//   async verifyEmailOTP(tempToken, otp) {
//     const pendingUser = await PendingUser.findOne({ tempToken });

//     if (!pendingUser) {
//       throw new Error('Invalid verification session');
//     }

//     const verification = pendingUser.verification?.email;

//     if (!verification || verification.otp !== otp) {
//       throw new Error('Invalid OTP');
//     }

//     if (new Date() > verification.expiresAt) {
//       throw new Error('OTP expired');
//     }

//     // Mark email as verified
//     await PendingUser.findByIdAndUpdate(pendingUser._id, {
//       $set: { 'verification.email.verified': true },
//       $unset: {
//         'verification.email.otp': 1,
//         'verification.email.expiresAt': 1
//       }
//     });

//     // Check if both contact and email are verified
//     const updatedPendingUser = await PendingUser.findById(pendingUser._id);

//     if (updatedPendingUser.verification.contact.verified && updatedPendingUser.verification.email.verified) {
//       // Create actual user account
//       const user = new User({
//         name: updatedPendingUser.name,
//         email: updatedPendingUser.email,
//         password: updatedPendingUser.password, // Already hashed
//         contact: updatedPendingUser.contact,
//         age: updatedPendingUser.age,
//         isEmailVerified: true,
//         isContactVerified: true,
//         isActive: updatedPendingUser.age >= 18 // If under 18, will need parent consent
//       });

//       await user.save();

//       // Clean up pending user
//       await PendingUser.deleteOne({ _id: pendingUser._id });

//       logger.info(`User account created: ${user.email}`);

//       return {
//         accountCreated: true,
//         user: user.toSafeObject(),
//         needsParentConsent: user.age < 18
//       };
//     }

//     return true;
//   }

//   async resendOTP(tempToken, type) {
//     const pendingUser = await PendingUser.findOne({ tempToken });

//     if (!pendingUser) {
//       throw new Error('Invalid verification session');
//     }

//     if (type === 'email') {
//       await this.sendEmailOTP(pendingUser);
//     } else if (type === 'contact') {
//       await this.sendContactOTP(pendingUser);
//     } else {
//       throw new Error('Invalid OTP type');
//     }

//     return true;
//   }

//   async initiateParentConsent(userId, parentEmail, parentPassword) {
//     const user = await User.findById(userId);

//     if (!user || user.age >= 18) {
//       throw new Error('Parent consent not required');
//     }

//     const hashedPassword = await bcrypt.hash(parentPassword, 12);

//     const parentConsent = new ParentConsent({
//       userId,
//       parentEmail,
//       parentPassword: hashedPassword
//     });

//     const otp = generateOTP();
//     const expiresAt = generateOTPExpiry();

//     parentConsent.otp = {
//       code: otp,
//       expiresAt,
//       attempts: 0
//     };

//     await parentConsent.save();

//     // Send OTP to parent email
//     await emailService.sendParentConsentOTP(parentEmail, otp, user.name);

//     return true;
//   }

//   async createAdminUser(email, password, role = 'admin') {
//     const existingAdmin = await User.findOne({ email });

//     if (existingAdmin) {
//       throw new Error('Admin user already exists with this email');
//     }

//     const admin = new User({
//       name: 'Admin User',
//       email,
//       password,
//       contact: '+1234567890', // Placeholder for admin
//       age: 25,
//       role,
//       isEmailVerified: true,
//       isContactVerified: true,
//       isActive: true
//     });

//     await admin.save();
//     logger.info(`Admin user created: ${email}`);

//     return admin.toSafeObject();
//   }
// }

// module.exports = new AuthService();

const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const User = require('../models/User');
const PendingUser = require('../models/PendingUser');
const ParentConsent = require('../models/ParentConsent');
const jwtConfig = require('../config/jwt');
const emailService = require('./emailService');
const smsService = require('./smsService');
const { generateOTP, generateOTPExpiry } = require('../utils/otpGenerator');
const logger = require('../utils/logger');
const { v4: uuidv4 } = require('uuid');

class AuthService {
  async generateToken(user) {
    const payload = {
      id: user._id,
      email: user.email,
      role: user.role
    };

    return jwt.sign(payload, jwtConfig.secret, {
      expiresIn: jwtConfig.expiresIn,
      issuer: jwtConfig.issuer,
      audience: jwtConfig.audience
    });
  }

  async verifyToken(token) {
    try {
      return jwt.verify(token, jwtConfig.secret);
    } catch (error) {
      throw new Error('Invalid token');
    }
  }

  async register(userData) {
    const { name, email, password, contact, age } = userData;

    // Check if user already exists in main User collection
    const existingUser = await User.findOne({
      $or: [{ email }, { contact }]
    });

    if (existingUser) {
      throw new Error('User with this email or contact already exists');
    }

    // Check if pending user already exists
    const existingPendingUser = await PendingUser.findOne({
      $or: [{ email }, { contact }]
    });

    if (existingPendingUser) {
      // Delete existing pending user to allow re-registration
      await PendingUser.deleteOne({ _id: existingPendingUser._id });
    }

    // Hash password
    console.log(password);
    const hashedPassword = await bcrypt.hash(password, 12);
    console.log('Hashed password:', hashedPassword);

    // Generate temporary token for verification process
    const tempToken = uuidv4();

    // Create pending user
    const pendingUser = new PendingUser({
      name,
      email,
      password: hashedPassword,
      contact,
      age,
      tempToken
    });

    await pendingUser.save();
    logger.info(`User registered: ${email}`);

    // Send verification OTPs
    await this.sendContactOTP(pendingUser);
    await this.sendEmailOTP(pendingUser);

    return {
      tempToken,
      message: 'Registration initiated. Please verify your contact and email.',
      email,
      contact,
      requiresParentConsent: age < 18
    };
  }

  // async login(email, password) {
  //   const user = await User.findOne({ email, isActive: true });

  //   if (!user) {
  //     throw new Error('Invalid credentials');
  //   }

  //   const isPasswordValid = await user.comparePassword(password);

  //   if (!isPasswordValid) {
  //     throw new Error('Invalid credentials');
  //   }

  //   if (!user.isEmailVerified || !user.isContactVerified) {
  //     throw new Error('Please verify your email and contact number first');
  //   }

  //   // Check if user is under 18 and needs parent consent
  //   if (user.age < 18 && !user.parentConsent) {
  //     throw new Error('Parent consent required for users under 18');
  //   }

  //   // Update last login
  //   user.lastLogin = new Date();
  //   await user.save();

  //   const token = await this.generateToken(user);

  //   logger.info(`User logged in: ${email}`);

  //   return {
  //     token,
  //     user: user.toSafeObject()
  //   };
  // }


  async login(email, password) {


    const user = await User.findOne({ email, isActive: true });


    if (!user) {
      console.log('User not found or inactive');
      throw new Error('Invalid credentials');
    }

    let isPasswordValid = false;
    try {
      isPasswordValid = await bcrypt.compare(password, user.password);
    } catch (bcryptError) {
    }

    if (!isPasswordValid) {
      throw new Error('Invalid credentials');
    }

    // Verification checks
    if (!user.isEmailVerified || !user.isContactVerified) {
      throw new Error('Please verify your email and contact number first');
    }

    if (user.age < 18 && !user.parentConsent) {
      throw new Error('Parent consent required for users under 18');
    }

    user.lastLogin = new Date();
    await user.save();

    const token = await this.generateToken(user);

    logger.info(`User logged in: ${email}`);

    return {
      token,
      user: user
    };
  }

  async sendContactOTP(pendingUser) {
    const otp = generateOTP();
    const expiresAt = generateOTPExpiry();

    // Store OTP in pending user document
    await PendingUser.findByIdAndUpdate(pendingUser._id, {
      $set: {
        'verification.contact.otp': otp,
        'verification.contact.expiresAt': expiresAt,
        'verification.contact.attempts': 0
      }
    });

    // Send SMS
    await smsService.sendOTP(pendingUser.contact, otp);

    return true;
  }

  async sendEmailOTP(pendingUser) {
    const otp = generateOTP();
    const expiresAt = generateOTPExpiry();

    // Store OTP in pending user document
    await PendingUser.findByIdAndUpdate(pendingUser._id, {
      $set: {
        'verification.email.otp': otp,
        'verification.email.expiresAt': expiresAt,
        'verification.email.attempts': 0
      }
    });

    // Send email
    await emailService.sendOTP(pendingUser.email, otp);

    return true;
  }

  async verifyContactOTP(tempToken, otp) {
    const pendingUser = await PendingUser.findOne({ tempToken });

    if (!pendingUser) {
      throw new Error('Invalid verification session');
    }

    const verification = pendingUser.verification?.contact;

    if (!verification || verification.otp !== otp) {
      throw new Error('Invalid OTP');
    }

    if (new Date() > verification.expiresAt) {
      throw new Error('OTP expired');
    }

    // Mark contact as verified
    await PendingUser.findByIdAndUpdate(pendingUser._id, {
      $set: { 'verification.contact.verified': true },
      $unset: {
        'verification.contact.otp': 1,
        'verification.contact.expiresAt': 1
      }
    });

    return { success: true, message: 'Contact verified successfully' };
  }

  async verifyEmailOTP(tempToken, otp) {
    const pendingUser = await PendingUser.findOne({ tempToken });

    if (!pendingUser) {
      throw new Error('Invalid verification session');
    }

    const verification = pendingUser.verification?.email;

    if (!verification || verification.otp !== otp) {
      throw new Error('Invalid OTP');
    }

    if (new Date() > verification.expiresAt) {
      throw new Error('OTP expired');
    }

    // Mark email as verified
    await PendingUser.findByIdAndUpdate(pendingUser._id, {
      $set: { 'verification.email.verified': true },
      $unset: {
        'verification.email.otp': 1,
        'verification.email.expiresAt': 1
      }
    });

    // Check if both contact and email are verified
    const updatedPendingUser = await PendingUser.findById(pendingUser._id);

    if (updatedPendingUser.verification.contact.verified && updatedPendingUser.verification.email.verified) {
      // Create actual user account
      const user = new User({
        name: updatedPendingUser.name,
        email: updatedPendingUser.email,
        password: updatedPendingUser.password, // Already hashed
        contact: updatedPendingUser.contact,
        age: updatedPendingUser.age,
        isEmailVerified: true,
        isContactVerified: true,
        isActive: updatedPendingUser.age >= 18 // If under 18, will need parent consent
      });

      await user.save();

      // Clean up pending user
      await PendingUser.deleteOne({ _id: pendingUser._id });

      logger.info(`User account created: ${user.email}`);

      // For users 18 and above, auto-login
      if (user.age >= 18) {
        const token = await this.generateToken(user);

        // Update last login
        user.lastLogin = new Date();
        await user.save();

        return {
          accountCreated: true,
          autoLogin: true,
          token,
          user: user,
          message: 'Account created and logged in successfully'
        };
      } else {
        // For users under 18, require parent consent
        return {
          accountCreated: true,
          autoLogin: false,
          user: user,
          needsParentConsent: true,
          message: 'Account created. Parent consent required to activate account.'
        };
      }
    }

    return { success: true, message: 'Email verified successfully' };
  }

  async resendOTP(tempToken, type) {
    const pendingUser = await PendingUser.findOne({ tempToken });

    if (!pendingUser) {
      throw new Error('Invalid verification session');
    }

    if (type === 'email') {
      await this.sendEmailOTP(pendingUser);
    } else if (type === 'contact') {
      await this.sendContactOTP(pendingUser);
    } else {
      throw new Error('Invalid OTP type');
    }

    return true;
  }

  async initiateParentConsent(userId, parentEmail, parentContact) {
    const user = await User.findById(userId);

    if (!user || user.age >= 18) {
      throw new Error('Parent consent not required for users 18 and above');
    }

    if (user.isActive) {
      throw new Error('User account is already active');
    }

    // Check if parent consent already exists
    let parentConsent = await ParentConsent.findOne({ userId });

    if (!parentConsent) {
      parentConsent = new ParentConsent({
        userId,
        parentEmail,
        parentContact
      });
    } else {
      // Update parent details if changed
      parentConsent.parentEmail = parentEmail;
      parentConsent.parentContact = parentContact;
      parentConsent.isVerified = false;
    }

    // Generate OTPs for both email and contact
    const emailOtp = generateOTP();
    const contactOtp = generateOTP();
    const expiresAt = generateOTPExpiry();

    parentConsent.emailOtp = {
      code: emailOtp,
      expiresAt,
      attempts: 0,
      verified: false
    };

    parentConsent.contactOtp = {
      code: contactOtp,
      expiresAt,
      attempts: 0,
      verified: false
    };

    await parentConsent.save();

    // Send OTPs to parent
    await emailService.sendParentConsentOTP(parentEmail, emailOtp, user.name);
    await smsService.sendOTP(parentContact, contactOtp);

    return {
      success: true,
      message: 'Parent consent initiated. OTPs sent to parent email and contact.',
      parentEmail,
      parentContact: parentContact.replace(/(\d{3})\d{4}(\d{3})/, '$1****$2') // Mask contact for security
    };
  }

  async verifyParentEmailOTP(userId, otp) {
    const parentConsent = await ParentConsent.findOne({ userId });

    if (!parentConsent) {
      throw new Error('Parent consent not found');
    }

    if (!parentConsent.emailOtp || parentConsent.emailOtp.code !== otp) {
      throw new Error('Invalid email OTP');
    }

    if (new Date() > parentConsent.emailOtp.expiresAt) {
      throw new Error('Email OTP expired');
    }

    // Mark email as verified
    parentConsent.emailOtp.verified = true;
    await parentConsent.save();

    return { success: true, message: 'Parent email verified successfully' };
  }

  async verifyParentContactOTP(userId, otp) {
    const parentConsent = await ParentConsent.findOne({ userId });

    if (!parentConsent) {
      throw new Error('Parent consent not found');
    }

    if (!parentConsent.contactOtp || parentConsent.contactOtp.code !== otp) {
      throw new Error('Invalid contact OTP');
    }

    if (new Date() > parentConsent.contactOtp.expiresAt) {
      throw new Error('Contact OTP expired');
    }

    // Mark contact as verified
    parentConsent.contactOtp.verified = true;
    await parentConsent.save();

    // Check if both email and contact are verified
    if (parentConsent.emailOtp.verified && parentConsent.contactOtp.verified) {
      // Mark parent consent as complete and activate user
      parentConsent.isVerified = true;
      parentConsent.verifiedAt = new Date();
      await parentConsent.save();

      const user = await User.findByIdAndUpdate(
        userId,
        {
          $set: {
            isActive: true,
            parentConsent: parentConsent._id
          }
        },
        { new: true }
      );

      // Auto-login the user
      const token = await this.generateToken(user);

      // Update last login
      user.lastLogin = new Date();
      await user.save();

      return {
        success: true,
        accountActivated: true,
        autoLogin: true,
        token,
        user: user,
        message: 'Parent consent completed. Account activated and logged in successfully.'
      };
    }

    return { success: true, message: 'Parent contact verified successfully' };
  }

  async createAdminUser(email, password, role = 'admin') {
    const existingAdmin = await User.findOne({ email });

    if (existingAdmin) {
      throw new Error('Admin user already exists with this email');
    }

    const admin = new User({
      name: 'Admin User',
      email,
      password,
      contact: '+1234567890', // Placeholder for admin
      age: 25,
      role,
      isEmailVerified: true,
      isContactVerified: true,
      isActive: true
    });

    await admin.save();
    logger.info(`Admin user created: ${email}`);

    return admin.toSafeObject();
  }
}

module.exports = new AuthService();