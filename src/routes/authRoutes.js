const express = require('express');
const authController = require('../controllers/authController');
const { authenticate, authorize } = require('../middlewares/auth');

const router = express.Router();

// Public routes
router.post('/signup', authController.signup);
router.post('/login', authController.login);
router.post('/verify-contact-otp', authController.verifyContactOTP);
router.post('/verify-email-otp', authController.verifyEmailOTP);
router.post('/resend-otp', authController.resendOTP);

// Protected routes (require authentication)

// Parent consent routes
// router.post('/parent/init', authenticate, authController.initiateParentConsent);
// router.post('/parent/verify-otp', authenticate, authController.verifyParentOTP);

router.post('/parent/init', authController.initiateParentConsent);
router.post('/parent/verify-email-otp', authController.verifyParentEmailOTP);
router.post('/parent/verify-contact-otp', authController.verifyParentContactOTP);
router.post('/parent/resend-otp', authController.resendParentOTP);


// Admin routes
router.post('/admin/invite', authenticate, authorize('admin', 'superadmin'), authController.inviteAdmin);
router.get('/admin/verify-invite', authController.verifyAdminInvite);
router.post('/admin/verify-invite', authController.verifyAdminInvite);

module.exports = router;