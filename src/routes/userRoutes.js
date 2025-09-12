const express = require('express');
const userController = require('../controllers/userController');
const { authenticate } = require('../middlewares/auth');

const router = express.Router();

// All user routes require authentication
router.use(authenticate);

router.get('/profile', userController.getProfile);
router.put('/profile', userController.updateProfile);
router.post('/change-password', userController.changePassword);
router.put('/notifications', userController.updateNotificationPrefs);
router.post('/delete-account', userController.requestAccountDeletion);
router.post('/confirm-deletion', userController.confirmAccountDeletion);
router.get('/booking-history', userController.getBookingHistory);

module.exports = router;