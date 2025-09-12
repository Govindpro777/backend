const express = require('express');
const moodController = require('../controllers/moodController');
const { authenticate } = require('../middlewares/auth');

const router = express.Router();

// All feeling routes require authentication
router.use(authenticate);

router.post('/today', moodController.submitFeelingToday);
router.get('/today', moodController.getTodaysFeeling);
router.get('/history', moodController.getFeelingHistory);

module.exports = router;