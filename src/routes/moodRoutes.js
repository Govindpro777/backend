const express = require('express');
const moodController = require('../controllers/moodController');
const { authenticate } = require('../middlewares/auth');

const router = express.Router();

// All mood routes require authentication
router.use(authenticate);

router.post('/log', moodController.logMood);
router.get('/history', moodController.getMoodHistory);

module.exports = router;