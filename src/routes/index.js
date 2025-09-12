const express = require('express');
const authRoutes = require('./authRoutes');
const userRoutes = require('./userRoutes');
const postRoutes = require('./postRoutes');
const pollRoutes = require('./pollRoutes');
const moodRoutes = require('./moodRoutes');
const psychologistRoutes = require('./psychologistRoutes');
const appointmentRoutes = require('./appointmentRoutes');
const questionnaireRoutes = require('./questionnaireRoutes');
const feelingRoutes = require('./feelingRoutes');
const analyticsRoutes = require('./analyticsRoutes');
const chatbotRoutes = require('./chatbotRoutes');
const contentRoutes = require('./contentRoutes');

const router = express.Router();

// API Routes
router.use('/auth', authRoutes);
router.use('/users', userRoutes);
router.use('/posts', postRoutes);
router.use('/polls', pollRoutes);
router.use('/moods', moodRoutes);
router.use('/psychologists', psychologistRoutes);
router.use('/appointments', appointmentRoutes);
router.use('/questionnaires', questionnaireRoutes);
router.use('/feelings', feelingRoutes);
router.use('/analytics', analyticsRoutes);
router.use('/chatbot', chatbotRoutes);
router.use('/content', contentRoutes);

// Health check for API
router.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    service: 'Mental Health Platform API',
    timestamp: new Date().toISOString()
  });
});

module.exports = router;