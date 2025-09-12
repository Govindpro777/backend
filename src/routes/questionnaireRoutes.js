const express = require('express');
const { Questionnaire, QuestionnaireResponse } = require('../models/Questionnaire');
const { authenticate, authorize } = require('../middlewares/auth');
const { successResponse, errorResponse } = require('../utils/response');
const logger = require('../utils/logger');

const router = express.Router();

// Get active questionnaire
router.get('/current', authenticate, async (req, res) => {
  try {
    const questionnaire = await Questionnaire.findOne({ isActive: true });
    
    if (!questionnaire) {
      return errorResponse(res, 'No active questionnaire found', 404);
    }

    return successResponse(res, { questionnaire });
  } catch (error) {
    logger.error('Get current questionnaire error:', error);
    return errorResponse(res, 'Failed to retrieve questionnaire', 500);
  }
});

// Submit questionnaire response
router.post('/submit', authenticate, async (req, res) => {
  try {
    const { questionnaireId, responses } = req.body;
    const userId = req.user.id;

    const questionnaire = await Questionnaire.findById(questionnaireId);
    
    if (!questionnaire) {
      return errorResponse(res, 'Questionnaire not found', 404);
    }

    // Calculate basic score (this would be more sophisticated in production)
    const score = responses.reduce((total, response) => {
      if (typeof response.answer === 'number') {
        return total + response.answer;
      }
      return total;
    }, 0);

    const questionnaireResponse = new QuestionnaireResponse({
      user: userId,
      questionnaire: questionnaireId,
      responses,
      score
    });

    // Determine category based on score (simplified logic)
    if (score <= 5) questionnaireResponse.category = 'low';
    else if (score <= 10) questionnaireResponse.category = 'moderate';
    else if (score <= 15) questionnaireResponse.category = 'high';
    else questionnaireResponse.category = 'severe';

    await questionnaireResponse.save();

    return successResponse(res, { 
      response: questionnaireResponse,
      recommendations: this.getRecommendations(questionnaireResponse.category)
    }, 'Questionnaire submitted successfully', 201);
  } catch (error) {
    logger.error('Submit questionnaire error:', error);
    return errorResponse(res, 'Failed to submit questionnaire', 500);
  }
});

// Get user's questionnaire history
router.get('/my-responses', authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    
    const responses = await QuestionnaireResponse.find({ user: userId })
      .populate('questionnaire', 'title')
      .sort({ createdAt: -1 })
      .limit(20);

    return successResponse(res, { responses });
  } catch (error) {
    logger.error('Get questionnaire responses error:', error);
    return errorResponse(res, 'Failed to retrieve responses', 500);
  }
});

// Admin: Create questionnaire
router.post('/', authenticate, authorize('admin', 'superadmin'), async (req, res) => {
  try {
    // Deactivate current questionnaire
    await Questionnaire.updateMany({}, { isActive: false });
    
    const questionnaire = new Questionnaire(req.body);
    await questionnaire.save();

    return successResponse(res, { questionnaire }, 'Questionnaire created successfully', 201);
  } catch (error) {
    logger.error('Create questionnaire error:', error);
    return errorResponse(res, 'Failed to create questionnaire', 500);
  }
});

// Helper method for recommendations
router.getRecommendations = (category) => {
  const recommendations = {
    low: [
      'Continue with your current mental health practices',
      'Consider daily mindfulness exercises',
      'Maintain social connections'
    ],
    moderate: [
      'Try guided meditation sessions',
      'Consider talking to friends or family',
      'Establish a regular sleep schedule',
      'Engage in regular physical activity'
    ],
    high: [
      'Consider professional counseling',
      'Practice stress management techniques',
      'Reach out to your support network',
      'Consider booking an appointment with our psychologists'
    ],
    severe: [
      'Please consider immediate professional help',
      'Contact a mental health professional',
      'Reach out to crisis support services',
      'Book an urgent appointment with our psychologists'
    ]
  };

  return recommendations[category] || recommendations.moderate;
};

module.exports = router;