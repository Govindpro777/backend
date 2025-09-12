const express = require('express');
const { authenticate } = require('../middlewares/auth');
const { successResponse, errorResponse } = require('../utils/response');
const logger = require('../utils/logger');

const router = express.Router();

router.use(authenticate);

// Chat with AI therapist
router.post('/chat', async (req, res) => {
  try {
    const { message, sessionId } = req.body;
    
    if (!message || message.trim().length === 0) {
      return errorResponse(res, 'Message is required', 400);
    }

    // Mock AI therapist response (replace with actual AI service)
    const response = await generateTherapistResponse(message, req.user);
    
    const chatResponse = {
      id: Date.now().toString(),
      message: response.text,
      timestamp: new Date(),
      sessionId: sessionId || `session-${Date.now()}`,
      metadata: {
        confidence: response.confidence,
        intent: response.intent,
        suggestions: response.suggestions
      }
    };

    return successResponse(res, { response: chatResponse }, 'Chat response generated');
  } catch (error) {
    logger.error('Chat error:', error);
    return errorResponse(res, 'Failed to generate response', 500);
  }
});

// Get chat history
router.get('/history', async (req, res) => {
  try {
    const { sessionId, limit = 50 } = req.query;
    
    // In a real implementation, you'd store chat history in the database
    // For now, return a mock response
    const history = {
      sessionId: sessionId || 'default',
      messages: [],
      createdAt: new Date(),
      lastActivity: new Date()
    };

    return successResponse(res, { history }, 'Chat history retrieved');
  } catch (error) {
    logger.error('Get chat history error:', error);
    return errorResponse(res, 'Failed to retrieve chat history', 500);
  }
});

// Mock AI therapist response generator
async function generateTherapistResponse(message, user) {
  // This is a mock implementation. In production, integrate with OpenAI, Claude, or similar
  const responses = {
    greeting: [
      "Hello! I'm here to support you today. How are you feeling?",
      "Hi there! It's good to see you. What's on your mind today?",
      "Welcome! I'm glad you reached out. How can I help you today?"
    ],
    sadness: [
      "I hear that you're feeling sad. That's completely valid. Can you tell me more about what's contributing to these feelings?",
      "Thank you for sharing that with me. Sadness is a natural emotion. What do you think might help you feel a bit better right now?",
      "I understand you're going through a difficult time. Would you like to explore some coping strategies together?"
    ],
    anxiety: [
      "Anxiety can feel overwhelming. Let's take this one step at a time. What specifically is making you feel anxious?",
      "I can sense your worry. Would you like to try a brief breathing exercise together?",
      "Anxiety is very common, and you're not alone in feeling this way. What usually helps you feel calmer?"
    ],
    default: [
      "Thank you for sharing that with me. Can you tell me more about how you're feeling?",
      "I'm listening. What would be most helpful for you to discuss right now?",
      "How has your day been going overall?"
    ]
  };

  // Simple keyword matching (replace with actual AI/NLP)
  let responseType = 'default';
  const lowerMessage = message.toLowerCase();
  
  if (lowerMessage.includes('hello') || lowerMessage.includes('hi')) {
    responseType = 'greeting';
  } else if (lowerMessage.includes('sad') || lowerMessage.includes('depressed')) {
    responseType = 'sadness';
  } else if (lowerMessage.includes('anxious') || lowerMessage.includes('worry') || lowerMessage.includes('stress')) {
    responseType = 'anxiety';
  }

  const responseOptions = responses[responseType];
  const selectedResponse = responseOptions[Math.floor(Math.random() * responseOptions.length)];

  // Simulate AI processing delay
  await new Promise(resolve => setTimeout(resolve, 1000));

  return {
    text: selectedResponse,
    confidence: 0.85,
    intent: responseType,
    suggestions: [
      'Try a breathing exercise',
      'Schedule time for self-care',
      'Talk to a friend or family member',
      'Consider booking an appointment with a psychologist'
    ]
  };
}

module.exports = router;