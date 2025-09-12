const express = require('express');
const Poll = require('../models/Poll');
const { authenticate, authorize, optionalAuth } = require('../middlewares/auth');
const { successResponse, errorResponse } = require('../utils/response');
const { pollSchema } = require('../utils/validators');
const logger = require('../utils/logger');

const router = express.Router();

// Get all polls (public)
router.get('/', optionalAuth, async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    
    const query = { isDeleted: false, isActive: true };
    
    const polls = await Poll.find(query)
      .populate('creator', 'name profile.avatar')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await Poll.countDocuments(query);

    return successResponse(res, {
      polls,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(total / limit),
        totalItems: total
      }
    });
  } catch (error) {
    logger.error('Get polls error:', error);
    return errorResponse(res, 'Failed to retrieve polls', 500);
  }
});

// Create poll
router.post('/', authenticate, async (req, res) => {
  try {
    const { error } = pollSchema.validate(req.body);
    if (error) {
      const errors = error.details.map(detail => ({
        field: detail.path[0],
        message: detail.message
      }));
      return errorResponse(res, 'Validation failed', 400, errors);
    }

    const poll = new Poll({
      ...req.body,
      creator: req.user.id,
      options: req.body.options.map(text => ({ text, votes: [] }))
    });

    await poll.save();
    await poll.populate('creator', 'name profile.avatar');

    return successResponse(res, { poll }, 'Poll created successfully', 201);
  } catch (error) {
    logger.error('Create poll error:', error);
    return errorResponse(res, 'Failed to create poll', 500);
  }
});

// Vote on poll
router.post('/:id/vote', authenticate, async (req, res) => {
  try {
    const { optionIndex } = req.body;
    const pollId = req.params.id;
    const userId = req.user.id;

    const poll = await Poll.findOne({ _id: pollId, isDeleted: false, isActive: true });
    
    if (!poll) {
      return errorResponse(res, 'Poll not found', 404);
    }

    if (poll.expiresAt && new Date() > poll.expiresAt) {
      return errorResponse(res, 'Poll has expired', 400);
    }

    if (optionIndex < 0 || optionIndex >= poll.options.length) {
      return errorResponse(res, 'Invalid option index', 400);
    }

    // Remove existing vote from all options
    poll.options.forEach(option => {
      option.votes = option.votes.filter(vote => vote.user.toString() !== userId);
    });

    // Add new vote
    poll.options[optionIndex].votes.push({ user: userId });
    
    await poll.save();

    return successResponse(res, { poll }, 'Vote recorded successfully');
  } catch (error) {
    logger.error('Vote on poll error:', error);
    return errorResponse(res, 'Failed to vote', 500);
  }
});

module.exports = router;