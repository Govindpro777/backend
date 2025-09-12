const express = require('express');
const ContentLibrary = require('../models/ContentLibrary');
const { authenticate, authorize, optionalAuth } = require('../middlewares/auth');
const { successResponse, errorResponse } = require('../utils/response');
const logger = require('../utils/logger');

const router = express.Router();

// Get content library (public)
router.get('/', optionalAuth, async (req, res) => {
  try {
    const { type, category, page = 1, limit = 20, search } = req.query;
    
    const query = { isPublished: true };
    
    if (type) query.type = type;
    if (category) query.category = category;
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { tags: { $in: [new RegExp(search, 'i')] } }
      ];
    }

    const content = await ContentLibrary.find(query)
      .populate('createdBy', 'name')
      .sort({ publishedAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await ContentLibrary.countDocuments(query);

    return successResponse(res, {
      content,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(total / limit),
        totalItems: total
      }
    });
  } catch (error) {
    logger.error('Get content error:', error);
    return errorResponse(res, 'Failed to retrieve content', 500);
  }
});

// Get content by ID
router.get('/:id', optionalAuth, async (req, res) => {
  try {
    const content = await ContentLibrary.findOne({
      _id: req.params.id,
      isPublished: true
    }).populate('createdBy', 'name profile.avatar');

    if (!content) {
      return errorResponse(res, 'Content not found', 404);
    }

    // Increment view count
    content.engagement.views += 1;
    await content.save();

    return successResponse(res, { content });
  } catch (error) {
    logger.error('Get content by ID error:', error);
    return errorResponse(res, 'Failed to retrieve content', 500);
  }
});

// Get content categories
router.get('/categories/list', async (req, res) => {
  try {
    const categories = await ContentLibrary.distinct('category', { isPublished: true });
    const types = await ContentLibrary.distinct('type', { isPublished: true });

    return successResponse(res, { categories, types });
  } catch (error) {
    logger.error('Get categories error:', error);
    return errorResponse(res, 'Failed to retrieve categories', 500);
  }
});

// Like content
router.post('/:id/like', authenticate, async (req, res) => {
  try {
    const content = await ContentLibrary.findById(req.params.id);
    
    if (!content) {
      return errorResponse(res, 'Content not found', 404);
    }

    content.engagement.likes += 1;
    await content.save();

    return successResponse(res, { 
      likes: content.engagement.likes 
    }, 'Content liked');
  } catch (error) {
    logger.error('Like content error:', error);
    return errorResponse(res, 'Failed to like content', 500);
  }
});

// Mark content as completed
router.post('/:id/complete', authenticate, async (req, res) => {
  try {
    const content = await ContentLibrary.findById(req.params.id);
    
    if (!content) {
      return errorResponse(res, 'Content not found', 404);
    }

    content.engagement.completions += 1;
    await content.save();

    // In a real app, you'd also track user progress
    return successResponse(res, null, 'Content marked as completed');
  } catch (error) {
    logger.error('Complete content error:', error);
    return errorResponse(res, 'Failed to mark content as completed', 500);
  }
});

// Admin: Create content
router.post('/', authenticate, authorize('admin', 'superadmin'), async (req, res) => {
  try {
    const content = new ContentLibrary({
      ...req.body,
      createdBy: req.user.id,
      publishedAt: req.body.isPublished ? new Date() : null
    });

    await content.save();

    return successResponse(res, { content }, 'Content created successfully', 201);
  } catch (error) {
    logger.error('Create content error:', error);
    return errorResponse(res, 'Failed to create content', 500);
  }
});

// Admin: Update content
router.put('/:id', authenticate, authorize('admin', 'superadmin'), async (req, res) => {
  try {
    const content = await ContentLibrary.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true, runValidators: true }
    );

    if (!content) {
      return errorResponse(res, 'Content not found', 404);
    }

    return successResponse(res, { content }, 'Content updated successfully');
  } catch (error) {
    logger.error('Update content error:', error);
    return errorResponse(res, 'Failed to update content', 500);
  }
});

module.exports = router;