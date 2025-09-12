const MoodLog = require('../models/MoodLog');
const FeelingToday = require('../models/FeelingToday');
const { successResponse, errorResponse } = require('../utils/response');
const { moodLogSchema } = require('../utils/validators');
const logger = require('../utils/logger');

class MoodController {
  async logMood(req, res) {
    try {
      const { error } = moodLogSchema.validate(req.body);
      if (error) {
        const errors = error.details.map(detail => ({
          field: detail.path[0],
          message: detail.message
        }));
        return errorResponse(res, 'Validation failed', 400, errors);
      }

      const { emoji, scale, emotions, notes, triggers } = req.body;
      
      const moodLog = new MoodLog({
        user: req.user.id,
        emoji,
        scale,
        emotions,
        notes,
        triggers
      });

      await moodLog.save();

      return successResponse(res, { moodLog }, 'Mood logged successfully', 201);
    } catch (error) {
      logger.error('Log mood error:', error);
      return errorResponse(res, 'Failed to log mood', 500);
    }
  }

  async getMoodHistory(req, res) {
    try {
      const userId = req.user.id;
      const { startDate, endDate, limit = 30 } = req.query;
      
      const query = { user: userId, isDeleted: false };
      
      if (startDate && endDate) {
        query.logDate = {
          $gte: new Date(startDate),
          $lte: new Date(endDate)
        };
      }

      const moodLogs = await MoodLog.find(query)
        .sort({ logDate: -1 })
        .limit(parseInt(limit));

      return successResponse(res, { moodLogs }, 'Mood history retrieved successfully');
    } catch (error) {
      logger.error('Get mood history error:', error);
      return errorResponse(res, 'Failed to retrieve mood history', 500);
    }
  }

  async submitFeelingToday(req, res) {
    try {
      const { feeling, emoji, notes } = req.body;
      
      if (!feeling || !emoji) {
        return errorResponse(res, 'Feeling and emoji are required', 400);
      }

      const today = new Date();
      today.setHours(0, 0, 0, 0);
      
      const tomorrow = new Date(today);
      tomorrow.setDate(tomorrow.getDate() + 1);

      // Check if feeling already submitted today
      const existingFeeling = await FeelingToday.findOne({
        user: req.user.id,
        date: { $gte: today, $lt: tomorrow }
      });

      if (existingFeeling) {
        // Update existing feeling
        existingFeeling.feeling = feeling;
        existingFeeling.emoji = emoji;
        existingFeeling.notes = notes;
        await existingFeeling.save();
        
        return successResponse(res, { feeling: existingFeeling }, 'Today\'s feeling updated');
      } else {
        // Create new feeling
        const feelingToday = new FeelingToday({
          user: req.user.id,
          feeling,
          emoji,
          notes
        });

        await feelingToday.save();
        
        return successResponse(res, { feeling: feelingToday }, 'Today\'s feeling submitted', 201);
      }
    } catch (error) {
      logger.error('Submit feeling today error:', error);
      return errorResponse(res, 'Failed to submit feeling', 500);
    }
  }

  async getFeelingHistory(req, res) {
    try {
      const userId = req.user.id;
      const { limit = 30 } = req.query;

      const feelings = await FeelingToday.find({ user: userId })
        .sort({ date: -1 })
        .limit(parseInt(limit));

      return successResponse(res, { feelings }, 'Feeling history retrieved successfully');
    } catch (error) {
      logger.error('Get feeling history error:', error);
      return errorResponse(res, 'Failed to retrieve feeling history', 500);
    }
  }

  async getTodaysFeeling(req, res) {
    try {
      const userId = req.user.id;
      
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      
      const tomorrow = new Date(today);
      tomorrow.setDate(tomorrow.getDate() + 1);

      const todaysFeeling = await FeelingToday.findOne({
        user: userId,
        date: { $gte: today, $lt: tomorrow }
      });

      return successResponse(res, { 
        feeling: todaysFeeling,
        hasSubmittedToday: !!todaysFeeling 
      }, 'Today\'s feeling retrieved successfully');
    } catch (error) {
      logger.error('Get today\'s feeling error:', error);
      return errorResponse(res, 'Failed to retrieve today\'s feeling', 500);
    }
  }
}

module.exports = new MoodController();