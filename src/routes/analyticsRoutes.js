const express = require('express');
const MoodLog = require('../models/MoodLog');
const FeelingToday = require('../models/FeelingToday');
const { authenticate } = require('../middlewares/auth');
const { successResponse, errorResponse } = require('../utils/response');
const logger = require('../utils/logger');

const router = express.Router();

router.use(authenticate);

// Get mood analytics
router.get('/mood', async (req, res) => {
  try {
    const userId = req.user.id;
    const { timeframe = '30d' } = req.query;

    let startDate = new Date();
    
    switch (timeframe) {
      case '7d':
        startDate.setDate(startDate.getDate() - 7);
        break;
      case '30d':
        startDate.setDate(startDate.getDate() - 30);
        break;
      case '90d':
        startDate.setDate(startDate.getDate() - 90);
        break;
      default:
        startDate.setDate(startDate.getDate() - 30);
    }

    // Daily mood aggregation
    const dailyMoods = await MoodLog.aggregate([
      {
        $match: {
          user: userId,
          logDate: { $gte: startDate },
          isDeleted: false
        }
      },
      {
        $group: {
          _id: {
            $dateToString: { format: "%Y-%m-%d", date: "$logDate" }
          },
          averageScale: { $avg: "$scale" },
          count: { $sum: 1 },
          emotions: { $push: "$emotions" }
        }
      },
      {
        $sort: { "_id": 1 }
      }
    ]);

    // Calculate streaks
    const moodLogs = await MoodLog.find({
      user: userId,
      logDate: { $gte: startDate },
      isDeleted: false
    }).sort({ logDate: -1 });

    const currentStreak = this.calculateCurrentStreak(moodLogs);
    const longestStreak = this.calculateLongestStreak(moodLogs);

    // Emotion frequency
    const emotionFrequency = await MoodLog.aggregate([
      {
        $match: {
          user: userId,
          logDate: { $gte: startDate },
          isDeleted: false
        }
      },
      {
        $unwind: "$emotions"
      },
      {
        $group: {
          _id: "$emotions",
          count: { $sum: 1 }
        }
      },
      {
        $sort: { count: -1 }
      }
    ]);

    const analytics = {
      timeframe,
      dailyMoods,
      streaks: {
        current: currentStreak,
        longest: longestStreak
      },
      emotionFrequency,
      insights: this.generateInsights(dailyMoods, emotionFrequency)
    };

    return successResponse(res, { analytics }, 'Mood analytics retrieved successfully');
  } catch (error) {
    logger.error('Get mood analytics error:', error);
    return errorResponse(res, 'Failed to retrieve mood analytics', 500);
  }
});

// Get weekly mood assessment
router.get('/weekly-assessment', async (req, res) => {
  try {
    const userId = req.user.id;
    
    const oneWeekAgo = new Date();
    oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);

    const weeklyMoods = await MoodLog.find({
      user: userId,
      logDate: { $gte: oneWeekAgo },
      isDeleted: false
    }).sort({ logDate: -1 });

    const feelings = await FeelingToday.find({
      user: userId,
      date: { $gte: oneWeekAgo }
    }).sort({ date: -1 });

    const weeklyAssessment = {
      moodLogs: weeklyMoods,
      feelings,
      averageScale: weeklyMoods.length > 0 
        ? weeklyMoods.reduce((sum, log) => sum + log.scale, 0) / weeklyMoods.length
        : null,
      totalEntries: weeklyMoods.length,
      daysActive: new Set(weeklyMoods.map(log => 
        log.logDate.toISOString().split('T')[0]
      )).size
    };

    return successResponse(res, { weeklyAssessment }, 'Weekly assessment retrieved successfully');
  } catch (error) {
    logger.error('Get weekly assessment error:', error);
    return errorResponse(res, 'Failed to retrieve weekly assessment', 500);
  }
});

// Helper methods
router.calculateCurrentStreak = (moodLogs) => {
  if (moodLogs.length === 0) return 0;
  
  let streak = 1;
  let currentDate = new Date(moodLogs[0].logDate);
  
  for (let i = 1; i < moodLogs.length; i++) {
    const prevDate = new Date(moodLogs[i].logDate);
    const diffTime = Math.abs(currentDate - prevDate);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    
    if (diffDays === 1) {
      streak++;
      currentDate = prevDate;
    } else {
      break;
    }
  }
  
  return streak;
};

router.calculateLongestStreak = (moodLogs) => {
  if (moodLogs.length === 0) return 0;
  
  let longestStreak = 1;
  let currentStreak = 1;
  
  for (let i = 1; i < moodLogs.length; i++) {
    const currentDate = new Date(moodLogs[i-1].logDate);
    const prevDate = new Date(moodLogs[i].logDate);
    const diffTime = Math.abs(currentDate - prevDate);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    
    if (diffDays === 1) {
      currentStreak++;
    } else {
      longestStreak = Math.max(longestStreak, currentStreak);
      currentStreak = 1;
    }
  }
  
  return Math.max(longestStreak, currentStreak);
};

router.generateInsights = (dailyMoods, emotionFrequency) => {
  const insights = [];
  
  if (dailyMoods.length > 0) {
    const avgMood = dailyMoods.reduce((sum, day) => sum + day.averageScale, 0) / dailyMoods.length;
    
    if (avgMood >= 4) {
      insights.push("You've been feeling great lately! Keep up the good work.");
    } else if (avgMood >= 3) {
      insights.push("Your mood has been stable. Consider adding some mood-boosting activities.");
    } else {
      insights.push("Your mood could use some attention. Consider speaking with a professional.");
    }
  }
  
  if (emotionFrequency.length > 0) {
    const topEmotion = emotionFrequency[0];
    insights.push(`Your most frequent emotion is "${topEmotion._id}".`);
  }
  
  return insights;
};

module.exports = router;