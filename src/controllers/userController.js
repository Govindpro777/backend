const User = require('../models/User');
const NotificationPrefs = require('../models/NotificationPrefs');
const DeletionRequest = require('../models/DeletionRequest');
const { successResponse, errorResponse } = require('../utils/response');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const logger = require('../utils/logger');

class UserController {
  async getProfile(req, res) {
    try {
      const user = await User.findById(req.user.id)
        .populate('notificationPrefs')
        .select('-password');
      
      return successResponse(res, { user }, 'Profile retrieved successfully');
    } catch (error) {
      logger.error('Get profile error:', error);
      return errorResponse(res, 'Failed to retrieve profile', 500);
    }
  }

  async updateProfile(req, res) {
    try {
      const { name, bio, interests, emergencyContact } = req.body;
      const userId = req.user.id;

      const updateData = {};
      if (name) updateData.name = name;
      if (bio !== undefined) updateData['profile.bio'] = bio;
      if (interests) updateData['profile.interests'] = interests;
      if (emergencyContact) updateData['profile.emergencyContact'] = emergencyContact;

      const user = await User.findByIdAndUpdate(
        userId,
        { $set: updateData },
        { new: true, select: '-password' }
      );

      return successResponse(res, { user }, 'Profile updated successfully');
    } catch (error) {
      logger.error('Update profile error:', error);
      return errorResponse(res, 'Failed to update profile', 500);
    }
  }

  async changePassword(req, res) {
    try {
      const { currentPassword, newPassword, retypePassword } = req.body;
      const userId = req.user.id;

      if (!currentPassword || !newPassword || !retypePassword) {
        return errorResponse(res, 'All password fields are required', 400);
      }

      if (newPassword !== retypePassword) {
        return errorResponse(res, 'New passwords do not match', 400);
      }

      if (newPassword.length < 8) {
        return errorResponse(res, 'New password must be at least 8 characters long', 400);
      }

      const user = await User.findById(userId);
      const isCurrentPasswordValid = await user.comparePassword(currentPassword);

      if (!isCurrentPasswordValid) {
        return errorResponse(res, 'Current password is incorrect', 400);
      }

      user.password = newPassword;
      await user.save();

      return successResponse(res, null, 'Password changed successfully');
    } catch (error) {
      logger.error('Change password error:', error);
      return errorResponse(res, 'Failed to change password', 500);
    }
  }

  async updateNotificationPrefs(req, res) {
    try {
      const userId = req.user.id;
      const prefs = req.body;

      let notificationPrefs = await NotificationPrefs.findOne({ user: userId });
      
      if (!notificationPrefs) {
        notificationPrefs = new NotificationPrefs({
          user: userId,
          ...prefs
        });
      } else {
        Object.assign(notificationPrefs, prefs);
      }

      await notificationPrefs.save();

      // Update user reference if not exists
      await User.findByIdAndUpdate(userId, {
        notificationPrefs: notificationPrefs._id
      });

      return successResponse(res, { preferences: notificationPrefs }, 'Notification preferences updated');
    } catch (error) {
      logger.error('Update notification prefs error:', error);
      return errorResponse(res, 'Failed to update preferences', 500);
    }
  }

  async requestAccountDeletion(req, res) {
    try {
      const { reason } = req.body;
      const userId = req.user.id;

      // Check if there's already a pending request
      const existingRequest = await DeletionRequest.findOne({
        user: userId,
        status: 'pending'
      });

      if (existingRequest) {
        return errorResponse(res, 'Account deletion request already pending', 409);
      }

      const confirmationToken = uuidv4();
      
      const deletionRequest = new DeletionRequest({
        user: userId,
        reason,
        confirmationToken
      });

      await deletionRequest.save();

      // Send confirmation email (implementation depends on your email service)
      // await emailService.sendDeletionConfirmation(req.user.email, confirmationToken);

      return successResponse(res, {
        requestId: deletionRequest._id,
        message: 'Account deletion requested. Please check your email for confirmation.'
      }, 'Deletion request submitted');
    } catch (error) {
      logger.error('Account deletion request error:', error);
      return errorResponse(res, 'Failed to process deletion request', 500);
    }
  }

  async confirmAccountDeletion(req, res) {
    try {
      const { token } = req.query;
      const userId = req.user.id;

      const deletionRequest = await DeletionRequest.findOne({
        user: userId,
        confirmationToken: token,
        status: 'pending'
      });

      if (!deletionRequest) {
        return errorResponse(res, 'Invalid or expired deletion request', 400);
      }

      if (new Date() > deletionRequest.expiresAt) {
        return errorResponse(res, 'Deletion request expired', 400);
      }

      // Mark request as approved (actual deletion would be handled by admin)
      deletionRequest.status = 'approved';
      deletionRequest.processedAt = new Date();
      await deletionRequest.save();

      // Deactivate user account
      await User.findByIdAndUpdate(userId, { isActive: false });

      return successResponse(res, null, 'Account deletion confirmed. Your account will be deleted within 30 days.');
    } catch (error) {
      logger.error('Confirm account deletion error:', error);
      return errorResponse(res, 'Failed to confirm deletion', 500);
    }
  }

  async getBookingHistory(req, res) {
    try {
      const userId = req.user.id;
      const { page = 1, limit = 10, status } = req.query;

      const query = { user: userId };
      if (status) {
        query.status = status;
      }

      const appointments = await Appointment.find(query)
        .populate('psychologist', 'name specializations rating')
        .sort({ dateTime: -1 })
        .limit(limit * 1)
        .skip((page - 1) * limit);

      const total = await Appointment.countDocuments(query);

      return successResponse(res, {
        appointments,
        pagination: {
          currentPage: page,
          totalPages: Math.ceil(total / limit),
          totalItems: total,
          hasMore: page < Math.ceil(total / limit)
        }
      }, 'Booking history retrieved successfully');
    } catch (error) {
      logger.error('Get booking history error:', error);
      return errorResponse(res, 'Failed to retrieve booking history', 500);
    }
  }
}

module.exports = new UserController();