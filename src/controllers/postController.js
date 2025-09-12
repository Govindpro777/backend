const Post = require('../models/Post');
const Comment = require('../models/Comment');
const { successResponse, errorResponse } = require('../utils/response');
const { postSchema } = require('../utils/validators');
const logger = require('../utils/logger');

class PostController {
  async createPost(req, res) {
    try {
      const { error } = postSchema.validate(req.body);
      if (error) {
        const errors = error.details.map(detail => ({
          field: detail.path[0],
          message: detail.message
        }));
        return errorResponse(res, 'Validation failed', 400, errors);
      }

      const post = new Post({
        ...req.body,
        author: req.user.id
      });

      await post.save();
      await post.populate('author', 'name profile.avatar');

      return successResponse(res, { post }, 'Post created successfully', 201);
    } catch (error) {
      logger.error('Create post error:', error);
      return errorResponse(res, 'Failed to create post', 500);
    }
  }

  async getPosts(req, res) {
    try {
      const { page = 1, limit = 10, moodTag, author } = req.query;
      
      const query = { isDeleted: false, visibility: 'public' };
      if (moodTag) query.moodTag = moodTag;
      if (author) query.author = author;

      const posts = await Post.find(query)
        .populate('author', 'name profile.avatar')
        .sort({ createdAt: -1 })
        .limit(limit * 1)
        .skip((page - 1) * limit);

      const total = await Post.countDocuments(query);

      return successResponse(res, {
        posts,
        pagination: {
          currentPage: page,
          totalPages: Math.ceil(total / limit),
          totalItems: total
        }
      }, 'Posts retrieved successfully');
    } catch (error) {
      logger.error('Get posts error:', error);
      return errorResponse(res, 'Failed to retrieve posts', 500);
    }
  }

  async getPost(req, res) {
    try {
      const post = await Post.findOne({
        _id: req.params.id,
        isDeleted: false
      })
      .populate('author', 'name profile.avatar')
      .populate({
        path: 'comments',
        populate: {
          path: 'author',
          select: 'name profile.avatar'
        }
      });

      if (!post) {
        return errorResponse(res, 'Post not found', 404);
      }

      return successResponse(res, { post }, 'Post retrieved successfully');
    } catch (error) {
      logger.error('Get post error:', error);
      return errorResponse(res, 'Failed to retrieve post', 500);
    }
  }

  async updatePost(req, res) {
    try {
      const postId = req.params.id;
      const userId = req.user.id;
      
      const post = await Post.findOne({
        _id: postId,
        author: userId,
        isDeleted: false
      });

      if (!post) {
        return errorResponse(res, 'Post not found or not authorized', 404);
      }

      const { title, content, moodTag, visibility } = req.body;
      
      if (title) post.title = title;
      if (content) post.content = content;
      if (moodTag) post.moodTag = moodTag;
      if (visibility) post.visibility = visibility;

      await post.save();
      await post.populate('author', 'name profile.avatar');

      return successResponse(res, { post }, 'Post updated successfully');
    } catch (error) {
      logger.error('Update post error:', error);
      return errorResponse(res, 'Failed to update post', 500);
    }
  }

  async deletePost(req, res) {
    try {
      const postId = req.params.id;
      const userId = req.user.id;
      const userRole = req.user.role;
      
      const query = { _id: postId, isDeleted: false };
      
      // Only post author or admin can delete
      if (userRole !== 'admin' && userRole !== 'superadmin') {
        query.author = userId;
      }

      const post = await Post.findOne(query);

      if (!post) {
        return errorResponse(res, 'Post not found or not authorized', 404);
      }

      post.isDeleted = true;
      await post.save();

      return successResponse(res, null, 'Post deleted successfully');
    } catch (error) {
      logger.error('Delete post error:', error);
      return errorResponse(res, 'Failed to delete post', 500);
    }
  }

  async likePost(req, res) {
    try {
      const postId = req.params.id;
      const userId = req.user.id;

      const post = await Post.findOne({ _id: postId, isDeleted: false });
      
      if (!post) {
        return errorResponse(res, 'Post not found', 404);
      }

      // Remove from unlikes if exists
      post.unlikes = post.unlikes.filter(unlike => unlike.user.toString() !== userId);
      
      // Check if already liked
      const existingLike = post.likes.find(like => like.user.toString() === userId);
      
      if (existingLike) {
        // Remove like
        post.likes = post.likes.filter(like => like.user.toString() !== userId);
      } else {
        // Add like
        post.likes.push({ user: userId });
      }

      await post.save();

      return successResponse(res, {
        liked: !existingLike,
        likesCount: post.likesCount,
        unlikesCount: post.unlikesCount
      }, existingLike ? 'Post unliked' : 'Post liked');
    } catch (error) {
      logger.error('Like post error:', error);
      return errorResponse(res, 'Failed to like/unlike post', 500);
    }
  }

  async addComment(req, res) {
    try {
      const { content, isAnonymous = false } = req.body;
      const postId = req.params.id;
      const userId = req.user.id;

      if (!content || content.trim().length === 0) {
        return errorResponse(res, 'Comment content is required', 400);
      }

      const post = await Post.findOne({ _id: postId, isDeleted: false });
      
      if (!post) {
        return errorResponse(res, 'Post not found', 404);
      }

      const comment = new Comment({
        content: content.trim(),
        author: userId,
        post: postId,
        isAnonymous
      });

      await comment.save();
      await comment.populate('author', 'name profile.avatar');

      // Add comment reference to post
      post.comments.push(comment._id);
      await post.save();

      return successResponse(res, { comment }, 'Comment added successfully', 201);
    } catch (error) {
      logger.error('Add comment error:', error);
      return errorResponse(res, 'Failed to add comment', 500);
    }
  }

  async getComments(req, res) {
    try {
      const postId = req.params.id;
      const { page = 1, limit = 20 } = req.query;

      const comments = await Comment.find({
        post: postId,
        isDeleted: false
      })
      .populate('author', 'name profile.avatar')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

      const total = await Comment.countDocuments({
        post: postId,
        isDeleted: false
      });

      return successResponse(res, {
        comments,
        pagination: {
          currentPage: page,
          totalPages: Math.ceil(total / limit),
          totalItems: total
        }
      }, 'Comments retrieved successfully');
    } catch (error) {
      logger.error('Get comments error:', error);
      return errorResponse(res, 'Failed to retrieve comments', 500);
    }
  }
}

module.exports = new PostController();