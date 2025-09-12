const Joi = require('joi');

const signupSchema = Joi.object({
  name: Joi.string().min(2).max(50).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(8).pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/).required(),
  contact: Joi.string().pattern(/^\+?[1-9]\d{1,14}$/).required(),
  age: Joi.number().min(13).max(120).required()
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

const otpSchema = Joi.object({
  otp: Joi.string().length(6).pattern(/^\d+$/).required(),
  tempToken: Joi.string().required()
});

const postSchema = Joi.object({
  title: Joi.string().min(1).max(200).required(),
  content: Joi.string().min(1).max(5000).required(),
  moodTag: Joi.string().valid('Bad', 'NotGreat', 'OK', 'Happy', 'Joyful').optional(),
  isAnonymous: Joi.boolean().default(false)
});

const pollSchema = Joi.object({
  question: Joi.string().min(5).max(300).required(),
  options: Joi.array().items(Joi.string().min(1).max(100)).min(2).max(6).required(),
  expiresAt: Joi.date().min('now').optional()
});

const moodLogSchema = Joi.object({
  emoji: Joi.string().required(),
  scale: Joi.number().min(1).max(5).required(),
  emotions: Joi.array().items(Joi.string()).max(10).optional(),
  notes: Joi.string().max(1000).optional()
});

const appointmentSchema = Joi.object({
  psychologistId: Joi.string().hex().length(24).required(),
  dateTime: Joi.date().min('now').required(),
  notes: Joi.string().max(500).optional()
});

module.exports = {
  signupSchema,
  loginSchema,
  otpSchema,
  postSchema,
  pollSchema,
  moodLogSchema,
  appointmentSchema
};