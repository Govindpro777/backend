const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
require('dotenv').config();

const User = require('../models/User');
const { Questionnaire } = require('../models/Questionnaire');
const Psychologist = require('../models/Psychologist');
const ContentLibrary = require('../models/ContentLibrary');
const logger = require('../utils/logger');

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URL, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    logger.info('✅ Connected to MongoDB');
  } catch (error) {
    logger.error('❌ MongoDB connection failed:', error);
    process.exit(1);
  }
};

const seedSuperAdmin = async () => {
  try {
    const adminEmail = process.env.ADMIN_EMAIL || 'superadmin@example.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'StrongPassword123!';

    const existingAdmin = await User.findOne({ email: adminEmail });
    
    if (existingAdmin) {
      logger.info(`ℹ️  Super admin already exists: ${adminEmail}`);
      return existingAdmin;
    }

    const hashedPassword = await bcrypt.hash(adminPassword, 12);

    const superAdmin = new User({
      name: 'Super Administrator',
      email: adminEmail,
      password: adminPassword, // Will be hashed by pre-save middleware
      contact: '+1234567890',
      age: 30,
      role: 'superadmin',
      isEmailVerified: true,
      isContactVerified: true,
      isActive: true,
      profile: {
        bio: 'System Administrator',
        interests: ['mental health', 'technology', 'wellness']
      }
    });

    await superAdmin.save();
    logger.info(`✅ Super admin created: ${adminEmail}`);
    
    return superAdmin;
  } catch (error) {
    logger.error('❌ Failed to create super admin:', error);
    throw error;
  }
};

const seedDefaultQuestionnaire = async () => {
  try {
    const existingQuestionnaire = await Questionnaire.findOne({ isActive: true });
    
    if (existingQuestionnaire) {
      logger.info('ℹ️  Default questionnaire already exists');
      return;
    }

    const questionnaire = new Questionnaire({
      title: 'Mental Health Assessment',
      description: 'This questionnaire helps us understand your current mental health status and provide personalized recommendations.',
      questions: [
        {
          text: 'How often do you feel overwhelmed or stressed?',
          type: 'multiple-choice',
          options: ['Never', 'Rarely', 'Sometimes', 'Often', 'Always']
        },
        {
          text: 'How would you rate your sleep quality?',
          type: 'rating',
          options: ['1', '2', '3', '4', '5']
        },
        {
          text: 'Do you have someone you can talk to when you\'re feeling down?',
          type: 'multiple-choice',
          options: ['Yes, always', 'Yes, sometimes', 'Not really', 'No, never']
        },
        {
          text: 'How often do you engage in activities you enjoy?',
          type: 'multiple-choice',
          options: ['Daily', 'Weekly', 'Monthly', 'Rarely', 'Never']
        },
        {
          text: 'On a scale of 1-5, how would you rate your overall mental wellbeing?',
          type: 'rating',
          options: ['1', '2', '3', '4', '5']
        }
      ],
      isActive: true
    });

    await questionnaire.save();
    logger.info('✅ Default questionnaire created');
  } catch (error) {
    logger.error('❌ Failed to create default questionnaire:', error);
  }
};

const seedSamplePsychologists = async () => {
  try {
    const count = await Psychologist.countDocuments();
    
    if (count > 0) {
      logger.info('ℹ️  Sample psychologists already exist');
      return;
    }

    const samplePsychologists = [
      {
        name: 'Dr. Sarah Johnson',
        email: 'sarah.johnson@clinic.com',
        degree: 'PhD in Clinical Psychology',
        experience: 8,
        about: 'Specializing in anxiety and depression treatment with cognitive behavioral therapy approach.',
        rating: 4.8,
        specializations: ['Anxiety', 'Depression', 'Stress Management'],
        schedule: [
          { day: 'Monday', startTime: '09:00', endTime: '17:00' },
          { day: 'Tuesday', startTime: '09:00', endTime: '17:00' },
          { day: 'Wednesday', startTime: '09:00', endTime: '17:00' },
          { day: 'Thursday', startTime: '09:00', endTime: '17:00' },
          { day: 'Friday', startTime: '09:00', endTime: '15:00' }
        ],
        languages: ['English', 'Spanish'],
        sessionRate: 150
      },
      {
        name: 'Dr. Michael Chen',
        email: 'michael.chen@clinic.com',
        degree: 'MD, Psychiatrist',
        experience: 12,
        about: 'Experienced psychiatrist focusing on trauma recovery and PTSD treatment.',
        rating: 4.9,
        specializations: ['PTSD', 'Trauma', 'Anxiety'],
        schedule: [
          { day: 'Tuesday', startTime: '10:00', endTime: '18:00' },
          { day: 'Wednesday', startTime: '10:00', endTime: '18:00' },
          { day: 'Thursday', startTime: '10:00', endTime: '18:00' },
          { day: 'Friday', startTime: '10:00', endTime: '16:00' },
          { day: 'Saturday', startTime: '09:00', endTime: '13:00' }
        ],
        languages: ['English', 'Mandarin'],
        sessionRate: 200
      }
    ];

    await Psychologist.insertMany(samplePsychologists);
    logger.info('✅ Sample psychologists created');
  } catch (error) {
    logger.error('❌ Failed to create sample psychologists:', error);
  }
};

const seedSampleContent = async () => {
  try {
    const count = await ContentLibrary.countDocuments();
    
    if (count > 0) {
      logger.info('ℹ️  Sample content already exists');
      return;
    }

    const sampleContent = [
      {
        title: '5-Minute Breathing Meditation',
        description: 'A gentle breathing exercise to help you relax and center yourself.',
        type: 'meditation',
        category: 'stress-relief',
        url: 'https://example.com/meditation/breathing-5min.mp3',
        duration: 300,
        author: 'Dr. Wellness',
        tags: ['breathing', 'relaxation', 'beginner'],
        difficulty: 'beginner',
        isPublished: true,
        publishedAt: new Date()
      },
      {
        title: 'Understanding Anxiety: A Beginner\'s Guide',
        description: 'Learn about anxiety symptoms, triggers, and coping strategies.',
        type: 'article',
        category: 'anxiety',
        url: 'https://example.com/articles/anxiety-guide.html',
        author: 'Mental Health Team',
        tags: ['anxiety', 'education', 'coping'],
        difficulty: 'beginner',
        isPublished: true,
        publishedAt: new Date()
      },
      {
        title: 'Calming Nature Sounds',
        description: 'Peaceful nature sounds for relaxation and focus.',
        type: 'music',
        category: 'sleep',
        url: 'https://example.com/music/nature-sounds.mp3',
        duration: 1800,
        author: 'Sound Therapy Studio',
        tags: ['nature', 'sleep', 'relaxation'],
        difficulty: 'beginner',
        isPublished: true,
        publishedAt: new Date()
      }
    ];

    await ContentLibrary.insertMany(sampleContent);
    logger.info('✅ Sample content created');
  } catch (error) {
    logger.error('❌ Failed to create sample content:', error);
  }
};

const runSeed = async () => {
  try {
    logger.info('🌱 Starting seed process...');
    
    await connectDB();
    
    await seedSuperAdmin();
    await seedDefaultQuestionnaire();
    await seedSamplePsychologists();
    await seedSampleContent();
    
    logger.info('✅ Seed process completed successfully');
    process.exit(0);
  } catch (error) {
    logger.error('❌ Seed process failed:', error);
    process.exit(1);
  }
};

// Run if called directly
if (require.main === module) {
  runSeed();
}

module.exports = { runSeed, seedSuperAdmin };