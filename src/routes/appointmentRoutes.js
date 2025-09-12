const express = require('express');
const Appointment = require('../models/Appointment');
const Psychologist = require('../models/Psychologist');
const { authenticate } = require('../middlewares/auth');
const { successResponse, errorResponse } = require('../utils/response');
const { appointmentSchema } = require('../utils/validators');
const logger = require('../utils/logger');

const router = express.Router();

router.use(authenticate);

// Book appointment
router.post('/', async (req, res) => {
  try {
    const { error } = appointmentSchema.validate(req.body);
    if (error) {
      const errors = error.details.map(detail => ({
        field: detail.path[0],
        message: detail.message
      }));
      return errorResponse(res, 'Validation failed', 400, errors);
    }

    const { psychologistId, dateTime, notes } = req.body;
    
    // Check if psychologist exists and is available
    const psychologist = await Psychologist.findOne({
      _id: psychologistId,
      isActive: true
    });
    
    if (!psychologist) {
      return errorResponse(res, 'Psychologist not found', 404);
    }

    // Check for conflicting appointments
    const conflictingAppointment = await Appointment.findOne({
      psychologist: psychologistId,
      dateTime: new Date(dateTime),
      status: { $ne: 'cancelled' }
    });

    if (conflictingAppointment) {
      return errorResponse(res, 'Time slot not available', 409);
    }

    const appointment = new Appointment({
      user: req.user.id,
      psychologist: psychologistId,
      dateTime: new Date(dateTime),
      notes
    });

    await appointment.save();
    await appointment.populate('psychologist', 'name specializations');

    return successResponse(res, { appointment }, 'Appointment booked successfully', 201);
  } catch (error) {
    logger.error('Book appointment error:', error);
    return errorResponse(res, 'Failed to book appointment', 500);
  }
});

// Get user appointments
router.get('/my', async (req, res) => {
  try {
    const { status, page = 1, limit = 10 } = req.query;
    
    const query = { user: req.user.id };
    if (status) query.status = status;

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
        totalItems: total
      }
    });
  } catch (error) {
    logger.error('Get appointments error:', error);
    return errorResponse(res, 'Failed to retrieve appointments', 500);
  }
});

// Cancel appointment
router.put('/:id/cancel', async (req, res) => {
  try {
    const { reason } = req.body;
    const appointmentId = req.params.id;
    
    const appointment = await Appointment.findOne({
      _id: appointmentId,
      user: req.user.id,
      status: 'scheduled'
    });

    if (!appointment) {
      return errorResponse(res, 'Appointment not found or cannot be cancelled', 404);
    }

    appointment.status = 'cancelled';
    appointment.cancellationReason = reason;
    appointment.cancelledBy = 'user';
    
    await appointment.save();

    return successResponse(res, { appointment }, 'Appointment cancelled successfully');
  } catch (error) {
    logger.error('Cancel appointment error:', error);
    return errorResponse(res, 'Failed to cancel appointment', 500);
  }
});

// Get available slots for a psychologist
router.get('/psychologist/:id/slots', async (req, res) => {
  try {
    const { date } = req.query; // YYYY-MM-DD format
    const psychologistId = req.params.id;

    const psychologist = await Psychologist.findOne({
      _id: psychologistId,
      isActive: true
    });

    if (!psychologist) {
      return errorResponse(res, 'Psychologist not found', 404);
    }

    // Get booked appointments for the date
    const startDate = new Date(date);
    const endDate = new Date(date);
    endDate.setDate(endDate.getDate() + 1);

    const bookedSlots = await Appointment.find({
      psychologist: psychologistId,
      dateTime: { $gte: startDate, $lt: endDate },
      status: { $ne: 'cancelled' }
    }).select('dateTime duration');

    return successResponse(res, {
      psychologist: {
        id: psychologist._id,
        name: psychologist.name,
        schedule: psychologist.schedule
      },
      bookedSlots,
      date
    });
  } catch (error) {
    logger.error('Get available slots error:', error);
    return errorResponse(res, 'Failed to retrieve available slots', 500);
  }
});

module.exports = router;