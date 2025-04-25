const express = require('express');
const router = express.Router();
const authRoutes = require('./auth.routes');
const patientRoutes = require('./patient.routes');
router.use('/auth', authRoutes);
router.use('/patients', patientRoutes)
module.exports = router;
