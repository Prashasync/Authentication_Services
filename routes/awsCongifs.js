const express = require("express");
const authMiddleware = require("../middlewares/auth");
const { getAWSConfig } = require("../controllers/auth.controller");
const router = express.Router();

router.get("/aws-configs", authMiddleware, getAWSConfig);

module.exports = router;