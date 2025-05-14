const express = require("express");
const router = express.Router();
const authRoutes = require("./auth.routes");
const awsConfigRoute = require("./awsCongifs");

router.use("/auth", authRoutes);
router.use("/aws_configs", awsConfigRoute);

module.exports = router;
