require("dotenv").config();
const express = require("express");
const app = express();
const db = require("./models");
const routes = require("./routes");
const logger = require("./utils/logger");
const requestLogger = require("./middlewares/requestLogger");
const cors = require("cors");

const PORT = process.env.PORT || 4000;

app.use(express.json());
app.use(requestLogger);
app.use(cors(
  {
    origin: process.env.CORS_ORIGIN || "http://localhost:3000",
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  }
));

app.get("/", (req, res) => {
  res.send("👋 Welcome to the API — v1 🚀");
});
app.use("/api/v1", routes);

db.sequelize.sync().then(() => {
  app.listen(PORT, () => {
    logger.info(`✅ Server running on port ${PORT}`);
  });
});