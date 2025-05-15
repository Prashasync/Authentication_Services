require("dotenv").config();
const express = require("express");
const app = express();
const db = require("./models");
const routes = require("./routes");
const logger = require("./utils/logger");
const requestLogger = require("./middlewares/requestLogger");
const cors = require("cors");

const PORT = process.env.PORT || 4000;

// Updated CORS configuration to handle multiple origins
const allowedOrigins = (process.env.CORS_ORIGIN || "http://localhost:3000").split(",");

app.use(express.json());
app.use(requestLogger);
//old code
// app.use(cors(
//   {
//     origin: process.env.CORS_ORIGIN || "http://localhost:3000",
//     methods: ["GET", "POST", "PUT", "DELETE"],
//     credentials: true,
//   }
// ));

// new
app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (like mobile apps, curl, Postman)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1 || allowedOrigins.includes('*')) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  credentials: true,
}));


app.get("/", (req, res) => {
  res.send("👋 Welcome to the API — v1 🚀");
});
app.use("/api/v1", routes);

db.sequelize.sync().then(() => {
  app.listen(PORT, () => {
    logger.info(`✅ Server running on port ${PORT}`);
  });
});