require("dotenv").config();
const express = require("express");
const { loadSecrets } = require("./utils/loadSecret");
const db = require("./models");
const routes = require("./routes");
const logger = require("./utils/logger");
const requestLogger = require("./middlewares/requestLogger");
const cors = require("cors");

(async () => {
  // await loadSecrets();

  const app = express();
  const PORT = process.env.PORT || 4000;

  app.use(express.json());
  app.use(requestLogger);
  app.use(
    cors({
      origin: function (origin, callback) {
        const allowedOrigins = [
          "http://localhost:3000",
          "http://care.prashasync.io",
        ];
        if (!origin || allowedOrigins.includes(origin)) {
          callback(null, true);
        } else {
          callback(new Error("Not allowed by CORS"));
        }
      },
      credentials: true,
    })
  );

  app.get("/", (req, res) => {
    res.send("👋 Welcome to the API — v1 🚀");
  });

  app.use("/api/v1", routes);

  db.sequelize.sync().then(() => {
    app.listen(PORT, () => {
      logger.info(`✅ Server running on port ${PORT}`);
    });
  });
})();
