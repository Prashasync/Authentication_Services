require('dotenv').config();
const express = require('express');
const db = require('./models');
const routes = require('./routes');
const logger = require('./utils/logger');
const requestLogger = require('./middlewares/requestLogger');
const cors = require('cors');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 4000;

app.use(express.json());
app.use(requestLogger);
app.use(
  cors({
    origin: function (origin, callback) {
      const allowedOrigins = [
        'http://localhost',
        'http://localhost:3000',
        'http://localhost:3001',
        'http://localhost:80',
        'http://care.prashasync.io',
        'https://care.prashasync.io',
        'http://api.prashasync.io',
        'https://api.prashasync.io',
        'http://aibot.prashasync.io',
        'https://aibot.prashasync.io',
      ];
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true,
  })
);

app.use(
  session({
    secret: process.env.JWT_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 15 * 60 * 10000,
    },
    rolling: true,
  })
);

app.get('/', (req, res) => {
  res.send('👋 Welcome to the API — v1 🚀');
});

app.use('/api/v1', routes);

db.sequelize.sync().then(() => {
  app.listen(PORT, () => {
    logger.info(`✅ Server running on port ${PORT}`);
  });
});
