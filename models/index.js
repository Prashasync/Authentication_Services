const { Sequelize } = require('sequelize');
const env = process.env.NODE_ENV || 'development';
const config = require(__dirname + '/../config/config.js')[env];
const logger = require('../utils/logger');
const db = {};

// Custom logger for Sequelize
config.logging = (msg) => logger.info(`[Sequelize] ${msg}`);

const sequelize = new Sequelize(
  config.database,
  config.username,
  config.password,
  {
    host: config.host,
    port: config.port,
    dialect: config.dialect,
    dialectOptions: {
      ssl: {
        require: true,
        rejectUnauthorized: false,
      },
    },
  }
);
 
sequelize.authenticate()
  .then(() => logger.info('✅ Database connected successfully'))
  .catch((err) => logger.error(`❌ Unable to connect to the database: ${err.message}`));

db.Sequelize = Sequelize;
db.sequelize = sequelize;
db.User = require('./user')(sequelize, Sequelize);
db.Otp = require('./Otp')(sequelize, Sequelize);

module.exports = db;
