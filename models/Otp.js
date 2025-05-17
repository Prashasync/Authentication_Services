module.exports = (sequelize, DataTypes) => {
  const Otp = sequelize.define(
    "otps",
    {
      otp_id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        allowNull: false,
        primaryKey: true,
      },
      otp_text: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      otp_attempts: {
        type: DataTypes.INTEGER,
        allowNull: false
      },
      user_id: {
        type: DataTypes.UUID,
        allowNull: false,
      },
      valid_until: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      blocked_until: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      validated_at: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      status: {
        type: DataTypes.STRING,
        allowNull: true,
      },
      roles: {
        type: DataTypes.TEXT,
        allowNull: false
      },
      updatedAt: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      createdAt: {
        type: DataTypes.DATE,
        defaultValue: DataTypes.NOW,
      },
    },
    {
      tableName: "otps",
      timestamps: true,
    }
  );
 
  return Otp;
};
