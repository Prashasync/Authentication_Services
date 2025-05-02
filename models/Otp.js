module.exports = (sequelize, DataTypes) => {
  const Otp = sequelize.define(
    "otp",
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
      user_id: {
        type: DataTypes.UUID,
        allowNull: false,
      },
      // otp_attempts: {
      //   type: DataTypes.INTEGER,
      //   defaultValue: 0,
      // },
      // blocked_until: {
      //   type: DataTypes.DATE,
      //   allowNull: true,
      // },
      created_at: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      valid_until: {
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
    },
  );
 
  return Otp;
};
