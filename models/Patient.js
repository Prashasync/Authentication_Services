module.exports = (sequelize, DataTypes) => {
  const Patient = sequelize.define(
    "patients",
    {
      patient_id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
        allowNull: false,
      },
      user_id: {
        type: DataTypes.UUID,
        allowNull: false,
      },
      title: {
        type: DataTypes.STRING,
      },
      first_name: {
        type: DataTypes.STRING,
      },
      last_name: {
        type: DataTypes.STRING,
      },
      address: {
        type: DataTypes.STRING,
      },
      dob: {
        type: DataTypes.DATE,
      },
      phone: {
        type: DataTypes.STRING,
      },
      interests: {
        type: DataTypes.JSONB,
      },
      treatment: {
        type: DataTypes.JSONB,
      },
      language: {
        type: DataTypes.STRING,
      },
      religion: {
        type: DataTypes.STRING,
      },
      region: {
        type: DataTypes.STRING,
      },
      health_score: {
        type: DataTypes.INTEGER,
      },
      under_medications: {
        type: DataTypes.BOOLEAN,
      },
      gender: {
        type: DataTypes.STRING,
      },
      created_at: {
        type: DataTypes.DATE,
        defaultValue: DataTypes.NOW,
      },
      updated_at: {
        type: DataTypes.DATE,
        defaultValue: DataTypes.NOW,
      },
      isOnboarded: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
      },
      onboardingCompletedAt: {
        type: DataTypes.DATE,
      },
      timezone: {
        type: DataTypes.STRING,
      },
      preferences: {
        type: DataTypes.JSONB,
        defaultValue: {},
      },
    },
    {
      tableName: "patients",
      timestamps: true,
      createdAt: "created_at",
      updatedAt: "updated_at",
    }
  );

  Patient.associate = (models) => {
    Patient.belongsTo(models.User, {
      foreignKey: "user_id",
      targetKey: "user_id",
      as: "user",
      onDelete: "CASCADE",
    });
  };

  return Patient;
};
