module.exports = (sequelize, DataTypes) => {
    const SocialLogins = sequelize.define(
      "social_logins",
      {
        social_id: {
          type: DataTypes.UUID,
          defaultValue: DataTypes.UUIDV4,
          primaryKey: true,
          allowNull: false,
        },
        email: {
          type: DataTypes.STRING,
          allowNull: false,
        },
        user_id: {
          type: DataTypes.TEXT,
          allowNull: true,
        },
        provider_name: {
          type: DataTypes.STRING,
          allowNull: false,
        },
        provider_id: {
          type: DataTypes.STRING,
          allowNull: false,
        },
        created_at: {
          type: DataTypes.DATE,
          defaultValue: DataTypes.NOW,
        },
        updated_at: {
          type: DataTypes.DATE,
          defaultValue: DataTypes.NOW,
        },
        status:{  
          type: DataTypes.BOOLEAN,
          defaultValue: false,
        },
      },
      {
        tableName: "social_logins",
        timestamps: true,
        createdAt: "created_at",
        updatedAt: "updated_at",
      }
    );
    
  
    return SocialLogins;
  };
  