module.exports = (sequelize, DataTypes) => {
  const User = sequelize.define("user", {
    otpId: {
      type: DataTypes.UUID,
      allowNull: true, 
    },    
    name: DataTypes.STRING,
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
      validate: {
        isEmail: true,
      },
    },
    phone: {
      type: DataTypes.STRING,
      unique: true,
      allowNull: true,
    },
    password: DataTypes.STRING,
    otp: DataTypes.STRING,
    otpId: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
    },
    otpExpiresAt: DataTypes.DATE,
    isVerified: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
    },
    otpattempts: {
      type: DataTypes.INTEGER,
      defaultValue: 0,
      allowNull: false,
    },
    blockeduntil: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    otpRequestedAt: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    otpblockeduntil: {
      type: DataTypes.DATE,
      allowNull: true,
    },
    createdAt: {
      type: DataTypes.DATE,
      defaultValue: DataTypes.NOW,
    },
    updatedAt: {
      type: DataTypes.DATE,
      defaultValue: DataTypes.NOW,
    },
    title: {
      type: DataTypes.STRING,  
    },
    first_name: {
      type: DataTypes.STRING,  
    },
    middle_name: {
      type: DataTypes.STRING,  
    },
    last_name: {
      type: DataTypes.STRING, 
    },
    gender: {
      type: DataTypes.STRING,  
    },
    roles: {
      type: DataTypes.STRING,  
    },
    profile_picture: {
      type: DataTypes.TEXT, 
    },
    is_active: {
      type: DataTypes.BOOLEAN,
      defaultValue: true,  
    },
    last_login: {
      type: DataTypes.DATE,  
    },
    is_deleted: {
      type: DataTypes.BOOLEAN,
      defaultValue: false, 
    }
  });

  return User;
};



