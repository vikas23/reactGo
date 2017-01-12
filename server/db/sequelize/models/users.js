import Promise from 'bluebird';
import bcryptNode from 'bcrypt-nodejs';

const bcrypt = Promise.promisifyAll(bcryptNode);

// Other oauthtypes to be added

/* eslint-disable no-param-reassign */
function hashPassword(user) {
  if (!user.changed('password')) return null;
  return bcrypt.genSaltAsync(5).then((salt) =>
    bcrypt.hashAsync(user.password, salt, null).then((hash) => {
      user.password = hash;
    })
  );
}
/* eslint-enable no-param-reassign */

export default (sequelize, DataTypes) => {
  const User = sequelize.define('User', {
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      validate: {
        isEmail: true
      }
    },
    password: {
      type: DataTypes.STRING
    },
    name: {
      type: DataTypes.STRING,
      defaultValue: ''
    },
    organisation: {
      type: DataTypes.STRING,
      defaultValue: ''
    },
    manager: {
      type: DataTypes.STRING,
      defaultValue: ''
    },
    userType: {
      type: DataTypes.STRING,
      defaultValue: ''
    },
    joinDate: {
      type: DataTypes.DATE,
      defaultValue: ''
    },
    resetPasswordToken: {
      type: DataTypes.STRING
    },
    resetPasswordExpires: {
      type: DataTypes.DATE
    }
  }, {
    timestamps: false,

    classMethods: {
      associate(models) {
        User.hasMany(models.Token, {
          foreignKey: 'userId'
        });
      }
    },

    instanceMethods: {
      comparePassword(candidatePassword) {
          return bcrypt.compareAsync(candidatePassword, this.password);
        },

        toJSON() {
          return {
            id: this.id,
            email: this.email,
            name: this.name,
            organisation: this.organisation,
            manager: this.manager,
            userType: this.userType,
            joinDate: this.joinDate
          };
        }
    }
  });

  User.beforeCreate(hashPassword);
  User.beforeUpdate(hashPassword);

  return User;
};
