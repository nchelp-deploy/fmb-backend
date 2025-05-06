const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    unique: true, 
    required: true 
  },
  passwordHash: { 
    type: String, 
    required: true, 
    select: false 
  },
  email: { 
    type: String, 
    unique: true, 
    required: true 
  },
  role: { 
    type: String, 
    enum: ['user', 'admin', 'super_admin'],
    default: 'user'
  },
  googleId: { 
    type: String, 
    unique: true, 
    sparse: true 
  },
  transactions: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Transaction'
  }],
  accountBalance: {
    type: Number,
    default: 0
  },
  isActive: {
    type: Boolean,
    default: true
  },
  lastLogin: {
    type: Date,
    default: Date.now
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  modifiedBy: {
    adminId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    modifiedAt: Date,
    reason: String
  }
});

// Add method to compare passwords
userSchema.methods.comparePassword = async function(candidatePassword) {
  const user = await this.constructor.findById(this._id).select('+passwordHash');
  return bcrypt.compare(candidatePassword, user.passwordHash);
};

// Add method to check if user is admin
userSchema.methods.isAdmin = function() {
  return this.role === 'admin' || this.role === 'super_admin';
};

// Add method to check if user is super admin
userSchema.methods.isSuperAdmin = function() {
  return this.role === 'super_admin';
};

module.exports = mongoose.model('User', userSchema);
