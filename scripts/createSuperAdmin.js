require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const User = require('../models/User');

const SUPER_ADMIN = {
  username: 'superadmin',
  email: 'admin@fundmebank.com',
  password: 'SuperAdmin@2025', // Change this in production
  role: 'super_admin'
};

async function createSuperAdmin() {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log('Connected to MongoDB');

    // Check if super admin exists
    const existingAdmin = await User.findOne({ role: 'super_admin' });
    if (existingAdmin) {
      console.log('Super admin already exists');
      process.exit(0);
    }

    // Create super admin
    const passwordHash = await bcrypt.hash(SUPER_ADMIN.password, 10);
    const superAdmin = await User.create({
      username: SUPER_ADMIN.username,
      email: SUPER_ADMIN.email,
      passwordHash,
      role: SUPER_ADMIN.role,
      isActive: true
    });

    console.log('Super admin created successfully:', {
      username: superAdmin.username,
      email: superAdmin.email,
      role: superAdmin.role
    });

    process.exit(0);
  } catch (err) {
    console.error('Error creating super admin:', err);
    process.exit(1);
  }
}

createSuperAdmin(); 