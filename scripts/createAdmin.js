const mongoose = require('mongoose');
const User = require('../models/User');
const bcrypt = require('bcrypt');

async function createAdmin() {
  try {
    // Connect to MongoDB
    await mongoose.connect('mongodb://localhost:27017/fmb', {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });

    // Check if admin already exists
    const existingAdmin = await User.findOne({ role: 'admin' });
    if (existingAdmin) {
      console.log('Admin user already exists:');
      console.log(`Username: ${existingAdmin.username}`);
      console.log(`Email: ${existingAdmin.email}`);
      return;
    }

    // Create admin user
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash('admin123', salt);

    const admin = new User({
      username: 'admin',
      email: 'admin@fundmebank.com',
      passwordHash,
      role: 'admin',
      isActive: true,
      accountBalance: 0,
      lastLogin: new Date(),
      createdAt: new Date()
    });

    await admin.save();
    console.log('Admin user created successfully:');
    console.log('Username: admin');
    console.log('Password: admin123');
    console.log('Email: admin@fundmebank.com');

    // Close the connection
    await mongoose.connection.close();
  } catch (error) {
    console.error('Error:', error);
    process.exit(1);
  }
}

createAdmin(); 