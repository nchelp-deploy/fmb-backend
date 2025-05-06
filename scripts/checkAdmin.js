require('dotenv').config();
const mongoose = require('mongoose');
const User = require('../models/User');

async function checkAdmin() {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log('Connected to MongoDB');

    const adminUsers = await User.find({ 
      $or: [{ role: 'admin' }, { role: 'super_admin' }] 
    }).select('username email role isActive');

    console.log('Admin users found:', adminUsers);

    if (adminUsers.length === 0) {
      console.log('No admin users found in the database');
    } else {
      console.log('\nAdmin Users:');
      adminUsers.forEach(user => {
        console.log(`Username: ${user.username}`);
        console.log(`Email: ${user.email}`);
        console.log(`Role: ${user.role}`);
        console.log(`Active: ${user.isActive}`);
        console.log('-------------------');
      });
    }

    process.exit(0);
  } catch (error) {
    console.error('Error:', error);
    process.exit(1);
  }
}

checkAdmin(); 