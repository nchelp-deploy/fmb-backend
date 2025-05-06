require('dotenv').config();
const mongoose = require('mongoose');
const User = require('../models/User');

async function checkUsers() {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log('Connected to MongoDB');

    const users = await User.find({}).select('username email role isActive');

    console.log('Users found:', users.length);

    if (users.length === 0) {
      console.log('No users found in the database');
    } else {
      console.log('\nUsers:');
      users.forEach(user => {
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

checkUsers(); 