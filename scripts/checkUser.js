require('dotenv').config();
const mongoose = require('mongoose');
const User = require('../models/User');

async function checkUser(username) {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });

    const user = await User.findOne({ username });
    
    if (!user) {
      console.log('User not found in database');
      return;
    }

    console.log('User found:');
    console.log('Username:', user.username);
    console.log('Email:', user.email);
    console.log('Role:', user.role);
    console.log('Is Active:', user.isActive);
    console.log('Account Balance:', user.accountBalance);
    console.log('Last Login:', user.lastLogin);
    console.log('Created At:', user.createdAt);
    
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await mongoose.connection.close();
  }
}

// Get username from command line argument
const username = process.argv[2];
if (!username) {
  console.log('Please provide a username as an argument');
  process.exit(1);
}

checkUser(username); 