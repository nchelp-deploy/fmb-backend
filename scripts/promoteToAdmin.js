const mongoose = require('mongoose');
require('dotenv').config();

// Import the User model
const User = require('../models/User');

async function promoteToAdmin(username) {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    // Find the user by username
    const user = await User.findOne({ username });

    if (!user) {
      console.error(`User with username "${username}" not found.`);
      process.exit(1);
    }

    // Update the user's role to admin
    user.role = 'admin';
    await user.save();

    console.log(`Successfully promoted ${username} to admin.`);
    process.exit(0);
  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  } finally {
    // Close the MongoDB connection
    await mongoose.connection.close();
  }
}

// Get the username from command line arguments
const username = process.argv[2];

if (!username) {
  console.error('Please provide a username as an argument.');
  console.error('Usage: node promoteToAdmin.js <username>');
  process.exit(1);
}

// Run the promotion
promoteToAdmin(username); 