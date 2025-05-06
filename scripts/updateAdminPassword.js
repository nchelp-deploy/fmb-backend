const mongoose = require('mongoose');
const User = require('../models/User');
const bcrypt = require('bcrypt');

async function updateAdminPassword() {
  try {
    // Connect to MongoDB
    await mongoose.connect('mongodb://localhost:27017/fmb', {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });

    // Find the admin user
    const admin = await User.findOne({ role: 'admin' });
    if (!admin) {
      console.log('Admin user not found. Please create an admin user first.');
      return;
    }

    // Generate a strong password
    const newPassword = 'FMB@dmin2025!Secure#';
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(newPassword, salt);

    // Update the admin password
    admin.passwordHash = passwordHash;
    admin.modifiedBy = {
      adminId: admin._id,
      modifiedAt: new Date(),
      reason: 'Password reset for security'
    };

    await admin.save();
    console.log('Admin password updated successfully:');
    console.log('Username: admin');
    console.log('New Password: FMB@dmin2025!Secure#');
    console.log('Email: admin@fundmebank.com');
    console.log('\nIMPORTANT: Please change this password after first login!');

    // Close the connection
    await mongoose.connection.close();
  } catch (error) {
    console.error('Error:', error);
    process.exit(1);
  }
}

// Run the function
updateAdminPassword(); 