const axios = require('axios');

async function listUsers() {
  try {
    // First, try to login as admin
    const loginResponse = await axios.post('http://localhost:4000/api/auth/login', {
      username: 'admin',
      password: 'admin123'
    });

    console.log('Login successful. Getting user list...');

    // Get all users
    const usersResponse = await axios.get('http://localhost:4000/api/admin/users', {
      headers: {
        'Authorization': `Bearer ${loginResponse.data.tokens.accessToken}`
      }
    });

    console.log('\nAll users in the system:');
    usersResponse.data.users.forEach((user, index) => {
      console.log(`\nUser #${index + 1}:`);
      console.log(`Username: ${user.username}`);
      console.log(`Email: ${user.email}`);
      console.log(`Role: ${user.role}`);
      console.log(`Created: ${user.createdAt}`);
      console.log(`Last Login: ${user.lastLogin}`);
      console.log(`Active: ${user.isActive}`);
    });
  } catch (error) {
    if (error.response?.status === 401) {
      console.error('Authentication failed. Please check your credentials.');
    } else {
      console.error('Error:', error.response?.data || error.message);
    }
  }
}

listUsers(); 