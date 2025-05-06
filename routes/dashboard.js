const express = require('express');
const router = express.Router();
const User = require('../models/User');
const authMiddleware = require('../middleware/authMiddleware');

// Get dashboard content
router.get('/', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ content: user.content });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Add content to dashboard
router.post('/content', authMiddleware, async (req, res) => {
  try {
    const { content } = req.body;
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    user.content.push(content);
    await user.save();
    res.json({ message: 'Content added successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Delete content from dashboard
router.delete('/content/:index', authMiddleware, async (req, res) => {
  try {
    const { index } = req.params;
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    user.content.splice(index, 1);
    await user.save();
    res.json({ message: 'Content deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router; 