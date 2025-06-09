const express = require('express');
const authRoutes = require('./routes/auth');
require('dotenv').config();

const app = express();
app.use(express.json());

app.use('/api/auth', authRoutes);

app.listen(process.env.PORT, () => {
  console.log(`Server running on http://localhost:${process.env.PORT}`);
});
