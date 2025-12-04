require('dotenv').config(); // Добавлено для чтения переменных окружения из файла .env
const express = require('express');
const { Pool } = require('pg'); // Клиент для PostgreSQL
const bcrypt = require('bcrypt'); // Библиотека для хеширования паролей
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Конфигурация подключения к базе данных PostgreSQL
// Использует переменную окружения DATABASE_URL или локальные настройки по умолчанию
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('render.com') 
    ? { rejectUnauthorized: false } // Настройки SSL для облачного хостинга (Render)
    : false
});

app.use(express.json()); // Middleware для парсинга JSON в теле запросов
app.use(express.static('public')); // Раздача статических файлов из папки public

// Инициализация БД: Создание таблицы пользователей при запуске сервера, если она не существует
pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    points INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`).catch(err => console.error('Error creating table:', err));

// --- API ENDPOINTS ---

// Регистрация нового пользователя
// Принимает email, username, password. Хеширует пароль и сохраняет в БД.
app.post('/api/register', async (req, res) => {
  try {
    const { email, username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const result = await pool.query(
      'INSERT INTO users (email, username, password) VALUES ($1, $2, $3) RETURNING id, email, username, points',
      [email, username, hashedPassword]
    );
    
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

// Авторизация пользователя
// Проверяет наличие пользователя и совпадение хеша пароля.
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Неверный логин или пароль' });
    }
    
    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(401).json({ success: false, message: 'Неверный логин или пароль' });
    }
    
    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        points: user.points
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Начисление баллов пользователю
// Обновляет поле points в базе данных для указанного ID
app.post('/api/add-points', async (req, res) => {
  try {
    const { userId, points } = req.body;
    
    const result = await pool.query(
      'UPDATE users SET points = points + $1 WHERE id = $2 RETURNING id, username, points',
      [points, userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }
    
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Получение информации о пользователе по ID
app.get('/api/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    
    const result = await pool.query(
      'SELECT id, email, username, points FROM users WHERE id = $1',
      [userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Пользователь не найден' });
    }
    
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Запуск сервера
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});