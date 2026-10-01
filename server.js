const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { PrismaClient } = require('@prisma/client');

const app = express();
const prisma = new PrismaClient();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'nagibatori_secret_key';

// Middleware для перевірки авторизації
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Доступ заборонено. Необхідна авторизація.' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(403).json({ error: 'Недійсний токен.' });
  }
};

// Middleware для перевірки прав Модератора / Адміна
const requireModerator = (req, res, next) => {
  if (req.user.role !== 'MODERATOR' && req.user.role !== 'ADMIN') {
    return res.status(403).json({ error: 'Недостатньо прав! Потрібні права модератора.' });
  }
  next();
};

// ------------------- АВТОРИЗАЦІЯ -------------------

// Реєстрація користувача
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  const passwordHash = await bcrypt.hash(password, 10);

  try {
    const user = await prisma.user.create({
      data: { username, email, passwordHash, role: 'USER' }
    });
    res.status(201).json({ message: 'Користувача успішно зареєстровано', userId: user.id });
  } catch (error) {
    res.status(400).json({ error: 'Користувач або Email вже існує.' });
  }
});

// Вхід
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: 'Невірний email або пароль.' });
  }

  const token = jwt.sign({ id: user.id, role: user.role, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
});

// ------------------- УПРАВЛІННЯ ПАПКАМИ -------------------

// Створити папку (Фото, Відео, Музика)
app.post('/api/folders', authenticate, async (req, res) => {
  const { name, type, genre } = req.body; // type: 'IMAGE', 'VIDEO', 'AUDIO'
  const folder = await prisma.folder.create({
    data: { name, type, genre, userId: req.user.id }
  });
  res.status(201).json(folder);
});

// ------------------- ПАНЕЛЬ МОДЕРАТОРА (Видалення будь-якого контенту) -------------------

// Модераторське видалення будь-якого медіафайлу без дозволу автора
app.delete('/api/admin/media/:id', authenticate, requireModerator, async (req, res) => {
  const { id } = req.params;
  try {
    await prisma.mediaItem.delete({ where: { id } });
    res.json({ message: 'Медіафайл примусово видалено модератором.' });
  } catch (err) {
    res.status(404).json({ error: 'Файл не знайдено.' });
  }
});

// Модераторське видалення будь-якої папки без дозволу автора
app.delete('/api/admin/folder/:id', authenticate, requireModerator, async (req, res) => {
  const { id } = req.params;
  try {
    await prisma.folder.delete({ where: { id } });
    res.json({ message: 'Папку та весь її вміст примусово видалено модератором.' });
  } catch (err) {
    res.status(404).json({ error: 'Папку не знайдено.' });
  }
});

// Модераторська зміна ролі користувача (надати/забрати модератора)
app.patch('/api/admin/user/:id/role', authenticate, requireModerator, async (req, res) => {
  const { id } = req.params;
  const { role } = req.body; // 'USER', 'MODERATOR', 'ADMIN'
  
  const updatedUser = await prisma.user.update({
    where: { id },
    data: { role }
  });
  res.json({ message: `Роль користувача змінено на ${role}`, user: updatedUser });
});

app.listen(5000, () => console.log('Сервер НагібаториUA запущено на порту 5000'));
