const express = require('express');
const fs = require('fs').promises;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;

const USERS_FILE = 'usuarios.json';
const SECRET = 'clave_secreta';

app.use(express.json());

async function leerTareas() {
  const data = await fs.readFile('tareas.json', 'utf8');
  return JSON.parse(data);
}

async function guardarTareas(tareas) {
  await fs.writeFile('tareas.json', JSON.stringify(tareas, null, 2));
}

async function leerUsuarios() {
  try {
    const data = await fs.readFile(USERS_FILE, 'utf8');
    return JSON.parse(data);
  } catch {
    return [];
  }
}

async function guardarUsuarios(usuarios) {
  await fs.writeFile(USERS_FILE, JSON.stringify(usuarios, null, 2));
}

function autenticarToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ mensaje: 'Token requerido' });
  }

  jwt.verify(token, SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ mensaje: 'Token inválido' });
    }

    req.user = user;
    next();
  });
}

app.post('/register', async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const usuarios = await leerUsuarios();
    const existe = usuarios.find(u => u.email === email);

    if (existe) {
      return res.status(400).json({ mensaje: 'Usuario ya existe' });
    }

    const hash = await bcrypt.hash(password, 10);

    const nuevoUsuario = {
      id: Date.now(),
      email,
      password: hash
    };

    usuarios.push(nuevoUsuario);
    await guardarUsuarios(usuarios);

    res.json({ mensaje: 'Usuario registrado correctamente' });
  } catch (error) {
    next(error);
  }
});

app.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const usuarios = await leerUsuarios();
    const usuario = usuarios.find(u => u.email === email);

    if (!usuario) {
      return res.status(400).json({ mensaje: 'Usuario no encontrado' });
    }

    const valido = await bcrypt.compare(password, usuario.password);
    if (!valido) {
      return res.status(400).json({ mensaje: 'Contraseña incorrecta' });
    }

    const token = jwt.sign(
      { id: usuario.id },
      SECRET,
      { expiresIn: '1h' }
    );

    res.json({ token });
  } catch (error) {
    next(error);
  }
});

app.get('/tareas', autenticarToken, async (req, res, next) => {
  try {
    const tareas = await leerTareas();
    res.json(tareas);
  } catch (error) {
    next(error);
  }
});

app.post('/tareas', autenticarToken, async (req, res, next) => {
  try {
    const { titulo, descripcion } = req.body;

    const tareas = await leerTareas();

    const nuevaTarea = {
      id: Date.now(),
      titulo,
      descripcion
    };

    tareas.push(nuevaTarea);
    await guardarTareas(tareas);

    res.status(201).json(nuevaTarea);
  } catch (error) {
    next(error);
  }
});

app.put('/tareas/:id', autenticarToken, async (req, res, next) => {
  try {
    const id = parseInt(req.params.id);
    const { titulo, descripcion } = req.body;

    const tareas = await leerTareas();
    const tarea = tareas.find(t => t.id === id);

    if (!tarea) {
      return res.status(404).json({ mensaje: 'Tarea no encontrada' });
    }

    tarea.titulo = titulo;
    tarea.descripcion = descripcion;

    await guardarTareas(tareas);
    res.json(tarea);
  } catch (error) {
    next(error);
  }
});

app.delete('/tareas/:id', autenticarToken, async (req, res, next) => {
  try {
    const id = parseInt(req.params.id);

    const tareas = await leerTareas();
    const nuevasTareas = tareas.filter(t => t.id !== id);

    await guardarTareas(nuevasTareas);
    res.json({ mensaje: 'Tarea eliminada correctamente' });
  } catch (error) {
    next(error);
  }
});

app.use((req, res) => {
  res.status(404).json({ mensaje: 'Ruta no encontrada' });
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ mensaje: 'Ocurrió un error en el servidor' });
});

app.listen(PORT, () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
