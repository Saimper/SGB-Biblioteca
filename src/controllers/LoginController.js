// Importar librerías necesarias
const bcrypt = require('bcrypt'); // Para hashear contraseñas

function index(req, res) {
  if (req.session.loggedin) {
    // Si el usuario está logueado, redirigir a la página de inicio
    res.redirect('/');
  } else {
    // Si no está logueado, renderizar la página de login
    res.render('login/index');
  }
}

function register(req, res) {
  // Renderizar la página de registro
  res.render('login/register');
}

function createUser(req, res) {
  const { name, email, password } = req.body;

  // Hash de la contraseña
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      console.error(err);
      return res.status(500).send("Error al crear el usuario.");
    }

    req.getConnection((err, conn) => {
      if (err) return res.status(500).send("Error en la conexión a la base de datos.");

      // Insertar nuevo usuario en la base de datos
      conn.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, email, hash], (err, result) => {
        if (err) {
          console.error(err);
          return res.status(500).send("Error al registrar el usuario.");
        }
        // Redirigir a la página de inicio o login tras un registro exitoso
        res.redirect('/login'); // Cambia esto según tu flujo
      });
    });
  });
}

function auth(req, res) {
  let email = req.body.email;
  let password = req.body.password;

  req.getConnection((err, conn) => {
    conn.query('SELECT * FROM users WHERE email = ?', [email], (err, rows) => {
      if (err) return res.status(500).send("Error en la consulta a la base de datos.");

      if (rows.length > 0) {
        const user = rows[0];
        // Comparar la contraseña
        bcrypt.compare(password, user.password, (err, result) => {
          if (result) {
            req.session.loggedin = true;
            req.session.name = user.name;
            res.redirect('/');
          } else {
            res.send('Contraseña incorrecta');
          }
        });
      } else {
        res.send('El usuario no existe');
      }
    });
  });
}

function logout(req, res) {
  if (req.session.loggedin) {
    req.session.destroy();
  }
  res.redirect('/');
}

module.exports = {
  index,
  register,
  createUser,
  auth,
  logout,
};
