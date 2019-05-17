const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

// Prepare the connection to the DB
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'login_test'
});

// Connecting to the DB
connection.connect(function (err) {
    if(err) {
        console.log(err);
    } else {
        console.log('Connected to the DB');
    }
});

// Middleware to verify the token
function verifyToken (req, res, next) {
    if(!req.headers.authorization) {
        res.status(401).json({
            message: 'Unauthorized request'
        });
    } else {
        let token = req.headers.authorization.split(' ')[1];
        jwt.verify(token, 'privateKey$', function(err, decoded) {
            if(err) {
                res.status(401).json({
                    message: 'Unauthorized request'
                });
            } else {
                res.locals.user = decoded.email;
                next();
            }
        });
    }
}

// Sign up
app.post('/api/signup', function (req, res) {
    let email = req.body.email;
    let password = req.body.password;
    let salt = bcrypt.genSaltSync(10);
    let hash = bcrypt.hashSync(password, salt);
    connection.query('INSERT INTO users VALUES (?, ?)', [email, hash], function(err) {
        if(err) {
            if(err.code == 'ER_DUP_ENTRY' || err.errno == 1062) {
                res.status(409).json({
                    message: "The email you've chosen has already been used, please choose another one"
                });
            } else {
                res.status(400).json({
                    message: err
                });
            }
        } else {
            res.status(201).json({
                message: 'User created'
            });
        }
    });
});

// Login
app.post('/api/login', function (req, res) {
    let email = req.body.email;
    let password = req.body.password;
    connection.query('SELECT pswrd FROM users WHERE email = ?', [email], function(err, result) {
        if(err) {
            res.status(400).json({
                message: err
            });
        } else {
            if(result.length == 1) {
                if(bcrypt.compareSync(password, result[0].pswrd)) {
                    const token = jwt.sign({ email: email }, 'privateKey$', { expiresIn: '1h' });
                    res.status(200).json({
                        message: "Authentication successfully completed",
                        token: token
                    });
                } else {
                    res.status(401).json({
                        message: "Wrong password"
                    });
                }
            } else {
                res.status(404).json({
                    message: 'User not found'
                });
            }
        }
    });
});

// Get all products
app.get('/api/products', function (req, res) {
    connection.query('SELECT * FROM products', function(err, result) {
        if(err) {
            res.status(400).json({
                message: err
            });
        } else {
            res.status(200).json(result);
        }
    });
});

// Get a single product
app.get('/api/products/:id', function (req, res) {
    let productId = req.params.id;
    connection.query('SELECT * FROM products WHERE id = ?', productId, function(err, result) {
        if(err) {
            res.status(400).json({
                message: err
            });
        } else {
            res.status(200).json(result[0]);
        }
    });
});

// Get cart items
app.get('/api/cart', verifyToken, function (req, res) {
    let user = res.locals.user;
    let sql = 'SELECT id, make, model, price FROM products INNER JOIN cart ON products.id = cart.product WHERE cart.user = ?';
    connection.query(sql, user, function(err, result) {
        if(err) {
            res.status(400).json({
                message: err
            });
        } else {
            res.status(200).json(result);
        }
    });
});

// Add item to cart
app.post('/api/cart', verifyToken, function (req, res) {
    let user = res.locals.user;
    let id = req.body.id;
    connection.query('INSERT INTO cart VALUES (?, ?)', [id, user], function(err, result) {
        if(err) {
            res.status(400).json({
                message: err
            });
        } else {
            res.status(200).json({
                message: 'The item has been added to the cart'
            });
        }
    });
});

// Delete item to cart
app.delete('/api/cart/:id', verifyToken, function (req, res) {
    let user = res.locals.user;
    let id = req.params.id;
    connection.query('DELETE FROM cart WHERE product = ? AND user = ?', [id, user], function(err, result) {
        if(err) {
            res.status(400).json({
                message: err
            });
        } else {
            res.status(200).json({
                message: result
            });
        }
    });
});

app.listen(3000, function () {
  console.log('App listening on port 3000!');
});

