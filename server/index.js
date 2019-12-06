require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const massive = require('massive');

const app = express();

app.use(express.json());

let { SERVER_PORT, CONNECTION_STRING, SESSION_SECRET } = process.env;

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  })
);

massive(CONNECTION_STRING).then(db => {
  app.set('db', db);
});

app.post('/auth/signup', async (req, res) => {
  const {email, password} = req.body;
  const db = req.app.get('db');
  const {session} = req;

  let user = await db.check_user_exists(email);
  user = user[0];
  if(user){
    return res.status(400).send('Email already exists')
  }
  let salt = bcrypt.genSaltSync(10);
  let hash = bcrypt.hashSync(password, salt);
  let createdUser = await db.create_user(email, hash);
  createdUser = createdUser[0];
  delete createdUser.user_password;
  session.user = createdUser;
  res.status(201).send(session.user);
})

app.post('/auth/login', async (req, res) => {
  const {email, password} = req.body;
  let db = req.app.get('db');
  const {session} = req;
  
  let user = await db.check_user_exists(email);
  user = user[0];
  if(!user){
    return res.status(400).send('Email not found')
  }
  let authenticated = bcrypt.compareSync(password, user.user_password);
  if(authenticated){
    delete user.user_password;
    session.user = user;
    res.status(202).send(session.user);
  } else {
    return res.status(401).send('Incorrect Password')
  }
})

app.post('/auth/logout', (req, res) => {
  req.session.destroy();
  res.sendStatus(200);
})

app.get('/auth/user', (req, res) => {
  if(req.session.user){
    res.status(200).send(req.session.user)
  } else {
    res.status(401).send('Please log-in')
  }
})

app.listen(SERVER_PORT, () => {
  console.log(`Listening on port: ${SERVER_PORT}`);
});
