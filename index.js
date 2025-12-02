const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const axios = require('axios');
const cors = require('cors');
const { expressjwt: jwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN;
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE;
const AUTH0_M2M_CLIENT_ID = process.env.AUTH0_M2M_CLIENT_ID;
const AUTH0_M2M_CLIENT_SECRET = process.env.AUTH0_M2M_CLIENT_SECRET;
const AUTH0_REGULAR_CLIENT_ID = process.env.AUTH0_REGULAR_CLIENT_ID;
const AUTH0_DEFAULT_CONNECTION = process.env.AUTH0_DEFAULT_CONNECTION;

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: 'https://' + AUTH0_DOMAIN + '/.well-known/jwks.json'
  }),
  audience: AUTH0_AUDIENCE,
  issuer: 'https://' + AUTH0_DOMAIN + '/',
  algorithms: ['RS256']
});

// Видаємо фронт
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// LOGIN: password grant → Auth0
app.post('/api/login', async (req, res) => {
  const login = req.body.login;
  const password = req.body.password;

  try {
    const tokenResponse = await axios.post(
      'https://' + AUTH0_DOMAIN + '/oauth/token',
      new URLSearchParams({
        grant_type: 'password',
        username: login,
        password: password,
        client_id: AUTH0_REGULAR_CLIENT_ID,
        audience: AUTH0_AUDIENCE,
        scope: 'offline_access'
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    const access_token = tokenResponse.data.access_token;
    const refresh_token = tokenResponse.data.refresh_token;
    const expires_in = tokenResponse.data.expires_in;
    const token_type = tokenResponse.data.token_type;

    return res.json({
      access_token: access_token,
      refresh_token: refresh_token,
      expires_in: expires_in,
      token_type: token_type
    });
  } catch (err) {
    console.error('Auth0 login error:', err.response && err.response.data ? err.response.data : err.message);
    return res.status(401).json({ error: 'Invalid credentials' });
  }
});

// HELP: отримати M2M токен для Management API
async function getManagementToken() {
  const resp = await axios.post(
    'https://' + AUTH0_DOMAIN + '/oauth/token',
    new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: AUTH0_M2M_CLIENT_ID,
      client_secret: AUTH0_M2M_CLIENT_SECRET,
      audience: AUTH0_AUDIENCE
    }),
    {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    }
  );

  return resp.data.access_token;
}

// REGISTER: створити юзера через Management API
app.post('/api/register', async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  try {
    const mgmtToken = await getManagementToken();

    const createResp = await axios.post(
      'https://' + AUTH0_DOMAIN + '/api/v2/users',
      {
        email: email,
        password: password,
        connection: AUTH0_DEFAULT_CONNECTION
      },
      {
        headers: {
          'Authorization': 'Bearer ' + mgmtToken,
          'Content-Type': 'application/json'
        }
      }
    );

    return res.json({
      message: 'User created',
      user: createResp.data
    });
  } catch (err) {
    console.error('Auth0 register error:', err.response && err.response.data ? err.response.data : err.message);
    return res.status(400).json({ error: 'Cannot create user' });
  }
});

// REFRESH: оновити токен через refresh_token grant
app.post('/api/refresh', async (req, res) => {
  const refresh_token = req.body.refresh_token;

  if (!refresh_token) {
    return res.status(400).json({ error: 'Missing refresh_token' });
  }

  try {
    const resp = await axios.post(
      'https://' + AUTH0_DOMAIN + '/oauth/token',
      new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: AUTH0_REGULAR_CLIENT_ID,
        refresh_token: refresh_token
      }),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      }
    );

    const access_token = resp.data.access_token;
    const expires_in = resp.data.expires_in;
    const token_type = resp.data.token_type;

    return res.json({
      access_token: access_token,
      expires_in: expires_in,
      token_type: token_type
    });
  } catch (err) {
    console.error('Auth0 refresh error:', err.response && err.response.data ? err.response.data : err.message);
    return res.status(400).json({ error: 'Cannot refresh token' });
  }
});

// Захищений маршрут: повертає інформацію про юзера з токена
app.get('/api/me', checkJwt, (req, res) => {
  res.json({
    sub: req.auth.sub,
    scope: req.auth.scope,
    message: 'Protected data from /api/me'
  });
});

app.listen(port, () => {
  console.log('App listening on port ' + port);
});
