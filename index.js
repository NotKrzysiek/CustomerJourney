require("dotenv").config({ path: "config/.env" });

const express = require("express");
const session = require("express-session");

const axios = require("axios");
const axiosRetry = require("axios-retry").default;

// https://github.com/softonic/axios-retry/issues/72#issuecomment-699785860
// Honor Retry-After header
axiosRetry(axios, {
  retries: 3,
  retryCondition(e) {
    return (
      axiosRetry.isNetworkOrIdempotentRequestError(e) ||
      e.response.status === 429
    );
  },
  retryDelay: (retryCount, error) => {
    if (error.response) {
      return error.response.headers["retry-after"];
    }
    return axiosRetry.exponentialDelay(retryCount, error);
  },
});

const AUTH_AUTHORIZE_URL =
  process.env.AUTH_AUTHORIZE_URL || `https://webexapis.com/v1/authorize`;
const AUTH_ACCESS_TOKEN_URL =
  process.env.AUTH_ACCESS_TOKEN_URL || `https://webexapis.com/v1/access_token`;

// client id/secret pair generated in Developer Portal
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;

// URL users will visit after successfully authenticating
const REDIRECT_URI = process.env.REDIRECT_URI || "http://localhost:4242";

// permissions users must grant your app, separated by spaces
const SCOPE = process.env.SCOPE || "cjp:config_read cjp:config_write";

const app = express();

// TODO(you): replace in-memory session store
app.use(
  session({
    secret: process.env.SESSION_SECRET || "development",
    resave: false,
    saveUninitialized: false,
  })
);

//
// OAuth2 landing/login page
//

// pre-login landing/redirect_uri page
app.get("/", async (req, res) => {
  // case 1: authentic session (session has token) => redirect to /home
  // case 2: new session (no token, no `code`) => serve landing page
  // case 3: authenticating new session (no token, has `code`) => exchange code for token, then follow case 1

  const sessionToken = await getSessionToken(req);

  // case 2
  if (!sessionToken && !("code" in req.query)) {
    res.send(buildLoginPage());
    return;
  }

  // case 3
  if (!sessionToken) {
    try {
      const token = await exchangeCodeForToken(req.query.code);
      await setSessionToken(req, token);
    } catch (e) {
      console.error(e);
      res
        .status(503)
        .send(
          "Unable to contact authentication server, please try again later."
        );
    }
  }

  // case 1
  res.redirect("/home");
});

function buildLoginPage() {
  return `<html>
        <head>
            <title>My Integration</title>
        </head>
        <body style="padding: 20%">
            <h1>Welcome!</h1>
            <a href="${buildLoginUrl("/")}">Login</a>
        </body>
        </html>
    `;
}

// creates /v1/authorize URL to redirect to with optional `state=` param.
function buildLoginUrl(state) {
  const baseUrlRedirectEncoded = encodeURI(AUTH_AUTHORIZE_URL);
  const clientIdEncoded = encodeURIComponent(CLIENT_ID);
  const redirectUriEncoded = encodeURIComponent(REDIRECT_URI);
  const scopeEncoded = encodeURIComponent(SCOPE);

  // optional: include something useful in state, like page to redirect to
  const stateEncoded = encodeURIComponent(state);

  return `${baseUrlRedirectEncoded}?client_id=${clientIdEncoded}&response_type=code&redirect_uri=${redirectUriEncoded}&scope=${scopeEncoded}&state=${stateEncoded}`;
}

async function exchangeCodeForToken(code) {
  const params = new URLSearchParams();
  params.append("grant_type", "authorization_code");
  params.append("client_id", CLIENT_ID);
  params.append("client_secret", CLIENT_SECRET);
  params.append("code", code);
  params.append("redirect_uri", REDIRECT_URI);

  const response = await axios.post(AUTH_ACCESS_TOKEN_URL, params, {
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
  });
  const token = response.data;

  // Translate `expires_in` duration to approximate timestamps ASAP
  const now = Date.now();
  token.expiresAt = now + token.expires_in * 1000; // usually a few hours
  token.refreshExpiresAt = now + token.refresh_token_expires_in * 1000; // usually a few days

  return token;
}

async function getSessionToken(req) {
  // `async` just in case your code writes to a shared cache like redis
  return req.session.token;
}

async function setSessionToken(req, token) {
  // `async` just in case your code writes to a shared cache like redis
  req.session.token = token;
}

// middleware to guarantee route will have session
async function requireAuthenticationMiddleware(req, res, next) {
  const sessionToken = await getSessionToken(req);
  if (!sessionToken) {
    res.redirect("/");
    return;
  }
  return next();
}

//
// Example protected route
//

app.use("/home", requireAuthenticationMiddleware, async (req, res) => {
  const { expiresAt } = await getSessionToken(req);

  res.send(`<html>
        <head>
            <title>My Integration</title>
        </head>
        <body style="padding: 20%">
            <h1>Welcome!</h1>
            Your token will expire at ${new Date(expiresAt).toISOString()}.
        </body>
        </html>
    `);
});

const port = process.env.PORT || 10000;
app.listen(port, "0.0.0.0", () => {
  console.log(`Running on port ${port}`);
});