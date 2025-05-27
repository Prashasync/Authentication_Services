# authentication-service

This is the backend service for the **Prasha** project. It is built using **Node.js** and designed to be run in both development and production environments.

---

## 🚀 Requirements

Before you begin, make sure you have the following installed:

- [Node.js](https://nodejs.org/) (version 14.x or above recommended)
- [npm](https://www.npmjs.com/) (comes with Node.js)
- [nodemon](https://www.npmjs.com/package/nodemon) (for development - can be installed globally)

---

## 📦 Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/Prashasync/authentication-service.git
   cd authentication-service

   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

## 🔧 Scripts

- **Start the app (Production mode)**

  ```bash
  npm start
  ```

  Starts the app using `node app.js`

- **Start the app in development mode**
  ```bash
  npm run dev
  ```
  Starts the app with `nodemon` and `--inspect` flag for debugging and hot reload

---

## 🛠 Environment Variables

Create a `.env` file in the root directory to manage configuration:

```env
# Environment
NODE_ENV=
PORT=7001

# DB
DB_USERNAME=
DB_PASSWORD=
DB_NAME=
DB_HOST=

# Twilio
TWILIO_ACCOUNT_SID=
TWILIO_AUTH_TOKEN=
TWILIO_PHONE=

# JWT
JWT_SECRET=

# Email OTP settings
EMAIL_FROM=
EMAIL_PASSWORD=

```

Use a package like `dotenv` to load these variables in `app.js`:

```js
require("dotenv").config();
```

---

## 💡 Debugging

If using `npm run dev`, it runs the app with:

```bash
nodemon app.js --inspect
```

This allows debugging using Chrome DevTools or other supported debuggers.

---

Changed