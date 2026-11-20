
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const crypto = require("crypto");
const path = require("path");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  throw new Error("SESSION_SECRET must be at least 32 characters.");
}

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is missing.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost")
    ? false
    : { rejectUnauthorized: false }
});

const accounts = Array.from({ length: 7 }, (_, i) => {
  const number = i + 1;
  return {
    number,
    username: process.env[`ACCOUNT_${number}_USERNAME`],
    password: process.env[`ACCOUNT_${number}_PASSWORD`]
  };
}).filter(account => account.username && account.password);

if (accounts.length !== 7) {
  throw new Error("You must configure all 7 accounts.");
}

app.set("trust proxy", 1);

app.use(helmet({
  contentSecurityPolicy: false
}));

app.use(express.json({ limit: "10kb" }));

app.use(session({
  name: "baytna.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

function safeCompare(a, b) {
  const first = Buffer.from(String(a));
  const second = Buffer.from(String(b));

  return first.length === second.length &&
    crypto.timingSafeEqual(first, second);
}

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS accounts (
      number INTEGER PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS memories (
      id BIGSERIAL PRIMARY KEY,
      owner_account_id INTEGER NOT NULL REFERENCES accounts(number),
      image_url TEXT NOT NULL,
      caption TEXT DEFAULT '',
      visibility TEXT NOT NULL DEFAULT 'private'
        CHECK (visibility IN ('private', 'public')),
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id BIGSERIAL PRIMARY KEY,
      account_number INTEGER NOT NULL REFERENCES accounts(number),
      memory_id BIGINT REFERENCES memories(id) ON DELETE CASCADE,
      is_read BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS site_settings (
      id INTEGER PRIMARY KEY DEFAULT 1,
      site_name TEXT NOT NULL DEFAULT 'ذكريات بيتنا',
      logo TEXT DEFAULT '',
      theme_color TEXT DEFAULT '#8b684b'
    )
  `);

  await pool.query(`
    INSERT INTO site_settings (id)
    VALUES (1)
    ON CONFLICT (id) DO NOTHING
  `);

  const countResult = await pool.query(
    "SELECT COUNT(*)::int AS count FROM accounts"
  );

  if (countResult.rows[0].count === 0) {
    const bcrypt = require("bcryptjs");

    for (const account of accounts) {
      const hash = await bcrypt.hash(account.password, 12);

      await pool.query(
        `INSERT INTO accounts (number, username, password_hash)
         VALUES ($1, $2, $3)
         ON CONFLICT (number) DO NOTHING`,
        [account.number, account.username, hash]
      );
    }
  }

  console.log("Database initialized.");
}

app.post("/api/login", async (req, res, next) => {
  try {
    const { username, password } = req.body || {};

    if (!username || !password) {
      return res.status(400).json({
        error: "اكتب اسم المستخدم وكلمة المرور."
      });
    }

    const result = await pool.query(
      "SELECT number, username, password_hash FROM accounts WHERE username = $1",
      [username]
    );

    const account = result.rows[0];
    const bcrypt = require("bcryptjs");

    if (!account || !(await bcrypt.compare(password, account.password_hash))) {
      return res.status(401).json({
        error: "اسم المستخدم أو كلمة المرور غير صحيحة."
      });
    }

    req.session.regenerate(error => {
      if (error) return next(error);

      req.session.account = {
        number: account.number,
        username: account.username
      };

      req.session.save(error => {
        if (error) return next(error);

        res.json({
          success: true,
          account: req.session.account
        });
      });
    });
  } catch (error) {
    next(error);
  }
});

app.get("/api/me", (req, res) => {
  res.json({
    authenticated: Boolean(req.session.account),
    account: req.session.account || null
  });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(error => {
    if (error) {
      return res.status(500).json({
        error: "تعذر تسجيل الخروج."
      });
    }

    res.clearCookie("baytna.sid");
    res.json({ success: true });
  });
});

app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.use((error, req, res, next) => {
  console.error(error);
  res.status(500).json({
    error: "حدث خطأ في الخادم."
  });
});

initializeDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Baytna Memories is running on port ${PORT}`);
    });
  })
  .catch(error => {
    console.error("Database initialization failed:", error);
    process.exit(1);
  });
