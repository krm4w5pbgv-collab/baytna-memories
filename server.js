
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const crypto = require("crypto");
const path = require("path");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 3000;
const BUCKET = "baytna-private-photos";

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  throw new Error("SESSION_SECRET must be at least 32 characters.");
}
if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is missing.");
}
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SECRET_KEY) {
  throw new Error("Supabase environment variables are missing.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost")
    ? false
    : { rejectUnauthorized: false }
});

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY,
  { auth: { persistSession: false, autoRefreshToken: false } }
);

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

app.use(helmet({ contentSecurityPolicy: false }));
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

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, callback) => {
    const allowed = [
      "image/jpeg",
      "image/png",
      "image/webp",
      "image/gif",
      "image/heic",
      "image/heif"
    ];

    if (!allowed.includes(file.mimetype)) {
      return callback(new Error("نوع الصورة غير مدعوم."));
    }
    callback(null, true);
  }
});

function requireLogin(req, res, next) {
  if (!req.session.account) {
    return res.status(401).json({ error: "سجّل الدخول أولًا." });
  }
  next();
}

function extensionFor(mime) {
  const extensions = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
    "image/gif": "gif",
    "image/heic": "heic",
    "image/heif": "heif"
  };
  return extensions[mime];
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
      image_url TEXT,
      storage_path TEXT,
      caption TEXT DEFAULT '',
      visibility TEXT NOT NULL DEFAULT 'private'
        CHECK (visibility IN ('private', 'public')),
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE memories
    ADD COLUMN IF NOT EXISTS storage_path TEXT
  `);

  await pool.query(`
    ALTER TABLE memories
    ALTER COLUMN image_url DROP NOT NULL
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
      `SELECT number, username, password_hash
       FROM accounts WHERE username = $1`,
      [username]
    );

    const account = result.rows[0];

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
        res.json({ success: true, account: req.session.account });
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

app.post(
  "/api/memories/private",
  requireLogin,
  upload.single("photo"),
  async (req, res, next) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: "اختر صورة أولًا." });
      }

      const extension = extensionFor(req.file.mimetype);
      const accountNumber = req.session.account.number;
      const storagePath =
        `${accountNumber}/${crypto.randomUUID()}.${extension}`;

      const { error: uploadError } = await supabase.storage
        .from(BUCKET)
        .upload(storagePath, req.file.buffer, {
          contentType: req.file.mimetype,
          upsert: false
        });

      if (uploadError) throw uploadError;

      const caption = String(req.body.caption || "").slice(0, 500);

      const result = await pool.query(
        `INSERT INTO memories
         (owner_account_id, storage_path, caption, visibility)
         VALUES ($1, $2, $3, 'private')
         RETURNING id, caption, created_at`,
        [accountNumber, storagePath, caption]
      );

      res.status(201).json({
        success: true,
        memory: result.rows[0]
      });
    } catch (error) {
      next(error);
    }
  }
);

app.get("/api/memories/private", requireLogin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id, storage_path, caption, created_at
       FROM memories
       WHERE owner_account_id = $1 AND visibility = 'private'
       ORDER BY created_at DESC`,
      [req.session.account.number]
    );

    const memories = [];

    for (const memory of result.rows) {
      const { data, error } = await supabase.storage
        .from(BUCKET)
        .createSignedUrl(memory.storage_path, 600);

      if (error) throw error;

      memories.push({
        id: memory.id,
        caption: memory.caption,
        created_at: memory.created_at,
        image_url: data.signedUrl
      });
    }

    res.json({ memories });
  } catch (error) {
    next(error);
  }
});

app.delete("/api/memories/:id", requireLogin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id, storage_path
       FROM memories
       WHERE id = $1 AND owner_account_id = $2`,
      [req.params.id, req.session.account.number]
    );

    const memory = result.rows[0];

    if (!memory) {
      return res.status(404).json({ error: "الصورة غير موجودة." });
    }

    if (memory.storage_path) {
      const { error } = await supabase.storage
        .from(BUCKET)
        .remove([memory.storage_path]);

      if (error) throw error;
    }

    await pool.query(
      "DELETE FROM memories WHERE id = $1 AND owner_account_id = $2",
      [memory.id, req.session.account.number]
    );

    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(error => {
    if (error) {
      return res.status(500).json({ error: "تعذر تسجيل الخروج." });
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
  console.error(error.message || error);
  res.status(500).json({
    error: "حدث خطأ في الخادم. تحقق من إعدادات التخزين."
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
