
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
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  }
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
    return res.status(401).json({
      error: "سجّل الدخول أولًا."
    });
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

// إنشاء الجداول
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

// تسجيل الدخول
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
       FROM accounts
       WHERE username = $1`,
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

// معلومات الحساب
app.get("/api/me", (req, res) => {
  res.json({
    authenticated: Boolean(req.session.account),
    account: req.session.account || null
  });
});

// حفظ صورة خاصة
app.post(
  "/api/memories/private",
  requireLogin,
  upload.single("photo"),
  async (req, res, next) => {
    let uploadedPath = null;

    try {
      if (!req.file) {
        return res.status(400).json({
          error: "اختر صورة أولًا."
        });
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

      uploadedPath = storagePath;

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
      if (uploadedPath) {
        await supabase.storage
          .from(BUCKET)
          .remove([uploadedPath])
          .catch(() => {});
      }

      next(error);
    }
  }
);

// عرض الصور الخاصة
app.get("/api/memories/private", requireLogin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id, storage_path, caption, created_at
       FROM memories
       WHERE owner_account_id = $1
         AND visibility = 'private'
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

// نشر صورة خاصة
app.post("/api/memories/:id/publish", requireLogin, async (req, res, next) => {
  const client = await pool.connect();

  try {
    const caption = String(req.body.caption || "").trim().slice(0, 500);
    const accountNumber = req.session.account.number;

    await client.query("BEGIN");

    const result = await client.query(
      `UPDATE memories
       SET visibility = 'public',
           caption = CASE
             WHEN $1 = '' THEN caption
             ELSE $1
           END
       WHERE id = $2
         AND owner_account_id = $3
         AND visibility = 'private'
       RETURNING id, caption, created_at`,
      [caption, req.params.id, accountNumber]
    );

    if (!result.rows.length) {
      await client.query("ROLLBACK");

      return res.status(404).json({
        error: "الصورة غير موجودة أو سبق نشرها."
      });
    }

    const memoryId = result.rows[0].id;

    // إشعار الحسابات الأخرى
    await client.query(
      `INSERT INTO notifications (account_number, memory_id)
       SELECT number, $1
       FROM accounts
       WHERE number <> $2`,
      [memoryId, accountNumber]
    );

    await client.query("COMMIT");

    res.json({
      success: true,
      memory: result.rows[0]
    });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    next(error);
  } finally {
    client.release();
  }
});

// عرض الذكريات العامة والبحث
app.get("/api/memories/public", requireLogin, async (req, res, next) => {
  try {
    const search = String(req.query.q || "").trim().slice(0, 80);

    let result;

    if (/^\d{4}$/.test(search)) {
      result = await pool.query(
        `SELECT
           m.id,
           m.storage_path,
           m.caption,
           m.created_at,
           a.username
         FROM memories m
         JOIN accounts a ON a.number = m.owner_account_id
         WHERE m.visibility = 'public'
           AND (
             m.caption ILIKE $1
             OR EXTRACT(YEAR FROM m.created_at)::int = $2
             OR m.id::text = $3
           )
         ORDER BY m.created_at DESC
         LIMIT 100`,
        [`%${search}%`, Number(search), search]
      );
    } else if (search) {
      result = await pool.query(
        `SELECT
           m.id,
           m.storage_path,
           m.caption,
           m.created_at,
           a.username
         FROM memories m
         JOIN accounts a ON a.number = m.owner_account_id
         WHERE m.visibility = 'public'
           AND (
             m.caption ILIKE $1
             OR a.username ILIKE $1
             OR m.id::text = $2
           )
         ORDER BY m.created_at DESC
         LIMIT 100`,
        [`%${search}%`, search]
      );
    } else {
      result = await pool.query(
        `SELECT
           m.id,
           m.storage_path,
           m.caption,
           m.created_at,
           a.username
         FROM memories m
         JOIN accounts a ON a.number = m.owner_account_id
         WHERE m.visibility = 'public'
         ORDER BY m.created_at DESC
         LIMIT 100`
      );
    }

    const memories = [];

    for (const memory of result.rows) {
      const { data, error } = await supabase.storage
        .from(BUCKET)
        .createSignedUrl(memory.storage_path, 3600);

      if (error) throw error;

      memories.push({
        id: memory.id,
        username: memory.username,
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

// جلب إشعارات الحساب الحالي
app.get("/api/notifications", requireLogin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT
         n.id,
         n.is_read,
         n.created_at,
         m.id AS memory_id,
         m.caption,
         a.username AS sender_username
       FROM notifications n
       LEFT JOIN memories m ON m.id = n.memory_id
       LEFT JOIN accounts a ON a.number = m.owner_account_id
       WHERE n.account_number = $1
       ORDER BY n.created_at DESC
       LIMIT 100`,
      [req.session.account.number]
    );

    res.json({
      notifications: result.rows,
      unread_count: result.rows.filter(item => !item.is_read).length
    });
  } catch (error) {
    next(error);
  }
});

// تحديد إشعار واحد كمقروء
app.post("/api/notifications/:id/read", requireLogin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `UPDATE notifications
       SET is_read = TRUE
       WHERE id = $1
         AND account_number = $2
       RETURNING id`,
      [req.params.id, req.session.account.number]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "الإشعار غير موجود."
      });
    }

    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

// تحديد جميع الإشعارات كمقروءة
app.post("/api/notifications/read-all", requireLogin, async (req, res, next) => {
  try {
    await pool.query(
      `UPDATE notifications
       SET is_read = TRUE
       WHERE account_number = $1`,
      [req.session.account.number]
    );

    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

// حذف صورة يملكها الحساب
app.delete("/api/memories/:id", requireLogin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id, storage_path
       FROM memories
       WHERE id = $1
         AND owner_account_id = $2`,
      [req.params.id, req.session.account.number]
    );

    const memory = result.rows[0];

    if (!memory) {
      return res.status(404).json({
        error: "الصورة غير موجودة."
      });
    }

    if (memory.storage_path) {
      const { error } = await supabase.storage
        .from(BUCKET)
        .remove([memory.storage_path]);

      if (error) throw error;
    }

    await pool.query(
      `DELETE FROM memories
       WHERE id = $1 AND owner_account_id = $2`,
      [memory.id, req.session.account.number]
    );

    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

// تسجيل الخروج
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

// الملفات
app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// معالجة الأخطاء
app.use((error, req, res, next) => {
  console.error("========== SERVER ERROR ==========");
  console.error("Name:", error.name);
  console.error("Message:", error.message);
  console.error("Status:", error.statusCode || error.status || "unknown");
  console.error("Code:", error.code || "unknown");
  console.error("==================================");

  const status = error.statusCode || error.status || 500;

  res.status(status).json({
    error: status < 500
      ? error.message
      : "حدث خطأ في الخادم. حاول مرة أخرى."
  });
});

// تشغيل الموقع
initializeDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Baytna Memories is running on port ${PORT}`);
    });
  })
  .catch(error => {
    console.error("Database initialization failed:", error.message);
    process.exit(1);
  });
