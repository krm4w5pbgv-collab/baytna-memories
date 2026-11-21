
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const crypto = require("crypto");
const path = require("path");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const { createClient } = require("@supabase/supabase-js");
const QRCode = require("qrcode");

const app = express();
const PORT = process.env.PORT || 3000;
const BUCKET = "baytna-private-photos";
const AVATAR_BUCKET = "baytna-private-photos";
const OWNER_NUMBER = 7;
const OWNER_QR_TOKEN = process.env.OWNER_QR_TOKEN;

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)
  throw new Error("SESSION_SECRET must be at least 32 characters.");
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is missing.");
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SECRET_KEY)
  throw new Error("Supabase environment variables are missing.");
if (!OWNER_QR_TOKEN || OWNER_QR_TOKEN.length < 32)
  throw new Error("OWNER_QR_TOKEN must be at least 32 characters.");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost")
    ? false : { rejectUnauthorized: false }
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
}).filter(a => a.username && a.password);

if (accounts.length !== 7)
  throw new Error("You must configure all 7 accounts.");

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
      "image/jpeg", "image/png", "image/webp",
      "image/gif", "image/heic", "image/heif"
    ];
    if (!allowed.includes(file.mimetype))
      return callback(new Error("نوع الصورة غير مدعوم."));
    callback(null, true);
  }
});

function requireLogin(req, res, next) {
  if (!req.session.account)
    return res.status(401).json({ error: "سجّل الدخول أولًا." });
  next();
}

function requireSettingsUnlocked(req, res, next) {
  const unlockedAt = Number(req.session.settingsUnlockedAt || 0);

  if (!unlockedAt || Date.now() - unlockedAt > 10 * 60 * 1000) {
    delete req.session.settingsUnlockedAt;
    return res.status(403).json({
      error: "افتح إعدادات الحساب بكلمة مرور الإعدادات أولًا."
    });
  }
  next();
}

function requireOwnerUnlocked(req, res, next) {
  if (!req.session.account || req.session.account.number !== OWNER_NUMBER)
    return res.status(403).json({ error: "غير مصرح لك." });

  const unlockedAt = Number(req.session.ownerUnlockedAt || 0);

  if (!unlockedAt || Date.now() - unlockedAt > 10 * 60 * 1000) {
    delete req.session.ownerUnlockedAt;
    return res.status(403).json({
      error: "امسح رمز QR لفتح إعدادات الأونر."
    });
  }
  next();
}

// ربط نظام إعدادات الأونر الجديد
const ownerAdminRouter = require("./owner-admin");
app.use(
  "/api/owner/control",
  ownerAdminRouter(pool, requireLogin, requireOwnerUnlocked)
);

function extensionFor(mime) {
  return {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
    "image/gif": "gif",
    "image/heic": "heic",
    "image/heif": "heif"
  }[mime];
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
    ALTER TABLE accounts ADD COLUMN IF NOT EXISTS avatar_path TEXT
  `);

  await pool.query(`
    ALTER TABLE accounts ADD COLUMN IF NOT EXISTS settings_password_hash TEXT
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
    ALTER TABLE memories ADD COLUMN IF NOT EXISTS storage_path TEXT
  `);

  await pool.query(`
    ALTER TABLE memories ALTER COLUMN image_url DROP NOT NULL
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
    VALUES (1) ON CONFLICT (id) DO NOTHING
  `);

  const count = await pool.query(
    "SELECT COUNT(*)::int AS count FROM accounts"
  );

  if (count.rows[0].count === 0) {
    for (const account of accounts) {
      const hash = await bcrypt.hash(account.password, 12);
      await pool.query(
        `INSERT INTO accounts (number, username, password_hash)
         VALUES ($1, $2, $3) ON CONFLICT (number) DO NOTHING`,
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
    if (!username || !password)
      return res.status(400).json({
        error: "اكتب اسم المستخدم وكلمة المرور."
      });

    const result = await pool.query(
      `SELECT number, username, password_hash
       FROM accounts WHERE username = $1`,
      [username]
    );

    const account = result.rows[0];

    if (!account || !(await bcrypt.compare(password, account.password_hash)))
      return res.status(401).json({
        error: "اسم المستخدم أو كلمة المرور غير صحيحة."
      });

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

// معلومات الحساب
app.get("/api/me", async (req, res, next) => {
  try {
    if (!req.session.account)
      return res.json({ authenticated: false, account: null });

    const result = await pool.query(
      `SELECT number, username, avatar_path
       FROM accounts WHERE number = $1`,
      [req.session.account.number]
    );

    const account = result.rows[0];
    if (!account)
      return res.status(404).json({ error: "الحساب غير موجود." });

    let avatar_url = null;
    if (account.avatar_path) {
      const signed = await supabase.storage
        .from(AVATAR_BUCKET)
        .createSignedUrl(account.avatar_path, 3600);
      if (!signed.error) avatar_url = signed.data.signedUrl;
    }

    req.session.account.username = account.username;

    res.json({
      authenticated: true,
      account: {
        number: account.number,
        username: account.username,
        avatar_url
      }
    });
  } catch (error) {
    next(error);
  }
});

// إعدادات الموقع العامة
app.get("/api/site-settings", requireLogin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT site_name, logo, theme_color
       FROM site_settings WHERE id = 1`
    );
    res.json({ settings: result.rows[0] || null });
  } catch (error) {
    next(error);
  }
});

// حالة كلمة مرور إعدادات الحساب
app.get("/api/account/settings-status", requireLogin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT settings_password_hash IS NOT NULL AS has_password
       FROM accounts WHERE number = $1`,
      [req.session.account.number]
    );

    if (!result.rows.length)
      return res.status(404).json({ error: "الحساب غير موجود." });

    res.json({ hasPassword: result.rows[0].has_password });
  } catch (error) {
    next(error);
  }
});

// إنشاء كلمة مرور الإعدادات
app.post("/api/account/settings-password", requireLogin, async (req, res, next) => {
  try {
    const password = String(req.body.password || "");
    const confirmPassword = String(req.body.confirmPassword || "");

    if (password.length < 8 || password.length > 100)
      return res.status(400).json({
        error: "كلمة المرور يجب أن تكون من 8 إلى 100 حرف."
      });

    if (password !== confirmPassword)
      return res.status(400).json({
        error: "كلمتا المرور غير متطابقتين."
      });

    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `UPDATE accounts SET settings_password_hash = $1
       WHERE number = $2 AND settings_password_hash IS NULL
       RETURNING number`,
      [hash, req.session.account.number]
    );

    if (!result.rows.length)
      return res.status(409).json({
        error: "تم إنشاء كلمة مرور الإعدادات مسبقًا."
      });

    req.session.settingsUnlockedAt = Date.now();

    req.session.save(error => {
      if (error) return next(error);
      res.json({ success: true });
    });
  } catch (error) {
    next(error);
  }
});

// فتح إعدادات الحساب
app.post("/api/account/settings-unlock", requireLogin, async (req, res, next) => {
  try {
    const password = String(req.body.password || "");
    if (!password)
      return res.status(400).json({ error: "اكتب كلمة مرور الإعدادات." });

    const result = await pool.query(
      "SELECT settings_password_hash FROM accounts WHERE number = $1",
      [req.session.account.number]
    );

    const hash = result.rows[0]?.settings_password_hash;
    if (!hash)
      return res.status(409).json({
        error: "أنشئ كلمة مرور الإعدادات أولًا."
      });

    if (!(await bcrypt.compare(password, hash)))
      return res.status(401).json({
        error: "كلمة مرور الإعدادات غير صحيحة."
      });

    req.session.settingsUnlockedAt = Date.now();

    req.session.save(error => {
      if (error) return next(error);
      res.json({ success: true });
    });
  } catch (error) {
    next(error);
  }
});

// تغيير اسم المستخدم
app.post(
  "/api/account/username",
  requireLogin,
  requireSettingsUnlocked,
  async (req, res, next) => {
    try {
      const username = String(req.body.username || "").trim();
      const password = String(req.body.password || "");

      if (!/^[a-zA-Z0-9_]{3,20}$/.test(username))
        return res.status(400).json({
          error: "اسم المستخدم يجب أن يكون من 3 إلى 20 حرفًا أو رقمًا أو _."
        });

      if (!password)
        return res.status(400).json({
          error: "اكتب كلمة المرور الحالية."
        });

      const number = req.session.account.number;
      const current = await pool.query(
        "SELECT password_hash FROM accounts WHERE number = $1",
        [number]
      );

      if (!current.rows.length ||
          !(await bcrypt.compare(password, current.rows[0].password_hash)))
        return res.status(401).json({
          error: "كلمة مرور الحساب غير صحيحة."
        });

      const updated = await pool.query(
        `UPDATE accounts SET username = $1
         WHERE number = $2 RETURNING number, username`,
        [username, number]
      );

      req.session.account.username = updated.rows[0].username;
      res.json({ success: true, account: updated.rows[0] });
    } catch (error) {
      if (error.code === "23505")
        return res.status(409).json({
          error: "اسم المستخدم مستخدم بالفعل."
        });
      next(error);
    }
  }
);

// تغيير كلمة مرور الحساب
app.post(
  "/api/account/password",
  requireLogin,
  requireSettingsUnlocked,
  async (req, res, next) => {
    try {
      const currentPassword = String(req.body.currentPassword || "");
      const newPassword = String(req.body.newPassword || "");

      if (newPassword.length < 8 || newPassword.length > 100)
        return res.status(400).json({
          error: "كلمة المرور الجديدة يجب أن تكون 8 أحرف على الأقل."
        });

      const number = req.session.account.number;
      const result = await pool.query(
        "SELECT password_hash FROM accounts WHERE number = $1",
        [number]
      );

      if (!result.rows.length ||
          !(await bcrypt.compare(currentPassword, result.rows[0].password_hash)))
        return res.status(401).json({
          error: "كلمة المرور الحالية غير صحيحة."
        });

      const hash = await bcrypt.hash(newPassword, 12);
      await pool.query(
        "UPDATE accounts SET password_hash = $1 WHERE number = $2",
        [hash, number]
      );

      res.json({ success: true });
    } catch (error) {
      next(error);
    }
  }
);

// رفع صورة الحساب
app.post(
  "/api/account/avatar",
  requireLogin,
  requireSettingsUnlocked,
  upload.single("photo"),
  async (req, res, next) => {
    let uploadedPath = null;

    try {
      if (!req.file)
        return res.status(400).json({ error: "اختر صورة أولًا." });

      const extension = extensionFor(req.file.mimetype);
      const number = req.session.account.number;
      const newPath = `avatars/${number}/${crypto.randomUUID()}.${extension}`;

      const { error: uploadError } = await supabase.storage
        .from(AVATAR_BUCKET)
        .upload(newPath, req.file.buffer, {
          contentType: req.file.mimetype,
          upsert: false
        });

      if (uploadError) throw uploadError;
      uploadedPath = newPath;

      const old = await pool.query(
        "SELECT avatar_path FROM accounts WHERE number = $1",
        [number]
      );

      const signed = await supabase.storage
        .from(AVATAR_BUCKET)
        .createSignedUrl(newPath, 3600);

      if (signed.error) throw signed.error;

      await pool.query(
        "UPDATE accounts SET avatar_path = $1 WHERE number = $2",
        [newPath, number]
      );

      const oldPath = old.rows[0]?.avatar_path;
      if (oldPath)
        await supabase.storage.from(AVATAR_BUCKET).remove([oldPath]);

      res.json({ success: true, avatar_url: signed.data.signedUrl });
    } catch (error) {
      if (uploadedPath)
        await supabase.storage.from(AVATAR_BUCKET).remove([uploadedPath]);
      next(error);
    }
  }
);

// إعدادات الأونر
app.get("/api/owner/status", requireLogin, (req, res) => {
  res.json({
    isOwner: req.session.account.number === OWNER_NUMBER
  });
});

// إنشاء صورة QR للأونر
app.get("/api/owner/qr-image", requireLogin, async (req, res, next) => {
  try {
    if (req.session.account.number !== OWNER_NUMBER) {
      return res.status(403).json({ error: "غير مصرح لك." });
    }

    const payload = "BAYTNA_OWNER_V1:" + OWNER_QR_TOKEN;

    const qrImage = await QRCode.toBuffer(payload, {
      type: "png",
      width: 600,
      margin: 3,
      errorCorrectionLevel: "H"
    });

    res.set({
      "Content-Type": "image/png",
      "Cache-Control": "no-store, no-cache, must-revalidate, private"
    });

    res.send(qrImage);
  } catch (error) {
    next(error);
  }
});

// فتح الأونر باستخدام QR
app.post("/api/owner/qr-unlock", requireLogin, async (req, res, next) => {
  try {
    if (req.session.account.number !== OWNER_NUMBER)
      return res.status(403).json({
        error: "هذا الحساب ليس حساب الأونر."
      });

    const payload = String(req.body.payload || "");
    const expected = "BAYTNA_OWNER_V1:" + OWNER_QR_TOKEN;

    if (payload.length > 200)
      return res.status(400).json({ error: "رمز QR غير صحيح." });

    const suppliedBuffer = Buffer.from(payload, "utf8");
    const expectedBuffer = Buffer.from(expected, "utf8");

    const valid =
      suppliedBuffer.length === expectedBuffer.length &&
      crypto.timingSafeEqual(suppliedBuffer, expectedBuffer);

    if (!valid)
      return res.status(401).json({ error: "رمز QR غير صحيح." });

    req.session.ownerUnlockedAt = Date.now();

    req.session.save(error => {
      if (error) return next(error);
      res.json({ success: true });
    });
  } catch (error) {
    next(error);
  }
});

// قفل الأونر
app.post("/api/owner/lock", requireLogin, (req, res) => {
  if (req.session.account.number !== OWNER_NUMBER)
    return res.status(403).json({ error: "غير مصرح لك." });

  delete req.session.ownerUnlockedAt;
  req.session.save(error => {
    if (error)
      return res.status(500).json({ error: "تعذر قفل الإعدادات." });
    res.json({ success: true });
  });
});

// إعدادات الموقع للأونر
app.get(
  "/api/owner/site-settings",
  requireLogin,
  requireOwnerUnlocked,
  async (req, res, next) => {
    try {
      const result = await pool.query(
        `SELECT site_name, logo, theme_color
         FROM site_settings WHERE id = 1`
      );
      res.json({ settings: result.rows[0] });
    } catch (error) {
      next(error);
    }
  }
);

app.post(
  "/api/owner/site-settings",
  requireLogin,
  requireOwnerUnlocked,
  async (req, res, next) => {
    try {
      const siteName = String(req.body.site_name || "").trim();
      const logo = String(req.body.logo || "").trim();
      const themeColor = String(req.body.theme_color || "").trim();

      if (siteName.length < 2 || siteName.length > 50)
        return res.status(400).json({
          error: "اسم الموقع يجب أن يكون بين حرفين و50 حرفًا."
        });

      if (logo.length > 500)
        return res.status(400).json({
          error: "رابط الشعار طويل جدًا."
        });

      if (logo && !/^https?:\/\//i.test(logo))
        return res.status(400).json({
          error: "رابط الشعار يجب أن يبدأ بـ https:// أو http://"
        });

      if (!/^#[0-9a-fA-F]{6}$/.test(themeColor))
        return res.status(400).json({
          error: "لون الموقع غير صالح."
        });

      const result = await pool.query(
        `UPDATE site_settings
         SET site_name = $1, logo = $2, theme_color = $3
         WHERE id = 1
         RETURNING site_name, logo, theme_color`,
        [siteName, logo, themeColor]
      );

      res.json({ success: true, settings: result.rows[0] });
    } catch (error) {
      next(error);
    }
  }
);

// قائمة الحسابات للأونر
app.get(
  "/api/owner/accounts",
  requireLogin,
  requireOwnerUnlocked,
  async (req, res, next) => {
    try {
      const result = await pool.query(
        `SELECT number, username, avatar_path, created_at
         FROM accounts ORDER BY number ASC`
      );

      res.json({
        accounts: result.rows.map(account => ({
          number: account.number,
          username: account.username,
          created_at: account.created_at,
          hasAvatar: Boolean(account.avatar_path)
        }))
      });
    } catch (error) {
      next(error);
    }
  }
);

// حفظ صورة خاصة
app.post("/api/memories/private", requireLogin, upload.single("photo"), async (req, res, next) => {
  let uploadedPath = null;

  try {
    if (!req.file)
      return res.status(400).json({ error: "اختر صورة أولًا." });

    const extension = extensionFor(req.file.mimetype);
    const number = req.session.account.number;
    const storagePath = `${number}/${crypto.randomUUID()}.${extension}`;

    const { error } = await supabase.storage.from(BUCKET).upload(
      storagePath,
      req.file.buffer,
      { contentType: req.file.mimetype, upsert: false }
    );

    if (error) throw error;
    uploadedPath = storagePath;

    const caption = String(req.body.caption || "").slice(0, 500);
    const result = await pool.query(
      `INSERT INTO memories
       (owner_account_id, storage_path, caption, visibility)
       VALUES ($1, $2, $3, 'private')
       RETURNING id, caption, created_at`,
      [number, storagePath, caption]
    );

    res.status(201).json({ success: true, memory: result.rows[0] });
  } catch (error) {
    if (uploadedPath)
      await supabase.storage.from(BUCKET).remove([uploadedPath]);
    next(error);
  }
});

// عرض الصور الخاصة
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

// نشر صورة خاصة
app.post("/api/memories/:id/publish", requireLogin, async (req, res, next) => {
  const client = await pool.connect();

  try {
    const caption = String(req.body.caption || "").trim().slice(0, 500);
    const number = req.session.account.number;

    await client.query("BEGIN");

    const result = await client.query(
      `UPDATE memories SET visibility = 'public',
       caption = CASE WHEN $1 = '' THEN caption ELSE $1 END
       WHERE id = $2 AND owner_account_id = $3
       AND visibility = 'private'
       RETURNING id, caption, created_at`,
      [caption, req.params.id, number]
    );

    if (!result.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({
        error: "الصورة غير موجودة أو سبق نشرها."
      });
    }

    await client.query(
      `INSERT INTO notifications (account_number, memory_id)
       SELECT number, $1 FROM accounts WHERE number <> $2`,
      [result.rows[0].id, number]
    );

    await client.query("COMMIT");
    res.json({ success: true, memory: result.rows[0] });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    next(error);
  } finally {
    client.release();
  }
});

// الذكريات العامة
app.get("/api/memories/public", requireLogin, async (req, res, next) => {
  try {
    const search = String(req.query.q || "").trim().slice(0, 80);
    let result;

    if (/^\d{4}$/.test(search)) {
      result = await pool.query(
        `SELECT m.id,m.storage_path,m.caption,m.created_at,a.username
         FROM memories m JOIN accounts a ON a.number=m.owner_account_id
         WHERE m.visibility='public' AND
         (m.caption ILIKE $1 OR EXTRACT(YEAR FROM m.created_at)::int=$2 OR m.id::text=$3)
         ORDER BY m.created_at DESC LIMIT 100`,
        [`%${search}%`, Number(search), search]
      );
    } else if (search) {
      result = await pool.query(
        `SELECT m.id,m.storage_path,m.caption,m.created_at,a.username
         FROM memories m JOIN accounts a ON a.number=m.owner_account_id
         WHERE m.visibility='public' AND
         (m.caption ILIKE $1 OR a.username ILIKE $1 OR m.id::text=$2)
         ORDER BY m.created_at DESC LIMIT 100`,
        [`%${search}%`, search]
      );
    } else {
      result = await pool.query(
        `SELECT m.id,m.storage_path,m.caption,m.created_at,a.username
         FROM memories m JOIN accounts a ON a.number=m.owner_account_id
         WHERE m.visibility='public'
         ORDER BY m.created_at DESC LIMIT 100`
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

// الإشعارات
app.get("/api/notifications", requireLogin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT n.id,n.is_read,n.created_at,m.id AS memory_id,
       m.caption,a.username AS sender_username
       FROM notifications n
       LEFT JOIN memories m ON m.id=n.memory_id
       LEFT JOIN accounts a ON a.number=m.owner_account_id
       WHERE n.account_number=$1
       ORDER BY n.created_at DESC LIMIT 100`,
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

app.post("/api/notifications/:id/read", requireLogin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `UPDATE notifications SET is_read=TRUE
       WHERE id=$1 AND account_number=$2 RETURNING id`,
      [req.params.id, req.session.account.number]
    );

    if (!result.rows.length)
      return res.status(404).json({ error: "الإشعار غير موجود." });

    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

app.post("/api/notifications/read-all", requireLogin, async (req, res, next) => {
  try {
    await pool.query(
      "UPDATE notifications SET is_read=TRUE WHERE account_number=$1",
      [req.session.account.number]
    );
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

// حذف صورة
app.delete("/api/memories/:id", requireLogin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id,storage_path FROM memories
       WHERE id=$1 AND owner_account_id=$2`,
      [req.params.id, req.session.account.number]
    );

    const memory = result.rows[0];
    if (!memory)
      return res.status(404).json({ error: "الصورة غير موجودة." });

    if (memory.storage_path) {
      const { error } = await supabase.storage
        .from(BUCKET)
        .remove([memory.storage_path]);
      if (error) throw error;
    }

    await pool.query("DELETE FROM memories WHERE id=$1", [memory.id]);
    res.json({ success: true });
  } catch (error) {
    next(error);
  }
});

// تسجيل الخروج
app.post("/api/logout", (req, res) => {
  req.session.destroy(error => {
    if (error)
      return res.status(500).json({ error: "تعذر تسجيل الخروج." });

    res.clearCookie("baytna.sid");
    res.json({ success: true });
  });
});

// الملفات
app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// الأخطاء
app.use((error, req, res, next) => {
  console.error("========== SERVER ERROR ==========");
  console.error("Name:", error.name);
  console.error("Message:", error.message);
  console.error("Code:", error.code || "unknown");
  console.error("==================================");

  const status = error.statusCode || error.status || 500;
  res.status(status).json({
    error: status < 500
      ? error.message
      : "حدث خطأ في الخادم. حاول مرة أخرى."
  });
});

// التشغيل
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
