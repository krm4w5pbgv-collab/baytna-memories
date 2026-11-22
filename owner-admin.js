
const express = require("express");

module.exports = function createOwnerAdminRouter(pool, requireLogin, requireOwnerUnlocked) {
  const router = express.Router();

  const definitions = {
    site_name: ["ذكريات بيتنا", "text", 50],
    logo: ["", "url", 500],
    theme_color: ["#8b684b", "color"],
    site_description: ["مساحة تجمع ذكريات بيتنا", "text", 200],
    welcome_message: ["أهلًا بكم في ذكريات بيتنا", "text", 300],
    background_color: ["#f5eee4", "color"],
    footer_text: ["جميع الحقوق محفوظة", "text", 200],
    maintenance_enabled: [false, "boolean"],
    maintenance_message: ["الموقع تحت الصيانة، نعود قريبًا.", "text", 300],
    allow_public_memories: [true, "boolean"],
    allow_memory_uploads: [true, "boolean"],
    max_upload_mb: [5, "number", 1, 5],
    max_public_memories: [100, "number", 1, 1000],
    notifications_enabled: [true, "boolean"],
    notification_sound: [true, "boolean"],
    show_account_numbers: [true, "boolean"],
    show_join_dates: [false, "boolean"],
    owner_session_minutes: [10, "number", 1, 60],
    settings_session_minutes: [10, "number", 1, 60],
    require_settings_password: [true, "boolean"],
    enable_public_search: [true, "boolean"],
    enable_memory_captions: [true, "boolean"],
    enable_avatar_uploads: [true, "boolean"],
    max_avatar_mb: [5, "number", 1, 5],
    gallery_page_size: [20, "number", 5, 100],
    default_memory_visibility: ["private", "choice", ["private", "public"]],
    allow_gif_uploads: [true, "boolean"],
    allow_heic_uploads: [true, "boolean"],
    site_language: ["ar", "choice", ["ar", "en"]],
    timezone: ["Asia/Riyadh", "choice", ["Asia/Riyadh", "UTC"]]
  };

  let initialization;

  async function initialize() {
    if (!initialization) {
      initialization = (async () => {
        await pool.query(`
          CREATE TABLE IF NOT EXISTS owner_settings (
            setting_key TEXT PRIMARY KEY,
            setting_value JSONB NOT NULL,
            updated_at TIMESTAMPTZ DEFAULT NOW()
          )
        `);

        await pool.query(`
          CREATE TABLE IF NOT EXISTS owner_audit_log (
            id BIGSERIAL PRIMARY KEY,
            account_number INTEGER,
            action TEXT NOT NULL,
            details JSONB DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ DEFAULT NOW()
          )
        `);

        for (const [key, definition] of Object.entries(definitions)) {
          await pool.query(
            `INSERT INTO owner_settings (setting_key, setting_value)
             VALUES ($1, $2::jsonb)
             ON CONFLICT (setting_key) DO NOTHING`,
            [key, JSON.stringify(definition[0])]
          );
        }
      })().catch(error => {
        initialization = null;
        throw error;
      });
    }

    return initialization;
  }

  function validateValue(key, value) {
    const definition = definitions[key];

    if (!definition) return "إعداد غير معروف.";

    const [, type, a, b] = definition;

    if (type === "boolean") {
      return typeof value === "boolean"
        ? null
        : "القيمة يجب أن تكون تشغيلًا أو إيقافًا.";
    }

    if (type === "number") {
      if (typeof value !== "number" || !Number.isFinite(value)) {
        return "القيمة يجب أن تكون رقمًا.";
      }

      if (value < a || value > b) {
        return `القيمة يجب أن تكون بين ${a} و${b}.`;
      }

      return null;
    }

    if (type === "choice") {
      return Array.isArray(a) && a.includes(value)
        ? null
        : "الخيار المحدد غير صالح.";
    }

    if (type === "color") {
      return typeof value === "string" && /^#[0-9a-fA-F]{6}$/.test(value)
        ? null
        : "صيغة اللون غير صحيحة.";
    }

    if (type === "url") {
      if (typeof value !== "string" || value.length > a) {
        return "الرابط طويل جدًا أو غير صالح.";
      }

      if (!value) return null;

      return /^https?:\/\/\S+$/i.test(value)
        ? null
        : "الرابط يجب أن يبدأ بـ https:// أو http://";
    }

    if (type === "text") {
      if (typeof value !== "string" || value.length > a) {
        return `النص يجب ألا يتجاوز ${a} حرفًا.`;
      }

      return null;
    }

    return "نوع القيمة غير مدعوم.";
  }

  router.use(requireLogin, requireOwnerUnlocked);

  router.get("/settings", async (req, res, next) => {
    try {
      await initialize();

      const result = await pool.query(
        `SELECT setting_key, setting_value, updated_at
         FROM owner_settings ORDER BY setting_key`
      );

      const settings = {};

      for (const row of result.rows) {
        settings[row.setting_key] = row.setting_value;
      }

      res.json({
        success: true,
        count: Object.keys(definitions).length,
        settings,
        definitions: Object.keys(definitions)
      });
    } catch (error) {
      next(error);
    }
  });

  router.put("/settings", async (req, res, next) => {
    try {
      await initialize();

      const changes = req.body && req.body.settings;

      if (!changes || typeof changes !== "object" || Array.isArray(changes)) {
        return res.status(400).json({
          error: "أرسل الإعدادات بصيغة صحيحة."
        });
      }

      const entries = Object.entries(changes);

      if (!entries.length || entries.length > 30) {
        return res.status(400).json({
          error: "عدد الإعدادات المرسلة غير صالح."
        });
      }

      for (const [key, value] of entries) {
        const error = validateValue(key, value);

        if (error) {
          return res.status(400).json({
            error: `${key}: ${error}`
          });
        }
      }

      const client = await pool.connect();

      try {
        await client.query("BEGIN");

        for (const [key, value] of entries) {
          await client.query(
            `INSERT INTO owner_settings (setting_key, setting_value, updated_at)
             VALUES ($1, $2::jsonb, NOW())
             ON CONFLICT (setting_key)
             DO UPDATE SET setting_value = EXCLUDED.setting_value,
                           updated_at = NOW()`,
            [key, JSON.stringify(value)]
          );
        }

        await client.query(
          `INSERT INTO owner_audit_log
           (account_number, action, details)
           VALUES ($1, $2, $3::jsonb)`,
          [
            req.session.account.number,
            "update_owner_settings",
            JSON.stringify({
              changed_keys: entries.map(([key]) => key)
            })
          ]
        );

        await client.query("COMMIT");

        res.json({
          success: true,
          updated: entries.length,
          message: "تم حفظ الإعدادات."
        });
      } catch (error) {
        await client.query("ROLLBACK").catch(() => {});
        throw error;
      } finally {
        client.release();
      }
    } catch (error) {
      next(error);
    }
  });

  router.get("/logs", async (req, res, next) => {
    try {
      await initialize();

      const result = await pool.query(
        `SELECT id, account_number, action, details, created_at
         FROM owner_audit_log
         ORDER BY created_at DESC
         LIMIT 100`
      );

      res.json({
        success: true,
        logs: result.rows
      });
    } catch (error) {
      next(error);
    }
  });

  return router;
};
