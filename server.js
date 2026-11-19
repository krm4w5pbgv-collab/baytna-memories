
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.set("trust proxy", 1);
app.use(helmet());
app.use(express.json({ limit: "10kb" }));

const accounts = Array.from({ length: 7 }, (_, i) => {
  const number = i + 1;

  return {
    number,
    username: process.env[`ACCOUNT_${number}_USERNAME`],
    password: process.env[`ACCOUNT_${number}_PASSWORD`]
  };
}).filter(account => account.username && account.password);

function safeCompare(a, b) {
  const first = Buffer.from(String(a));
  const second = Buffer.from(String(b));

  return first.length === second.length &&
    crypto.timingSafeEqual(first, second);
}

app.use(session({
  name: "baytna.sid",
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

app.post("/api/login", (req, res, next) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({
      error: "اكتب اسم المستخدم وكلمة المرور."
    });
  }

  const account = accounts.find(item =>
    safeCompare(item.username, username) &&
    safeCompare(item.password, password)
  );

  if (!account) {
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
});

app.get("/api/me", (req, res) => {
  res.json({
    authenticated: Boolean(req.session.account),
    account: req.session.account || null
  });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("baytna.sid");
    res.json({ success: true });
  });
});

app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`Baytna Memories is running on port ${PORT}`);
});
