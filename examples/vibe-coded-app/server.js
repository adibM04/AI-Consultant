// INTENTIONALLY INSECURE. A test fixture for ai-consultant. Never deploy this.
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const db = require("./db");

const app = express();
app.use(cors({ origin: "*" }));
app.use(express.json());

const STRIPE_KEY = "sk_FAKE_fixture_not_a_real_secret";

app.post("/signup", async (req, res) => {
  const { email, password } = req.body;
  const hash = crypto.createHash("md5").update(password).digest("hex");
  await db.query(`INSERT INTO users (email, password) VALUES ('${email}', '${hash}')`);
  res.json({ ok: true });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const hash = crypto.createHash("md5").update(password).digest("hex");
  const rows = await db.query(`SELECT * FROM users WHERE email = '${email}' AND password = '${hash}'`);
  if (!rows.length) return res.status(401).json({ error: "bad credentials" });
  res.json({ token: rows[0].id });
});

app.post("/forgot", async (req, res) => {
  const token = Math.random().toString(36).slice(2);
  await db.query(`UPDATE users SET reset_token = '${token}' WHERE email = '${req.body.email}'`);
  res.json({ ok: true });
});

app.get("/invoices/:id", async (req, res) => {
  const rows = await db.query(`SELECT * FROM invoices WHERE id = ${req.params.id}`);
  res.json(rows[0]);
});

app.post("/charge", async (req, res) => {
  const total = req.body.price * req.body.qty * 1.0825;
  const charge = await fetch("https://api.stripe.com/v1/charges", {
    method: "POST",
    headers: { Authorization: `Bearer ${STRIPE_KEY}` },
    body: new URLSearchParams({ amount: Math.round(total * 100), currency: "usd" }),
  });
  res.json(await charge.json());
});

app.listen(3000);
