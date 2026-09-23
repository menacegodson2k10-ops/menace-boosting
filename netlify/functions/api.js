// netlify/functions/api.js
// Complete API replacement for Menace Boosting
// Compatible with the existing frontend

const express = require("express");
const serverless = require("serverless-http");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(cors());
app.use(express.json());

// ============================================================
// CONFIGURATION – set these in Netlify Environment Variables
// ============================================================
const JWT_SECRET = process.env.JWT_SECRET || "change-this-to-a-long-random-secret";
const JWT_EXPIRES_IN = "7d";

// ============================================================
// IN-MEMORY STORE
// (Data is lost on cold starts. Replace with MongoDB / Postgres later)
// ============================================================
const users = [];          // { id, email, passwordHash, balance, role, createdAt }
const services = [         // Pre-loaded sample services
  { id: 1, name: "Instagram Followers", category: "Instagram", rate: 2.50, min: 100, max: 10000, refill: true, cancel: true },
  { id: 2, name: "Instagram Likes",     category: "Instagram", rate: 0.80, min: 50,  max: 5000,  refill: true, cancel: false },
  { id: 3, name: "TikTok Views",        category: "TikTok",    rate: 0.40, min: 1000,max: 100000,refill: false,cancel: true },
  { id: 4, name: "YouTube Views",       category: "YouTube",   rate: 1.20, min: 500, max: 50000, refill: true, cancel: true },
  { id: 5, name: "Twitter Followers",   category: "Twitter",   rate: 3.00, min: 100, max: 5000,  refill: true, cancel: true },
];
const orders = [];         // { id, userId, serviceId, service_name, link, quantity, charge, status, cancel, refill, createdAt }
const deposits = [];       // { id, userId, email, amount, method, reference, status, createdAt }

// Create a default admin account on first run (password: Admin123!)
(async () => {
  const adminExists = users.find(u => u.email === "admin@menace.com");
  if (!adminExists) {
    const hash = await bcrypt.hash("Admin123!", 10);
    users.push({
      id: uuidv4(),
      email: "admin@menace.com",
      passwordHash: hash,
      balance: 100.00,
      role: "admin",
      createdAt: new Date().toISOString()
    });
    console.log("Default admin created → email: admin@menace.com | password: Admin123!");
  }
})();

// ============================================================
// HELPER FUNCTIONS
// ============================================================
function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Authentication required." });
  }
  try {
    const decoded = jwt.verify(header.split(" ")[1], JWT_SECRET);
    const user = users.find(u => u.id === decoded.id);
    if (!user) return res.status(401).json({ error: "User not found." });
    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token." });
  }
}

function adminMiddleware(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin access required." });
  }
  next();
}

// ============================================================
// AUTH ROUTES
// ============================================================
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required." });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters." });
    }
    if (users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
      return res.status(400).json({ error: "Email already registered." });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = {
      id: uuidv4(),
      email: email.toLowerCase(),
      passwordHash,
      balance: 0,
      role: "user",
      createdAt: new Date().toISOString()
    };
    users.push(newUser);

    const token = generateToken(newUser);
    res.status(201).json({ token });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "Unable to create account." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required." });
    }

    const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
    if (!user) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) {
      return res.status(401).json({ error: "Invalid email or password." });
    }

    const token = generateToken(user);
    res.json({ token });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Unable to log in." });
  }
});

// ============================================================
// USER ROUTES
// ============================================================
app.get("/api/me", authMiddleware, (req, res) => {
  res.json({
    id: req.user.id,
    email: req.user.email,
    balance: req.user.balance,
    role: req.user.role
  });
});

// ============================================================
// SERVICES
// ============================================================
app.get("/api/services", authMiddleware, (req, res) => {
  res.json(services);
});

// ============================================================
// ORDERS
// ============================================================
app.post("/api/orders", authMiddleware, (req, res) => {
  try {
    const { serviceId, link, quantity } = req.body;
    const service = services.find(s => s.id === Number(serviceId));
    if (!service) return res.status(400).json({ error: "Service not found." });
    if (!link) return res.status(400).json({ error: "Target link is required." });
    if (!quantity || quantity < service.min || quantity > service.max) {
      return res.status(400).json({ error: `Quantity must be between ${service.min} and ${service.max}.` });
    }

    const charge = (service.rate / 1000) * quantity;
    if (req.user.balance < charge) {
      return res.status(400).json({ error: "Insufficient balance." });
    }

    // Deduct balance
    req.user.balance -= charge;

    const order = {
      id: orders.length + 1,
      userId: req.user.id,
      serviceId: service.id,
      service_name: service.name,
      link,
      quantity: Number(quantity),
      charge: Number(charge.toFixed(4)),
      status: "Pending",
      cancel: service.cancel,
      refill: service.refill,
      createdAt: new Date().toISOString()
    };
    orders.push(order);

    res.json({ orderId: order.id, charge: order.charge });
  } catch (err) {
    console.error("Create order error:", err);
    res.status(500).json({ error: "Unable to place order." });
  }
});

app.get("/api/orders", authMiddleware, (req, res) => {
  const userOrders = orders
    .filter(o => o.userId === req.user.id)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json(userOrders);
});

app.post("/api/orders/:id/cancel", authMiddleware, (req, res) => {
  const order = orders.find(o => o.id === Number(req.params.id) && o.userId === req.user.id);
  if (!order) return res.status(404).json({ error: "Order not found." });
  if (!order.cancel) return res.status(400).json({ error: "This order cannot be cancelled." });
  if (order.status === "Cancelled" || order.status === "Completed") {
    return res.status(400).json({ error: "Order cannot be cancelled in its current status." });
  }
  order.status = "Cancelled";
  res.json({ success: true });
});

app.post("/api/orders/:id/refill", authMiddleware, (req, res) => {
  const order = orders.find(o => o.id === Number(req.params.id) && o.userId === req.user.id);
  if (!order) return res.status(404).json({ error: "Order not found." });
  if (!order.refill) return res.status(400).json({ error: "This order does not support refill." });
  // In a real system you would call the supplier API here
  res.json({ success: true, message: "Refill request sent." });
});

// ============================================================
// DEPOSITS
// ============================================================
app.post("/api/deposits", authMiddleware, (req, res) => {
  try {
    const { amount, method, reference } = req.body;
    if (!amount || amount <= 0) return res.status(400).json({ error: "Valid amount is required." });
    if (!method) return res.status(400).json({ error: "Payment method is required." });

    const deposit = {
      id: deposits.length + 1,
      userId: req.user.id,
      email: req.user.email,
      amount: Number(amount),
      method,
      reference: reference || "",
      status: "pending",
      createdAt: new Date().toISOString()
    };
    deposits.push(deposit);
    res.json({ success: true });
  } catch (err) {
    console.error("Deposit error:", err);
    res.status(500).json({ error: "Unable to submit deposit." });
  }
});

// ============================================================
// ADMIN ROUTES
// ============================================================
app.get("/api/admin/summary", authMiddleware, adminMiddleware, (req, res) => {
  res.json({
    users: users.length,
    orders: orders.length,
    pendingDeposits: deposits.filter(d => d.status === "pending").length
  });
});

app.get("/api/admin/deposits", authMiddleware, adminMiddleware, (req, res) => {
  const list = deposits
    .map(d => ({
      id: d.id,
      email: d.email,
      amount: d.amount,
      method: d.method,
      reference: d.reference,
      status: d.status,
      createdAt: d.createdAt
    }))
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json(list);
});

app.post("/api/admin/deposits/:id/:action", authMiddleware, adminMiddleware, (req, res) => {
  const deposit = deposits.find(d => d.id === Number(req.params.id));
  if (!deposit) return res.status(404).json({ error: "Deposit not found." });
  if (deposit.status !== "pending") {
    return res.status(400).json({ error: "Deposit is already processed." });
  }

  const action = req.params.action;
  if (action === "approve") {
    deposit.status = "approved";
    const user = users.find(u => u.id === deposit.userId);
    if (user) user.balance += deposit.amount;
  } else if (action === "reject") {
    deposit.status = "rejected";
  } else {
    return res.status(400).json({ error: "Invalid action." });
  }
  res.json({ success: true });
});

app.post("/api/admin/sync-services", authMiddleware, adminMiddleware, (req, res) => {
  // Placeholder – in production this would call your SMM panel API
  // and update the services array
  res.json({ count: services.length });
});

app.get("/api/supplier/balance", authMiddleware, adminMiddleware, (req, res) => {
  // Placeholder for supplier balance check
  res.json({
    data: {
      balance: 0,
      currency: "USD",
      note: "Connect your real SMM panel API here"
    }
  });
});

// ============================================================
// HEALTH CHECK
// ============================================================
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ============================================================
// EXPORT FOR NETLIFY
// ============================================================
module.exports.handler = serverless(app);
