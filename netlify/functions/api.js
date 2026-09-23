const express = require("express");
const serverless = require("serverless-http");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { getStore } = require("@netlify/blobs");

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "change-this";
const API_URL =
  process.env.EXOSUPPLIER_API_URL || "https://exosupplier.com/api/v2";

const store = () =>
  getStore({
    name: "menace-boosting-data",
    consistency: "strong"
  });

async function read(key, fallback) {
  const value = await store().get(key, { type: "json" });
  return value ?? fallback;
}

async function write(key, value) {
  return store().setJSON(key, value);
}

async function nextId(name) {
  const key = `counter:${name}`;
  const value = (await read(key, 0)) + 1;
  await write(key, value);
  return value;
}

async function supplier(data) {
  if (!process.env.EXOSUPPLIER_API_KEY) {
    throw new Error("ExoSupplier API key is not configured");
  }

  const response = await fetch(API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json"
    },
    body: new URLSearchParams({
      key: process.env.EXOSUPPLIER_API_KEY,
      ...data
    })
  });

  const text = await response.text();

  let result;
  try {
    result = JSON.parse(text);
  } catch {
    result = { raw: text };
  }

  if (!response.ok || result.error) {
    throw new Error(result.error || `Supplier HTTP ${response.status}`);
  }

  return result;
}

function token(user) {
  return jwt.sign(
    {
      id: user.id,
      role: user.role
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      throw new Error();
    }

    req.user = jwt.verify(
      header.substring(7),
      JWT_SECRET
    );

    next();
  } catch {
    res.status(401).json({
      error: "Authentication required"
    });
  }
}

function admin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      error: "Admin only"
    });
  }

  next();
}

/* Registration */
app.post("/api/auth/register", async (req, res) => {
  try {
    const email = String(req.body.email || "").toLowerCase();
    const password = String(req.body.password || "");

    if (!email || password.length < 6) {
      return res.status(400).json({
        error: "Valid email and 6+ character password required"
      });
    }

    const users = await read("users", []);

    if (users.some(user => user.email === email)) {
      return res.status(400).json({
        error: "Email already registered"
      });
    }

    const user = {
      id: await nextId("users"),
      email,
      password: await bcrypt.hash(password, 10),
      role: "user",
      balance: 0,
      created_at: new Date().toISOString()
    };

    users.push(user);

    await write("users", users);

    res.json({
      token: token(user),
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        balance: user.balance
      }
    });
  } catch (error) {
    res.status(500).json({
      error: error.message
    });
  }
});

/* Login */
app.post("/api/auth/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").toLowerCase();
    const password = String(req.body.password || "");

    const users = await read("users", []);

    const user = users.find(
      item => item.email === email
    );

    if (
      !user ||
      !(await bcrypt.compare(password, user.password))
    ) {
      return res.status(401).json({
        error: "Invalid credentials"
      });
    }

    res.json({
      token: token(user),
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        balance: user.balance
      }
    });
  } catch (error) {
    res.status(500).json({
      error: error.message
    });
  }
});

/* Current user */
app.get("/api/me", auth, async (req, res) => {
  const users = await read("users", []);

  const user = users.find(
    item => item.id === req.user.id
  );

  if (!user) {
    return res.status(404).json({
      error: "User not found"
    });
  }

  res.json({
    id: user.id,
    email: user.email,
    role: user.role,
    balance: user.balance
  });
});

/* Categories */
app.get("/api/categories", async (req, res) => {
  res.json(
    await read("categories", [
      { id: 1, name: "Instagram" },
      { id: 2, name: "TikTok" },
      { id: 3, name: "YouTube" },
      { id: 4, name: "Facebook" },
      { id: 5, name: "Other" }
    ])
  );
});

/* Services */
app.get("/api/services", auth, async (req, res) => {
  const services = await read("services", []);

  res.json(
    services.filter(service => service.active !== false)
  );
});

/* Sync ExoSupplier services */
app.post(
  "/api/admin/sync-services",
  auth,
  admin,
  async (req, res) => {
    try {
      const data = await supplier({
        action: "services"
      });

      const list = Array.isArray(data)
        ? data
        : data.services || [];

      const services = list.map((service, index) => ({
        id: index + 1,
        supplier_id: String(
          service.service ?? service.id
        ),
        name: service.name || "Unnamed service",
        category: service.category || "Other",
        rate: Number(
          service.rate || service.price || 0
        ),
        min: Number(service.min || 1),
        max: Number(service.max || 999999),
        refill: Boolean(service.refill),
        cancel: Boolean(service.cancel),
        active: true
      }));

      await write("services", services);

      res.json({
        ok: true,
        count: services.length
      });
    } catch (error) {
      res.status(502).json({
        error: error.message
      });
    }
  }
);

/* Create order */
app.post("/api/orders", auth, async (req, res) => {
  try {
    const services = await read("services", []);

    const service = services.find(
      item =>
        item.id === Number(req.body.serviceId) &&
        item.active !== false
    );

    const quantity = Number(req.body.quantity);

    if (
      !service ||
      !req.body.link ||
      !Number.isInteger(quantity) ||
      quantity < service.min ||
      quantity > service.max
    ) {
      return res.status(400).json({
        error: "Invalid service, link or quantity"
      });
    }

    const users = await read("users", []);

    const user = users.find(
      item => item.id === req.user.id
    );

    const charge = Number(
      (quantity * service.rate / 1000).toFixed(4)
    );

    if (!user || user.balance < charge) {
      return res.status(400).json({
        error: "Insufficient wallet balance"
      });
    }

    user.balance = Number(
      (user.balance - charge).toFixed(4)
    );

    await write("users", users);

    const orders = await read("orders", []);

    const order = {
      id: await nextId("orders"),
      user_id: user.id,
      service_id: service.id,
      service_name: service.name,
      link: String(req.body.link),
      quantity,
      charge,
      status: "processing",
      supplier_order_id: null,
      created_at: new Date().toISOString()
    };

    orders.unshift(order);

    await write("orders", orders);

    try {
      const result = await supplier({
        action: "add",
        service: service.supplier_id,
        link: order.link,
        quantity: String(quantity)
      });

      order.supplier_order_id = String(
        result.order || result.id || ""
      );

      await write("orders", orders);

      res.json({
        ok: true,
        orderId: order.id,
        charge
      });
    } catch (error) {
      order.status = "supplier_error";

      user.balance = Number(
        (user.balance + charge).toFixed(4)
      );

      await write("orders", orders);
      await write("users", users);

      res.status(502).json({
        error: error.message
      });
    }
  } catch (error) {
    res.status(500).json({
      error: error.message
    });
  }
});

/* Order history */
app.get("/api/orders", auth, async (req, res) => {
  const orders = await read("orders", []);

  res.json(
    orders.filter(
      order => order.user_id === req.user.id
    )
  );
});

/* Deposit request */
app.post("/api/deposits", auth, async (req, res) => {
  const amount = Number(req.body.amount);

  if (!amount || amount <= 0) {
    return res.status(400).json({
      error: "Invalid amount"
    });
  }

  const deposits = await read("deposits", []);

  const deposit = {
    id: await nextId("deposits"),
    user_id: req.user.id,
    amount,
    method: req.body.method || "Manual",
    reference: req.body.reference || "",
    status: "pending",
    created_at: new Date().toISOString()
  };

  deposits.unshift(deposit);

  await write("deposits", deposits);

  res.json({
    ok: true,
    id: deposit.id
  });
});

/* Admin dashboard summary */
app.get(
  "/api/admin/summary",
  auth,
  admin,
  async (req, res) => {
    const users = await read("users", []);
    const orders = await read("orders", []);
    const deposits = await read("deposits", []);

    res.json({
      users: users.length,
      orders: orders.length,
      pendingDeposits: deposits.filter(
        item => item.status === "pending"
      ).length,
      revenue: orders.reduce(
        (total, order) =>
          total + Number(order.charge || 0),
        0
      )
    });
  }
);

/* Supplier balance */
app.get(
  "/api/supplier/balance",
  auth,
  admin,
  async (req, res) => {
    try {
      const result = await supplier({
        action: "balance"
      });

      res.json({
        ok: true,
        data: result
      });
    } catch (error) {
      res.status(502).json({
        error: error.message
      });
    }
  }
);

exports.handler = serverless(app);
