const express = require("express");
const serverless = require("serverless-http");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const {
  getStore,
  connectLambda
} = require("@netlify/blobs");

const app = express();

app.use(express.json());

const JWT_SECRET =
  process.env.JWT_SECRET || "change-this-secret";

const EXOSUPPLIER_API_URL =
  process.env.EXOSUPPLIER_API_URL ||
  "https://exosupplier.com/api/v2";

const store = () =>
  getStore("menace-boosting-data");

async function read(key, fallback) {
  const value = await store().get(key, {
    type: "json"
  });

  if (
    value === null ||
    value === undefined
  ) {
    return fallback;
  }

  return value;
}

async function write(key, value) {
  await store().setJSON(key, value);
  return value;
}

async function nextId(name) {
  const key = `counter:${name}`;

  const current = await read(key, 0);

  const next = Number(current) + 1;

  await write(key, next);

  return next;
}

async function callExoSupplier(data) {
  const apiKey =
    process.env.EXOSUPPLIER_API_KEY;

  if (!apiKey) {
    throw new Error(
      "ExoSupplier API key is not configured in Netlify."
    );
  }

  const response = await fetch(
    EXOSUPPLIER_API_URL,
    {
      method: "POST",

      headers: {
        "Content-Type":
          "application/x-www-form-urlencoded",

        Accept: "application/json"
      },

      body: new URLSearchParams({
        key: apiKey,
        ...data
      })
    }
  );

  const text = await response.text();

  let result;

  try {
    result = JSON.parse(text);
  } catch {
    result = {
      raw: text
    };
  }

  if (!response.ok) {
    throw new Error(
      `ExoSupplier HTTP error: ${response.status}`
    );
  }

  if (result.error) {
    throw new Error(
      String(result.error)
    );
  }

  return result;
}

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      role: user.role
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function authenticate(
  req,
  res,
  next
) {
  try {
    const header =
      req.headers.authorization || "";

    if (
      !header.startsWith("Bearer ")
    ) {
      return res.status(401).json({
        error:
          "Authentication required."
      });
    }

    const token =
      header.substring(7);

    req.user =
      jwt.verify(
        token,
        JWT_SECRET
      );

    next();
  } catch {
    return res.status(401).json({
      error:
        "Invalid or expired login session."
    });
  }
}

function requireAdmin(
  req,
  res,
  next
) {
  if (
    !req.user ||
    req.user.role !== "admin"
  ) {
    return res.status(403).json({
      error:
        "Administrator access required."
    });
  }

  next();
}


/* =========================
   HEALTH CHECK
========================= */

app.get(
  "/api/health",
  (req, res) => {
    res.json({
      ok: true,
      service:
        "Menace Boosting API"
    });
  }
);


/* =========================
   REGISTER
========================= */

app.post(
  "/api/auth/register",
  async (req, res) => {
    try {
      const email =
        String(
          req.body.email || ""
        )
          .trim()
          .toLowerCase();

      const password =
        String(
          req.body.password || ""
        );

      if (
        !email ||
        password.length < 6
      ) {
        return res.status(400).json({
          error:
            "Enter a valid email and a password of at least 6 characters."
        });
      }

      const users =
        await read(
          "users",
          []
        );

      const existingUser =
        users.find(
          user =>
            user.email ===
            email
        );

      if (existingUser) {
        return res.status(400).json({
          error:
            "An account with this email already exists."
        });
      }

      const user = {
        id:
          await nextId(
            "users"
          ),

        email,

        password:
          await bcrypt.hash(
            password,
            10
          ),

        role: "user",

        balance: 0,

        created_at:
          new Date().toISOString()
      };

      users.push(user);

      await write(
        "users",
        users
      );

      const accessToken =
        createToken(user);

      return res.json({
        success: true,

        token:
          accessToken,

        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          balance: user.balance
        }
      });

    } catch (error) {
      console.error(
        "REGISTER ERROR:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to create account."
      });
    }
  }
);


/* =========================
   LOGIN
========================= */

app.post(
  "/api/auth/login",
  async (req, res) => {
    try {
      const email =
        String(
          req.body.email || ""
        )
          .trim()
          .toLowerCase();

      const password =
        String(
          req.body.password || ""
        );

      const users =
        await read(
          "users",
          []
        );

      const user =
        users.find(
          item =>
            item.email ===
            email
        );

      if (!user) {
        return res.status(401).json({
          error:
            "Invalid email or password."
        });
      }

      const validPassword =
        await bcrypt.compare(
          password,
          user.password
        );

      if (!validPassword) {
        return res.status(401).json({
          error:
            "Invalid email or password."
        });
      }

      const accessToken =
        createToken(user);

      return res.json({
        success: true,

        token:
          accessToken,

        user: {
          id: user.id,
          email: user.email,
          role: user.role,
          balance: user.balance
        }
      });

    } catch (error) {
      console.error(
        "LOGIN ERROR:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to log in."
      });
    }
  }
);


/* =========================
   CURRENT USER
========================= */

app.get(
  "/api/me",
  authenticate,
  async (req, res) => {
    try {
      const users =
        await read(
          "users",
          []
        );

      const user =
        users.find(
          item =>
            item.id ===
            req.user.id
        );

      if (!user) {
        return res.status(404).json({
          error:
            "User not found."
        });
      }

      return res.json({
        id: user.id,
        email: user.email,
        role: user.role,
        balance: user.balance,
        created_at:
          user.created_at
      });

    } catch (error) {
      console.error(
        "ME ERROR:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to load account."
      });
    }
  }
);


/* =========================
   CATEGORIES
========================= */

app.get(
  "/api/categories",
  async (req, res) => {
    const categories =
      await read(
        "categories",
        [
          {
            id: 1,
            name: "Instagram"
          },
          {
            id: 2,
            name: "TikTok"
          },
          {
            id: 3,
            name: "YouTube"
          },
          {
            id: 4,
            name: "Facebook"
          },
          {
            id: 5,
            name: "Other"
          }
        ]
      );

    return res.json(
      categories
    );
  }
);


/* =========================
   SERVICES
========================= */

app.get(
  "/api/services",
  authenticate,
  async (req, res) => {
    try {
      const services =
        await read(
          "services",
          []
        );

      return res.json(
        services.filter(
          service =>
            service.active !== false
        )
      );

    } catch (error) {
      console.error(
        "SERVICES ERROR:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to load services."
      });
    }
  }
);


/* =========================
   ADMIN SYNC SERVICES
========================= */

app.post(
  "/api/admin/sync-services",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const supplierData =
        await callExoSupplier({
          action:
            "services"
        });

      const serviceList =
        Array.isArray(
          supplierData
        )
          ? supplierData
          : supplierData.services ||
            [];

      const services =
        serviceList.map(
          (service, index) => ({
            id:
              index + 1,

            supplier_id:
              String(
                service.service ??
                service.id ??
                ""
              ),

            name:
              service.name ||
              "Unnamed service",

            category:
              service.category ||
              "Other",

            rate:
              Number(
                service.rate ||
                service.price ||
                0
              ),

            min:
              Number(
                service.min ||
                1
              ),

            max:
              Number(
                service.max ||
                999999
              ),

            refill:
              service.refill ===
                true ||
              service.refill ===
                1 ||
              service.refill ===
                "1",

            cancel:
              service.cancel ===
                true ||
              service.cancel ===
                1 ||
              service.cancel ===
                "1",

            active:
              true
          })
        );

      await write(
        "services",
        services
      );

      return res.json({
        success: true,
        count:
          services.length
      });

    } catch (error) {
      console.error(
        "SERVICE SYNC ERROR:",
        error
      );

      return res.status(502).json({
        error:
          error.message
      });
    }
  }
);


/* =========================
   CREATE ORDER
========================= */

app.post(
  "/api/orders",
  authenticate,
  async (req, res) => {
    try {
      const serviceId =
        Number(
          req.body.serviceId
        );

      const quantity =
        Number(
          req.body.quantity
        );

      const link =
        String(
          req.body.link || ""
        ).trim();

      const services =
        await read(
          "services",
          []
        );

      const service =
        services.find(
          item =>
            item.id ===
              serviceId &&
            item.active !== false
        );

      if (!service) {
        return res.status(400).json({
          error:
            "Service not found."
        });
      }

      if (!link) {
        return res.status(400).json({
          error:
            "Enter a valid link."
        });
      }

      if (
        !Number.isInteger(
          quantity
        ) ||
        quantity <
          service.min ||
        quantity >
          service.max
      ) {
        return res.status(400).json({
          error:
            `Quantity must be between ${service.min} and ${service.max}.`
        });
      }

      const users =
        await read(
          "users",
          []
        );

      const user =
        users.find(
          item =>
            item.id ===
            req.user.id
        );

      if (!user) {
        return res.status(404).json({
          error:
            "User not found."
        });
      }

      const charge =
        Number(
          (
            quantity *
            Number(
              service.rate || 0
            ) /
            1000
          ).toFixed(4)
        );

      if (
        user.balance <
        charge
      ) {
        return res.status(400).json({
          error:
            "Insufficient wallet balance."
        });
      }

      user.balance =
        Number(
          (
            user.balance -
            charge
          ).toFixed(4)
        );

      await write(
        "users",
        users
      );

      const orders =
        await read(
          "orders",
          []
        );

      const order = {
        id:
          await nextId(
            "orders"
          ),

        user_id:
          user.id,

        service_id:
          service.id,

        service_name:
          service.name,

        link,

        quantity,

        charge,

        status:
          "processing",

        supplier_order_id:
          null,

        created_at:
          new Date().toISOString(),

        updated_at:
          new Date().toISOString()
      };

      orders.unshift(
        order
      );

      await write(
        "orders",
        orders
      );

      try {
        const supplierResult =
          await callExoSupplier({
            action:
              "add",

            service:
              service.supplier_id,

            link,

            quantity:
              String(
                quantity
              )
          });

        order.supplier_order_id =
          String(
            supplierResult.order ||
            supplierResult.id ||
            ""
          );

        await write(
          "orders",
          orders
        );

        return res.json({
          success: true,
          orderId:
            order.id,
          charge
        });

      } catch (
        supplierError
      ) {
        order.status =
          "supplier_error";

        user.balance =
          Number(
            (
              user.balance +
              charge
            ).toFixed(4)
          );

        await write(
          "orders",
          orders
        );

        await write(
          "users",
          users
        );

        return res.status(502).json({
          error:
            supplierError.message
        });
      }

    } catch (error) {
      console.error(
        "ORDER ERROR:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to create order."
      });
    }
  }
);


/* =========================
   ORDER HISTORY
========================= */

app.get(
  "/api/orders",
  authenticate,
  async (req, res) => {
    try {
      const orders =
        await read(
          "orders",
          []
        );

      return res.json(
        orders.filter(
          order =>
            order.user_id ===
            req.user.id
        )
      );

    } catch (error) {
      console.error(
        "ORDER HISTORY ERROR:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to load orders."
      });
    }
  }
);


/* =========================
   DEPOSITS
========================= */

app.post(
  "/api/deposits",
  authenticate,
  async (req, res) => {
    try {
      const amount =
        Number(
          req.body.amount
        );

      if (
        !amount ||
        amount <= 0
      ) {
        return res.status(400).json({
          error:
            "Enter a valid deposit amount."
        });
      }

      const deposits =
        await read(
          "deposits",
          []
        );

      const deposit = {
        id:
          await nextId(
            "deposits"
          ),

        user_id:
          req.user.id,

        amount,

        method:
          req.body.method ||
          "Manual",

        reference:
          req.body.reference ||
          "",

        status:
          "pending",

        created_at:
          new Date().toISOString()
      };

      deposits.unshift(
        deposit
      );

      await write(
        "deposits",
        deposits
      );

      return res.json({
        success: true,
        id:
          deposit.id
      });

    } catch (error) {
      console.error(
        "DEPOSIT ERROR:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to create deposit request."
      });
    }
  }
);


/* =========================
   ADMIN SUMMARY
========================= */

app.get(
  "/api/admin/summary",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const users =
        await read(
          "users",
          []
        );

      const orders =
        await read(
          "orders",
          []
        );

      const deposits =
        await read(
          "deposits",
          []
        );

      const revenue =
        orders.reduce(
          (
            total,
            order
          ) =>
            total +
            Number(
              order.charge ||
              0
            ),
          0
        );

      return res.json({
        users:
          users.length,

        orders:
          orders.length,

        pendingDeposits:
          deposits.filter(
            deposit =>
              deposit.status ===
              "pending"
          ).length,

        revenue
      });

    } catch (error) {
      console.error(
        "ADMIN SUMMARY ERROR:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to load admin dashboard."
      });
    }
  }
);


/* =========================
   ADMIN DEPOSITS
========================= */

app.get(
  "/api/admin/deposits",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const users =
        await read(
          "users",
          []
        );

      const deposits =
        await read(
          "deposits",
          []
        );

      return res.json(
        deposits.map(
          deposit => ({
            ...deposit,

            email:
              users.find(
                user =>
                  user.id ===
                  deposit.user_id
              )?.email ||
              ""
          })
        )
      );

    } catch (error) {
      console.error(
        "ADMIN DEPOSITS ERROR:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to load deposits."
      });
    }
  }
);


/* =========================
   APPROVE DEPOSIT
========================= */

app.post(
  "/api/admin/deposits/:id/approve",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const depositId =
        Number(
          req.params.id
        );

      const deposits =
        await read(
          "deposits",
          []
        );

      const deposit =
        deposits.find(
          item =>
            item.id ===
              depositId &&
            item.status ===
              "pending"
        );

      if (!deposit) {
        return res.status(404).json({
          error:
            "Pending deposit not found."
        });
      }

      deposit.status =
        "approved";

      await write(
        "deposits",
        deposits
      );

      const users =
        await read(
          "users",
          []
        );

      const user =
        users.find(
          item =>
            item.id ===
            deposit.user_id
        );

      if (!user) {
        return res.status(404).json({
          error:
            "User for this deposit was not found."
        });
      }

      user.balance =
        Number(
          (
            Number(
              user.balance ||
              0
            ) +
            Number(
              deposit.amount
            )
          ).toFixed(4)
        );

      await write(
        "users",
        users
      );

      return res.json({
        success:
          true
      });

    } catch (error) {
      console.error(
        "APPROVE DEPOSIT ERROR:",
        error
      );

      return res.status(50
