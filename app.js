require("dotenv").config();
const http = require("http");
const express = require("express");
const PORT = process.env.PORT || 4000;
const { Client } = require("pg");
const cors = require("cors");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const { error } = require("console");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
let tokenSecreat =
  "4233d702105f11041081e9aacd786076f8de2f4f33db08d5125e50397e31f890";
const client = new Client({
  connectionString:
    "postgresql://neondb_owner:npg_K4OVGyc1rEaN@ep-morning-fog-a536ioyx-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require",
  ssl: {
    rejectUnauthorized: false, // Required for Neon
  },
});
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "Sattakingspinner@gmail.com",
    pass: "gpxc rjti wqbs wcis",
  },
});
client
  .connect()
  .then(() => console.log("✅ Connected to Neon PostgreSQL"))
  .catch((err) => console.error("❌ Connection error", err.stack));

module.exports = client;

const app = express();
app.use(cors());
const server = http.createServer(app);
app.use(express.json());
app.use((req, res, next) => {
  console.log("req.protocol", req.protocol);
  req.domain = req.protocol + "://" + req.get("host");

  next();
});
const authenticateToken = (request, response, next) => {
  let mastiToken;
  const authHeader = request.headers["authorization"];
  console.log("authHeader", authHeader);
  if (authHeader !== undefined) {
    mastiToken = authHeader.split(" ")[1];
  }
  if (mastiToken === undefined) {
    response.status(401);
    response.send("Invalid JWT Token");
  } else {
    jwt.verify(mastiToken, tokenSecreat, async (error, payload) => {
      if (error) {
        response.status(401);
        response.send("Invalid JWT Token");
      } else {
        console.log(payload);
        request.email = payload.email;
        request.id = payload.id;
        next();
      }
    });
  }
};
app.post("/register", async (req, res) => {
  const { name, password, confirmPassword, email } = req.body;
  const text = "SELECT * from users WHERE email = $1";
  const result = await client.query(text, [email]);
  if (result.rowCount != 0) {
    return res.status(400).send({ error: "Email already exists" });
  } else if (password != confirmPassword) {
    return res
      .status(400)
      .send({ error: "password and confirm password do not match" });
  } else {
    const text = "INSERT INTO users (name, email, password) VALUES ($1, $2,$3)";
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await client.query(text, [name, email, hashedPassword]);
    token = crypto.randomBytes(20).toString("hex");
    const verifyLink = `${req.domain}/verify?token=${token}`;

    const mailOptions = {
      from: "Sattakingspinner@gmail.com",
      to: email,
      subject: "Verify Account",
      text: `Click the link to verify your account: ${verifyLink}. this link expires in 1 hour`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error("Error sending email:", error);
        res.status(500).send("Error sending email");
      } else {
        console.log("Email sent:", info.response);
        // res.send("Email sent successfully");
      }
    });
    await client.query("insert into verify (token,email) values ($1,$2)", [
      token,
      email,
    ]);
    return res.status(201).send({ message: "User created successfully" });
  }
  //   console.log(result);
  //   res.send(result);
});

app.get("/verify", async (req, res) => {
  const { token } = req.query;
  const result = await client.query("select * from verify where token=$1", [
    token,
  ]);
  if (result.rowCount == 0) {
    return res.status(400).send({ error: "Invalid token" });
  } else {
    await client.query("update users set verified=true where email=($1)", [
      result.rows[0].email,
    ]);
    await client.query("delete from verify where token=$1", [token]);
    return res.status(200).send({ message: "Account verified successfully" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const result = await client.query("select * from users where email=$1", [
    email,
  ]);
  if (result.rowCount == 0) {
    return res.status(400).send({ error: "user not found" });
  } else {
    const isPasswordMatched = await bcrypt.compare(
      password,
      result.rows[0].password
    );
    if (isPasswordMatched === true) {
      const payload = {
        email: result.rows[0].email,
        name: result.rows[0].name,
        id: result.rows[0].id,
      };
      const jwtToken = jwt.sign(payload, tokenSecreat);
      res.send({ token: jwtToken });
    } else {
      return res.status(401).send({ error: "invalid password" });
    }
  }
});

app.get("/details", authenticateToken, async (req, res) => {
  console.log("called");
  const email = req.email;
  console.log(email);
  const result = await client.query("select * from users where email=$1", [
    email,
  ]);
  const tasks = await client.query("select * from tasks where userid=$1", [
    req.id,
  ]);
  console.log();
  return res.status(200).send({ ...result.rows[0], tasks: tasks.rows });
});

app.post("/addTask", authenticateToken, async (req, res) => {
  const { task } = req.body;
  let id = uuidv4();
  console.log([id, task, "pending", req.id]);
  try {
    await client.query(
      "insert into  tasks (id,task,status,userid) values ($1,$2,$3,$4)",
      [id, task, "pending", req.id]
    );
    return res.status(200).send({ message: "created task successfully", id });
  } catch (e) {
    console.log(e);
    res.status(500).send(`internal server error ${e}`);
  }
});

app.put("/editTask", authenticateToken, async (req, res) => {
  const { task, status, id } = req.body;
  try {
    await client.query("update  tasks set status=$1 ,task=$2 where id=$3", [
      status,
      task,
      id,
    ]);
    return res.status(200).send({ message: "task updated successfully" });
  } catch (e) {
    console.log(e);
    res.status(500).send(`internal server error ${e}`);
  }
});

app.delete("/deleteTask", authenticateToken, async (req, res) => {
  const { id } = req.body;
  try {
    await client.query("delete from tasks where id=$1", [id]);
    return res.status(200).send({ message: "task deleted successfully" });
  } catch (e) {
    console.log(e);
    res.status(500).send(`internal server error ${e}`);
  }
});
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`); 
});  
 