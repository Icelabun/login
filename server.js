var express = require("express");
var mongoose = require("mongoose");
var bodyParser = require("body-parser");
var session = require("express-session");
var cookieParser = require("cookie-parser");
var bcrypt = require("bcrypt");

var app = express();

// ✅ Connect to MongoDB
mongoose
  .connect("mongodb+srv://sinit:@tesfaye42@cluster0.1ttll.mongodb.net/Mern?retryWrites=true&w=majority&appName=Cluster0")
  .then(() => console.log("✅ MongoDB connected successfully"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// ✅ Create User Schema & Model (with Email & Password Hashing)
var userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
});

// Hash password before saving to database
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

var User = mongoose.model("User", userSchema);

app.set("view engine", "pug");
app.set("views", "./views");

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(
  session({
    secret: "Your secret key",
    resave: false,
    saveUninitialized: true,
  })
);

// ✅ Signup Route
app.get("/signup", function (req, res) {
  res.render("signup");
});

app.post("/signup", async function (req, res) {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.render("signup", { message: "All fields are required!" });
  }

  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.render("signup", { message: "Username or Email already exists!" });
    }

    const newUser = new User({ username, email, password });
    await newUser.save(); // ✅ Save user to database
    req.session.user = newUser;
    res.redirect("/protected_page");
  } catch (err) {
    console.error("❌ Error saving user:", err);
    res.render("signup", { message: "Error registering user. Try again!" });
  }
});

// ✅ Login Route
app.get("/login", function (req, res) {
  res.render("login");
});

app.post("/login", async function (req, res) {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.render("login", { message: "Please enter both username and password" });
  }

  try {
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.render("login", { message: "Invalid credentials!" });
    }

    req.session.user = user;
    res.redirect("/protected_page");
  } catch (err) {
    console.error("❌ Error during login:", err);
    res.render("login", { message: "Error logging in." });
  }
});

// ✅ Protected Page Middleware
function checkSignIn(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    res.redirect("/login");
  }
}

app.get("/protected_page", checkSignIn, function (req, res) {
  res.render("protected_page", { username: req.session.user.username });
});

// ✅ Logout Route
app.get("/logout", function (req, res) {
  req.session.destroy(() => {
    console.log("User logged out.");
    res.redirect("/login");
  });
});

// Start Server
app.listen(3000, function () {
  console.log("✅ Server is running on port 3000");
});
