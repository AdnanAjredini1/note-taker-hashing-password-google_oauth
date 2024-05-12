import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import env from "dotenv";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";


env.config();

const app = express();
const port = process.env.PORT || 4000 || 4040 || 3003 || 5000;
const saltRounds = parseInt(process.env.SALT_ROUNDS);

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/note", async (req, res) => {
  console.log(req.user);
  if (req.isAuthenticated()) {
    const result = await db.query("SELECT * FROM notes WHERE user_email = $1", [
      req.user.email,
    ]);
    const notes = result.rows;
    res.render("index.ejs", { notes: notes });
  } else {
    res.redirect("/login");
  }
});

app.get("/new", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("new");
  } else {
    res.redirect("/login");
  }
});

app.get("/notes/:id", async (req, res) => {
  const id = req.params.id;
  console.log(id);
  try {
    const note = await db.query("SELECT * FROM notes WHERE id = $1", [id]);
    res.render("show", { note: note.rows[0] });
  } catch (error) {
    console.log(error);

    res.status(500).send("Internal Server Error");
  }
});

app.get("/edit/:id", async (req, res) => {
  const id = req.params.id;
  try {
    const note = await db.query("SELECT * FROM notes WHERE id = $1", [id]);
    res.render("edit", { note: note.rows[0] }); // Added the missing closing parenthesis here
  } catch (error) {
    console.log(error);
    res.status(500).send("Internal Server Error");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/note",
    failureRedirect: "/login",
  })
);

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) console.log(err);
    res.redirect("/");
  });
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    const CheckResult = await db.query("SELECT * FROM users WHERE email = $1", [
      username,
    ]);

    if (CheckResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      // Password hashing
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.log("Error hashing password", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [username, hash]
          );
          const user = result.rows[0];

          req.login(user, (err) => {
            console.log(err);
            res.redirect("/note");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/note",
    failureRedirect: "/login",
  })
);

app.post("/new", async (req, res) => {
  const { title, content } = req.body;
  try {
    await db.query(
      "INSERT INTO notes (title, content,user_email) VALUES ($1, $2, $3)",
      [title, content, req.user.email]
    );
    res.redirect("/note");
  } catch (err) {
    console.log(err);
  }
});

app.post("/edit/:id", async (req, res) => {
  const id = req.params.id;
  const { title, content } = req.body;
  try {
    await db.query(
      "UPDATE notes SET title = $1, content = $2 WHERE id = $3 ;",
      [title, content, id]
    );
    res.redirect("/note");
  } catch (error) {
    console.log(error);
  }
});

app.post("/delete/:id", async (req, res) => {
  const id = req.params.id;
  try {
    await db.query("DELETE FROM notes WHERE id = $1 ", [id]);
    res.redirect("/note");
  } catch (error) {
    console.log(error);
  }
});

passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    console.log(username, password);
    try {
      const CheckResult = await db.query(
        "SELECT * FROM users WHERE email = $1",
        [username]
      );
      if (CheckResult.rows.length > 0) {
        const user = CheckResult.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(
          password,
          storedHashedPassword,
          async function (err, result) {
            if (err) {
              return cb(err);
            } else {
              if (result) {
                return cb(null, user);
              } else {
                return cb(null, false, { message: "Incorrect password" });
              }
            }
          }
        );
      } else {
        return cb("User not found");
      }
    } catch (err) {
      return cb(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "https://note-taker-ghaf.onrender.com/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      console.log(profile);
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});
