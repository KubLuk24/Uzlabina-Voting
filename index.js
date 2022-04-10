const express = require("express")
const app = express();
const ejs = require("ejs");
const bodyparser = require('body-parser')
const cookieParser = require('cookie-parser');
const mysql = require("mysql2")
const crypto = require("crypto")
const fs = require("fs")
const multer = require('multer')
const chunk = require("chunk");
const {render} = require("ejs");
const config = require("./config.json")
const upload = multer({dest: './uploads/', storage: multer.memoryStorage()})

const con = mysql.createConnection(config.db);

con.connect(function (err) {
    if (err) throw err;
    console.log("Connected to mysql!");
});

con.query("CREATE TABLE IF NOT EXISTS etwinning (username VARCHAR(40), password TEXT, permissions VARCHAR(32));")
con.query("CREATE TABLE IF NOT EXISTS logs (usename VARCHAR(40), action VARCHAR(32), id TEXT, time VARCHAR(50));")
con.query("CREATE TABLE IF NOT EXISTS likes (username VARCHAR(40), id TEXT);")


app.use(cookieParser());
app.set("view engine", "ejs");
app.use("/assets", express.static('assets'));
app.use("/uploads", express.static('uploads'));
app.use(bodyparser.json());
app.use(bodyparser.urlencoded({extended: true}));

app.get("/", (req, res) => {
    if (req.cookies['_MDPLX_SECURITY_TOKEN']) return res.render(__dirname + "/views/login.ejs", {autoLogin: true})
    res.render(__dirname + "/views/login.ejs", {autoLogin: false})
})

app.post("/fileUpload", upload.single('file'), async (req, res) => {
    if (!req.cookies['_MDPLX_SECURITY_TOKEN']) return res.status(403).send("403 Forbidden")
    if (!req.file) return res.redirect("/list");
    con.query("SELECT * FROM etwinning WHERE password = ?", [req.cookies['_MDPLX_SECURITY_TOKEN']], async (err, result) => {
        if (result.length !== 0) {
            const suffix = "." + req.file.mimetype.split("/")[1].replace("e", "");
            const filename = crypto.randomBytes(32).toString("hex") + suffix;
            con.query("INSERT INTO logs (usename, action, id, time) values (?, ?, ?, ?)", [result[0].username, "Image Upload", filename, new Date()], async (err, result2) => {
                fs.writeFile("./uploads/" + filename, req.file.buffer, (err) => {
                    if (err) return res.send("An error occured trying to save that file.");
                    res.redirect("/list")
                })
            })

        } else {
            res.redirect("/");
        }
    });
})

app.get("/list", async (req, res) => {
    if (!req.cookies['_MDPLX_SECURITY_TOKEN']) return res.redirect("/")

    con.query("SELECT * FROM etwinning WHERE password = ?", [req.cookies['_MDPLX_SECURITY_TOKEN']], async (err, result) => {
        if (result.length === 0) return res.redirect("/")
        con.query("SELECT * FROM logs", async (err, rsl) => {
            con.query("SELECT * FROM likes", async (err, likeArray) => {
                const files = fs.readdirSync("./uploads");
                const images = [];

                files.forEach(file => {
                    const entry = rsl.filter(function (entry) {
                        return entry.id === file;
                    })[0];
                    images.push({
                        file: "/uploads/" + file,
                        user: entry.usename,
                        time: entry.time,
                        likes: likeArray.filter(function (entry) {
                            return entry.id === file;
                        }).length,
                        liked: likeArray.filter(function (entity) {
                            return entity.id === file && entity.username === result[0].username;
                        }).length
                    });
                })

                const renderChunks = chunk(images, 3);


                res.render(__dirname + "/views/list.ejs", {chunks: renderChunks, user: result[0]});
            })
        })
    })


})

app.get("/:id/vote", async (req, res) => {
    if (!req.cookies['_MDPLX_SECURITY_TOKEN']) return res.redirect("/")

    con.query("SELECT * FROM etwinning WHERE password = ?", [req.cookies['_MDPLX_SECURITY_TOKEN']], async (err, result) => {
        if (result.length === 0) return res.redirect("/")

        con.query("SELECT * FROM likes WHERE id = ?", [req.params.id], async (err, userVoteArray) => {
            if (userVoteArray.length === 0) {
                con.query("INSERT INTO likes (username, id) VALUES (?, ?)", [result[0].username, req.params.id], async (err, insert) => {
                    res.redirect("/list");
                })
            } else {
                con.query("DELETE FROM likes WHERE id = ? AND username = ?", [req.params.id, result[0].username], async (err, insert) => {
                    res.redirect("/list");
                })
            }
        })
    })
})

app.get("/permhandle", async (req, res) => {
    if (req.cookies['_MDPLX_SECURITY_TOKEN']) {
        setTimeout(() => {
            con.query("SELECT * FROM etwinning WHERE password = ?", [req.cookies['_MDPLX_SECURITY_TOKEN']], async (err, result) => {
                if (result.length === 0) {
                    res.send("Your login details either changed or are no longer available.")
                } else {
                    res.send("Success")

                }
            })
        }, 1500)
    } else {
        res.status(403).send("Access forbidden")
    }
})

app.post("/", (req, res) => {
    const passwd = crypto.createHash('SHA512').update(req.body.password).digest('hex');
    con.query("SELECT * FROM etwinning WHERE username = ? AND password = ?", [req.body.username, passwd], async (err, result) => {
        if (result.length === 0) {
            res.send("NO")
        } else {
            res.cookie('_MDPLX_SECURITY_TOKEN', passwd)
            res.redirect("/list")
        }
    })
})

app.listen(config.port, () => {
    console.log("Server ready.")
})