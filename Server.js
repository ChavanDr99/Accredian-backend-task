import express from "express";
import mysql from 'mysql';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import cookieParser from "cookie-parser";
import jwt from 'jsonwebtoken'
// import jwt from 'jsonwebtoken'

const saltRounds = 10;

const app = express();
app.use(express.json());
app.use(cors({
   origin:["http://localhost:5173"],
   methods:["Post","Get"],
   credentials:true
}));
app.use(cookieParser());

// Use Online Xampp Mysql
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "", 
  database: "signup"
});
const verifyUser = (req,res,next)=>{
   const token =req.cookies.token;
   if(!token){
      return res.json({ error: "you are not authorized" })
   }
   else{
      jwt.verify(token,"jwt-secret-key",(err,decoded)=>{
         if(err){
            return res.json({ error: "token not okay" })
         }
         else{
            req.name=decoded.name;
            next();
         }
      })
   }
}

db.connect(err => {
  if (err) {
    console.error('Error connecting to database:', err);
    return;
  }
  console.log("Connected to the database");
});

app.get('/',verifyUser,(req,res)=>{
return res.json({Status:"Success",name:req.name})
})

app.post('/register', async (req, res) => {
   const { name, email, password, confirmPassword } = req.body;
 
   if (!name || !email || !password || !confirmPassword) {
     return res.status(400).send({ error: "All fields are required" });
   }
 
   if (password !== confirmPassword) {
     return res.status(400).send({ error: "Passwords do not match" });
   }
 
   const checkExistingUserQuery = 'SELECT * FROM signup WHERE Email = ?';
   db.query(checkExistingUserQuery, [email], async (err, results) => {
     if (err) {
       return res.status(500).json({ error: 'Database error' });
     }
 
     if (results.length > 0) {
       return res.status(200).json({ success: true, message: "Already registered, please login" });
     }
 
     try {
       const hashedPassword = await bcrypt.hash(password, 10);
 
       const insertUserQuery = 'INSERT INTO signup (Name, Email, Password) VALUES (?, ?, ?)';
       db.query(insertUserQuery, [name, email, hashedPassword], (err, result) => {
         if (err) {
           return res.status(500).json({ message: 'Error creating user' });
         }
 
         return res.status(201).json({ message: 'User created successfully' });
       });
     } catch (hashError) {
       return res.status(500).json({ error: 'Error hashing password' });
     }
   });
 });
 
 app.post('/login', async (req, res) => {
   const userEmail = req.body.email; 
   console.log('Email received:', userEmail);
 
   const sql = 'SELECT * FROM signup WHERE Email = ?';
   db.query(sql, [userEmail], (err, data) => {
     if (err) {
       console.error('Database error:', err);
       return res.status(500).json({ error: 'Login error' });
     }
 
     if (data.length > 0) {
       bcrypt.compare(req.body.password.toString(), data[0].Password, (err, response) => {
         if (err) {
           console.error('Bcrypt comparison error:', err);
           return res.status(500).json({ error: 'Password comparison error' });
         }
         if (response) {
            const name = data[0].Name
            const token = jwt.sign({name},"jwt-secret-key",{expiresIn:"1d"});
            res.cookie('token',token)
           return res.json({ Status: "Success" , name});
         } else {
           return res.json({ Status: "Password does not match" });
         }
       });
     } else {
       console.log('User not found for email:', userEmail);
       return res.status(404).json({ error: 'User not found' });
     }
   });
 });
 
app.get('/logout',(req,res)=>{
   res.clearCookie('token')
   return res.json({Status:"success"})
})

app.listen(8081, () => {
  console.log("Server running on port 8081");
});
