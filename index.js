import express from "express";
import session from "express-session";
import path from "path"
import bcrypt from "bcrypt";
import passport from "passport";
import passportLocal from "passport-local";

let users = [];
const app = express();

app.use(session({
  secret:process.env.SESSION_SECRET,
  resave:false,
  saveUninitialized:false
}));
app.use(express.json());
app.use(express.urlencoded({extended:true}));

app.use(passport.initialize());
app.use(passport.session());


passport.use(new passportLocal.Strategy({
    usernameField: "email"
}, async (email,password, done)=>{
  const user = users.find((user)=>user.email === email);

 if(user===undefined){
   return done(null,null, {message:"incorrect email"});
 }

 if(await bcrypt.compare(password,user.password)){
   return done(null,user);
 }

done(null,null,{message:"incorrect password"});
}));

passport.serializeUser((user,done) =>{
  done(null,user.id);
});

passport.deserializeUser((id,done) =>{
  done(null, users.find((user)=>user.id===id));  
});

app.get("/register",(req,res)=>{
  res.sendFile(path.resolve("views/register.html"));   
});

app.post("/register",async (req,res)=>{
  const {name,email,password } = req.body;

  const hashedPwd = await bcrypt.hash(password,10);
  users.push({
   id:`${Date.now()}_${Math.random()}`,
   name:name,
   email:email,
   password:hashedPwd
  });
  res.redirect("/login");
});

app.get("/login",(req,res)=>{
  res.sendFile(path.resolve("views/login.html")); 
});

app.post("/login",passport.authenticate('local',{
  successRedirect:"/",
  failureRedirect:"/login"
}));

app.get("/",checkAuthentication,(req,res)=>{
  res.send("Welocme To Our Application!");
});

function checkAuthentication(req,res,next){
  if(req.isAuthenticated() === false){
    return res.redirect("/login");
  }
  next();
}
app.listen(process.env.PORT);
