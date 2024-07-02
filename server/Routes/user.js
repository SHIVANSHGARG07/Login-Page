import express from "express";
import bcrypt from "bcrypt";
import {User} from "../Models/User.js";
import jwt from "jsonwebtoken"
const router = express.Router();
import nodemailer from "nodemailer"
import dotenv from "dotenv"

router.post('/signup', async (req, res) => {
    const {  username, email, password} = req.body;

    if (!username ||  !email || !password ) {
        return res.json({ message: "All fields are required" });
    }

    try {
        // Check if the user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.json({ message: "User already exists" });
        }

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create a new user
        const newUser = new User({
            username,
            email,
            password: hashedPassword,
        });

        await newUser.save();

        return res.json({ status:true , message: "User created successfully" });
    } catch (error) {
        console.error(error);
        return res.json({ message: "Server error" });
    }
});

router.post('/login', async (req, res) => {
    const { email, password} = req.body;

    const user = await User.findOne({email});
    if(!user){
        return res.json({message:"User Not existed"});
    }
  const validpassword = await bcrypt.compare(password,user.password);
  if(!validpassword){
    return res.json({message:"password incorrect"})
  }
  const token = jwt.sign({username:user.username},process.env.KEY,{expiresIn:'1h'})
  res.cookie('token',token,{httpOnly:true,maxAge:360000})
  return res.json({status:true,message:"login successfully"})
});

router.post('/forgot',async(req,res)=>{
    const {email} = req.body;

    const user = await User.findOne({email});
    try{
        if(!user){
            return res.json({message:"user not registered"});
        }
        const token = jwt.sign({id: user._id},process.env.KEY,{expiresIn:'5m'})
        var transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
              user: 'shivanshgarg587@gmail.com',
              pass: 'vpey sfbh bstw cbaq'
            }
          });
          const encodedtoken = encodeURIComponent(token).replace(/\./g,"%2E")
          var mailOptions = {
            from: 'shivanshgarg587@gmail.com',
            to: email,
            subject: 'Reset Password',
            // text:`http://localhost:5173/resetpassword/${token}`
            text:`http://localhost:5173/resetpassword/${encodedtoken}`
          };
          
          transporter.sendMail(mailOptions, function(error, info){
            if (error) {
                return res.json({message:"error sending email"})
            } else {
              return res.json({status: true,message:'Email sent: ' });
            }
          });
    }catch(err){
        console.log(err);
    }
    
})

router.post('/reset/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body

  try {
    
    const decoded = await jwt.verify(token, process.env.KEY);
    const id = decoded.id;

    const hashedPassword = await bcrypt.hash(password, 10);

    await User.findByIdAndUpdate({_id:id}, { password: hashedPassword })

    return res.json({ status: true, message: "Password updated successfully" });
  } catch (err) {
    console.error(err);
    return res.json({ message: "Invalid or expired token" });
  }
});

const verifyuser =async (req,res,next)=>{
  try{
    const token = req.cookies.token;
    if(!token){
      return res.json({status:false,message:"no token"})
    }
    const decoded = await jwt.verify(token,process.env.KEY);
    next()
  }
  catch(err){
  return res.json(err);
  }
};

router.get('/verify',(req,res)=>{
  return res.json({status:true,message:"authorized"})
})

router.get('/logout',(req,res)=>{
  res.clearCookie('token');
  return res.json({status:true});
})




export { router as UserRouter };
