import { generateToken } from "../lib/utils.js";
import User from "../models/user.model.js";
import bcrypt from "bcryptjs"

export const signup =async (req,res)=>{
    const{fullname,email,password} = req.body
    try {

        if(!fullname || !email || !password){
            return res.status(400).json({massage:"Please fill all fields"});
        }

        if(password.length < 6){
            return res.status(400).json({massage:"password must be at least 6 characters"});
        }
        const user= await User.findOne({email})
        
        if(user) return res.status(400).json({message:"Email already exists"});

        const salt = await bcrypt.genSalt(10)
        const hashedPassword = await bcrypt.hash(password,salt)

        const newUser = new User({
            fullname,
            email,
            password:hashedPassword
        })

        if(newUser){
            generateToken(newUser._id,res)
            await newUser.save();

            res.status(201).json({
                _id:newUser._id,
                fullname:newUser.fullname,
                email:newUser.email,
                profilepic:newUser.profilepic,

            });

        }else{
            res.status(400).json({message:"Invalid user data"});
        }

    } catch (error) {
     
        console.log("Error in signup controller",error.message);
        res.status(500).json({massage:"Internal Server Error"});
    }
};
export const login = async(req,res)=>{
    const {email, password}=req.body
   try{
    const user = await User.findOne({email})

    if(!user){
        return res.status(400).json({message:"Invalid Login"});
    }

    const isPasswordCorrect = await bcrypt.compare(password,user.password);
    if(!isPasswordCorrect){
        return res.status(400).json({message:"Invalid Password"})
    }
     generateToken(user._id,res)

     res.status(200).json({
        _id:user._id,
        fullname:user.fullname,
        email:user.email,
        profilepic:user.profilepic,
     })


   }catch (error){
     console.log("Error in login controller",error.massage);
     res.status(500).json({message:"Internal server Error 2"})
   }
};
export const logout = (req,res)=>{
    try{
        res.cookie("jwt","",{maxAge:0})
        res.status(200).json({message:"Logout successfully"});
    }catch (error){
          console.log("Error in logout controller",error.message);
          res.status(500).json({message:"Internal Server error 3"})
    }
};

export const updateProfile = async(req,res)=>{};