import User from "../models/user.js";
import bcrypt from "bcrypt";
const registerUser = async (req, res) => {
    try {
        // 1. Extract email and password from req.body
          const email=req.body.email;
          const password=req.body.password;
          // not empty and valid format
        if (
    typeof email !== "string" ||
    typeof password !== "string" ||
    !email.trim() ||
    !password
   ) {
    return res.status(400).json({
        message: "Email and password are required"
    });
    } 
    // normalize email
        const normalizedEmail=email.trim().toLowerCase();
        // password length check
         if (password.length < 8) {
    return res.status(400).json({
        message: "Password must be at least 8 characters long"
    });
}
         if (Buffer.byteLength(password, "utf8") > 72) {
    return res.status(400).json({
        message: "Password cannot exceed 72 bytes"
    });
} 
       // valid email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
         if (!emailRegex.test(normalizedEmail)) {
    return res.status(400).json({
        message: "Invalid email format"
    });
}
        // user already exists
        const existingUser = await User.findOne({
    email: normalizedEmail
});
     if(existingUser){
        return res.status(409).json({
             message:"email already registered"
        });
     }
      // hash 
      const passwordHash = await bcrypt.hash(password, 12);
      // create user
      const newuser= await User.create({
            email:normalizedEmail,
            passwordHash:passwordHash
      });
      return res.status(201).json(
        {
           message:"user registeration successfull",
           user:{
              id:newuser._id,
              email: newuser.email
           }
        }
      );
    }
    catch (error) {
        // Handle errors
         if (error.code === 11000) {
        return res.status(409).json({
            message: "Email already registered"
        });
    }

    console.error("Registration error:", error);

    return res.status(500).json({
        message: "Internal server error"
    });
    }
};
export {registerUser};
