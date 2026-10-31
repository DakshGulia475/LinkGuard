import mongoose from "mongoose";
const UserSchema= new mongoose.Schema(
    // fields
    // id,created at and updated at are created by itself
  { 
      
      email:{
        type:String,
        required:true,
        unique:true,
        lowercase:true,
        trim:true
      },

      passwordHash:{
        type:String,
        required:true,
        select:false
      }


  },
  // schmema options
  {
    timestamps:true
  }
);
// create model
const User= mongoose.model("User",UserSchema);
export default User;