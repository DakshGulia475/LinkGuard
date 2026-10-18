function validateurl(input){
   // input not string or empty
   if(typeof input !=="string"|| input.trim()==="") return false;  
   try{
     const parsedurl= new URL(input);
     if(parsedurl.protocol!=="http:"&&parsedurl.protocol!=="https:") return false;
     return true;
   } catch{
      return false;
   }
}
export default validateurl;