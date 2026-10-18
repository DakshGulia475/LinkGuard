import validateurl from "../utils/validateurl.js";
function checkUrl(req,res){
      const url=req.body.url;
      if(validateurl(url)===true){
           return res.status(200).json(
            {
              vaild:true,
              message:"URL format is vaild"
            }
           );
      }
      else {
          return res.status(400).json({
            vaild:false,
            message:"invalid url"
          })
      }
}
export {checkUrl};