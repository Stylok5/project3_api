 const errorHandler = (err,req,res,next) => {
    
     if ( err.name === "JsonWebTokenError"){
        return res.status(403).json( { message: "Invalid Token"})
     }
    if (err.name === "CastError"){
    return res.status(400).json({message: "Wrong input"})
  }
   console.log(err)
    return res.status(500).json({message: "Internal server error"})

 }

 export default errorHandler;