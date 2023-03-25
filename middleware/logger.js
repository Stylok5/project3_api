const logger = async (req,res,next) => {
    console.log(` ${req.method} Request received at ${req.url}`);
      if (Object.keys(req.body).length) {
        console.log('Request body: ', req.body);
      }
    next()
}
export default logger;