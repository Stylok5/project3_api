const fallback = (req,res,next) => {
    return res.status(404).json({message: "There is no endpoint under this address"})
}
export default fallback;