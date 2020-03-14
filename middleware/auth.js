const jwt = require("jsonwebtoken")
const config = require("config")

module.exports = (req,res,next)=>{
    const token = req.header('x-auth-token')
    if(!token){
        return res.status(401).send({msg:'please authenticate'})
    }
    try{
        const decoded = jwt.verify(token,config.get('JWTSECRET'))
        req.user = decoded.user
        next()
    }catch{
        res.status(401).json({msg:'authentication failed'})
    }
}