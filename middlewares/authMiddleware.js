const User = require('../models/userModel')
const jwt = require('jsonwebtoken')
const asyncHandler = require('express-async-handler')


const authMiddleware = asyncHandler( async (req, res, next) => {
    let token;
    if(req?.headers?.authorization?.startsWith("Bearer")){
        token = req.headers.authorization.split(" ") [1]
        try{
            if(token){
                const decoded = jwt.verify(token, process.env.JWT_SECRET)
                const user = await User.findById(decoded?.id)
                req.user = user
                next()
            }
        }catch(e){
            throw new Error('Not authorized token expired, please try again')
        }
    }else {
        throw new Error ('There is no token attached to header')
    }
})

const isAdmin = asyncHandler(async (req, res, next) => {
    const {email} = req.user
    const adminUser = await User.findOne({email})
    if(adminUser.permission !== "admin") {
        throw new Error ('Bạn không phải admin')
    } else {
        next();
    }
    
})
module.exports = {
    authMiddleware,
    isAdmin
}