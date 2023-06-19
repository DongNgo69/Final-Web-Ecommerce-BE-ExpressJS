const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const crypto = require('crypto')
// Khai báo Schema
var userSchema = new mongoose.Schema({
    fullname:{
        type:String,
        required:true,
    },
    email:{
        type:String,
        required:true,
        unique:true,
    },
    mobile:{
        type:String,
        required:true,
        unique:true,
    },
    password:{
        type:String,
        required:true,
    },
    permission: {
        type:String,
        default:"user",
    },
    isBlocked: {
        type:Boolean,
        default:false,
    },
    cart: {
        type: Array,
        default: [],
    },
    address: {
        type: String,
    },
    wishlist:[{
        type: mongoose.Schema.Types.ObjectId, 
        ref: "Product"
    }],
    refreshToken: {
        type:String
    },
    passwordChangedAt: Date,
    passwordResetToken: String,
    passwordResetExpires: Date,
   
}, {
    timestamps: true,
});
//hashing password
userSchema.pre('save', async function(next){
    if (!this.isModified("password")){
        next()
    }
    const salt = await bcrypt.genSaltSync(10)
    this.password = await bcrypt.hash(this.password, salt)
    next()
})
//kiếm trả password
userSchema.methods.isPasswordMatched = async function(enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password)
}
userSchema.methods.createPasswordResetToken = async function () {
    const resetToken = crypto.randomBytes(32).toString('hex')
    this.passwordResetToken = crypto
        .createHash('sha256')
        .update(resetToken)
        .digest('hex')
    //passwordreset hết hạn
    this.passwordResetExpires = Date.now() + 30 * 60 * 1000 // 10 phút
    return resetToken
}
//Export the model
module.exports = mongoose.model('User', userSchema);