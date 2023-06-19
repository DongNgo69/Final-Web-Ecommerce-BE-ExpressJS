const mongoose = require('mongoose'); 


var couponSchema = new mongoose.Schema({
    title:{
        type:String,
        required:true,
    },
    expiry:{
        type:Date,
        required:true,
    },
    discount:{
        type:Number,
        required:true,
    },
},
{
    timestamps: true
}
);

//Export the model
module.exports = mongoose.model('Coupon', couponSchema);