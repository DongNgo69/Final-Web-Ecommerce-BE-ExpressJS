const { generateToken } = require('../config/jwtToken');
const { generateRefreshToken } = require('../config/refreshToken');

//import model
const User = require('../models/userModel')
const Product = require('../models/productModel')
const Cart = require('../models/cartModel')
const Order = require('../models/orderModel')
const Coupon = require('../models/couponModel')

const asyncHandler = require('express-async-handler');
const validateMongoDBId = require('../utils/validateMongodbId');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const uniqid = require('uniqid') //tạo id thập lục phân
const { sendEmail } = require('./emailController')
//register
const createUser = asyncHandler(async (req, res) => {
    const email = req.body.email
    const findUser = await User.findOne({ email: email })
    if (!findUser) {
        const newUser = await User.create(req.body)
        res.json(newUser)
    } else {
        throw new Error("Email người dùng đã tồn tại")
    }
})

//login
const loginUser = asyncHandler(async (req, res) => {
    const {email, password} = req.body
    //check đăng nhập
    const findUser = await User.findOne({ email })
    if (findUser && (await findUser.isPasswordMatched(password))){
        const refreshToken = await generateRefreshToken(findUser?._id)
        const updateUser = await User.findByIdAndUpdate(
            findUser.id,
            {    
                refreshToken : refreshToken,
            }, {
                new: true
            }
        )
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            maxAge:72 * 60 * 60 * 1000
        })    
        res.json({
            _id: findUser?._id,
            fullname: findUser?.fullname,
            email: findUser?.email,
            mobile: findUser?.mobile,
            token: generateToken(findUser?._id),
    })
    } else {
        throw new Error("Thông tin không hợp lệ")
    }
})

// Xử lý refreshtoken
const handlerRefreshToken = asyncHandler( async (req, res) => {
    const cookie = req.cookies
    if(!cookie?.refreshToken) throw new Error("No refresh Token in Cookies")
    const refreshToken = cookie.refreshToken
    const user = await User.findOne({refreshToken})
    if (!user) throw new Error("No refresh Token in db or not matchesd")
    jwt.verify(refreshToken, process.env.JWT_SECRET, (err, decoded) => {
        if(err || user.id !== decoded.id){
            throw new Error ("Có lỗi xảy ra khi refresh Token")
        }
        const accessToken = generateToken(user?._id)
        res.json({ accessToken })
    })
})

// login ADmin
const loginAdmin = asyncHandler(async (req, res) => {
    const {email, password} = req.body
    //check  admin đăng nhập
    const findAdmin = await User.findOne({ email })
    if (findAdmin.permission !== "admin") throw new Error("Xác minh không thành công");
    if (findAdmin && (await findAdmin.isPasswordMatched(password))){
        const refreshToken = await generateRefreshToken(findAdmin?._id)
        const updateUser = await User.findByIdAndUpdate(
            findAdmin.id,
            {    
                refreshToken : refreshToken,
            }, {
                new: true
            }
        )
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            maxAge:72 * 60 * 60 * 1000
        })    
        res.json({
            _id: findAdmin?._id,
            fullname: findAdmin?.fullname,
            email: findAdmin?.email,
            mobile: findAdmin?.mobile,
            token: generateToken(findAdmin?._id),
    })
    } else {
        throw new Error("Thông tin không hợp lệ")
    }
})

//logout
const logoutUser = asyncHandler(async (req, res) => {
    const cookie = req.cookies
    if(!cookie?.refreshToken) throw new Error("No refresh Token in Cookies")
    const refreshToken = cookie.refreshToken
    const user = await User.findOne({ refreshToken })
    if(!user){
        res.clearCookie("refreshToken", {
            httpOnly: true,
            secure: true
        })
        return res.sendStatus(204) //forbiden
    }
    await User.findOneAndUpdate({refreshToken}, {
        refreshToken: ""
    })
    res.clearCookie("refreshToken", {
        httpOnly: true,
        secure: true
    })
    res.sendStatus(204)
})

//Get all user
const getallUser = asyncHandler(async (req, res) => {
    try {
        const getUsers = await User.find().populate("wishlist")
        res.json(getUsers)
    } catch (e){
        throw new Error(e)
    }
})

//Get one user
const getaUser = asyncHandler(async (req, res) => {
    const { id } = req.params
    validateMongoDBId(id)
    try{
        const getUsers = await User.findById(id)
        res.json({
            getUsers
        })
    }catch(e){
        throw new Error(e)
    }
})

//DeleteUser
const deleteaUser = asyncHandler(async (req, res) => {
    const { id } = req.params
    validateMongoDBId(id)
    try{
        const deletedUser = await User.findByIdAndDelete(id)
        res.json({
            deletedUser
        })
    }catch(e){
        throw new Error(e)
    }
})

//UpdateUser by Client
const updateaUser = asyncHandler(async (req, res) => {
    const { _id } = req.user
    validateMongoDBId(_id)
    try{
        const updatedUser = await User.findByIdAndUpdate(
        _id,
         {
            fullname: req?.body.fullname,
            email: req?.body.email,
            mobile: req?.body.mobile,
        },
        {
            new: true,
        })
        res.json(updatedUser)
    } catch (e){
        throw new Error(e)
    }
})

//Block user
const blockUser = asyncHandler(async (req, res) => {
    const {id} = req.params
    validateMongoDBId(id)
    try {
        const blockUser = await User.findByIdAndUpdate(
            id, 
            {
                isBlocked:true,
            },
            {
                new:true,
            }
        )
        res.json(blockUser)
    }catch (e) {
        throw new Error(e);
    }
})

const unblockUser = asyncHandler(async (req, res) => {
    const {id} = req.params
    validateMongoDBId(id)
    try {
        const unblockUser = await User.findByIdAndUpdate(
            id, 
            {
                isBlocked:false,
            },
            {
                new:true,
            }
        )
        res.json(unblockUser)
    }catch (e) {
        throw new Error(e);
    }
})

//đổi mật khẩu
const updatePassword = asyncHandler(async (req, res) => {
    const { _id } = req.user
    const {password} = req.body
    validateMongoDBId(_id)
    const user = await User.findById(_id)
    if (password) {
        user.password = password
        const updatePassword = await user.save()
        res.json(updatePassword)
    } else {
        res.json(user)
    }
})

const forgotPasswordToken = asyncHandler(async(req, res) => {
    const { email } = req.body
    const user = await User.findOne({ email })
    if(!user) throw new Error('Email không tồn tại trên hệ thống')
    try{
        const token = await user.createPasswordResetToken();
        await user.save()
        const resetURL = `Bấm vào link để đặt lại mật khẩu của bạn. Link sẽ vô hiệu sau 10 phút! 
                        <a href='http://localhost:3000/reset-password/${token}'>
                        Bấm vào đây</a>`
        const data = {
            to: email,
            text: "Hey User",
            subject: 'Link lấy lại mật khẩu.',
            htm: resetURL,
        }
        sendEmail(data)
        res.json(token)
    }catch (e){
        throw new Error(e)
    }
})

//quên mật khẩu
const resetPassword = asyncHandler(async (req, res) => {
    const {password} = req.body
    const { token } = req.params
    const hashedToken = crypto
        .createHash('sha256')
        .update(token)
        .digest("hex")
    const user = await User.findOne({
        passwordResetToken: hashedToken,
        passwordResetExpires: {
            $gt: Date.now()
        } 
    })
    if(!user) throw new Error('Token đã hết hạn, vui lòng thử lại')
    user.password = password
    user.passwordResetToken = undefined
    user.passwordResetExpires = undefined
    await user.save()
    res.json(user)
})

//lấy danh sách wishlist
const getWishlist = asyncHandler(async (req, res) => {
    const { _id } = req.user
    try{
        const findUser = await User.findById(_id).populate('wishlist')
        res.json(findUser)
    } catch (e){
        throw new Error(e)
    }
})

//lưu địa chỉ người dùng
const saveAddress = asyncHandler(async (req, res) => {
    const { _id } = req.user
    validateMongoDBId(_id)
    try{
        const updateUser = await User.findByIdAndUpdate (
            _id,
            {
                address: req?.body?.address,
            },
            {
                new: true
            }
        )
        res.json(updateUser)
    } catch (e) {
        throw new Error(e)
    }
})
//xử lý giỏ hàng
const userCart = asyncHandler (async (req, res) => {
    const { productId, color, quantity, price     } = req.body
    const { _id } = req.user
    validateMongoDBId(_id)
    try {
        
          //xuất ra cart mới
        let newCart = await new Cart({
            userId:_id,
            productId,
            color,
            price,
            quantity,
        }).save();
        res.json(newCart);
    }catch (e){
        throw new Error(e)
    }
})

//xem giỏ hàng
const getUserCart = asyncHandler(async (req, res) => {
    const { _id } = req.user;
    validateMongoDBId(_id);
    try {
        const cart = await Cart.find({ userId: _id }).populate("productId").populate("color");
        res.json(cart);
    }  catch (e) {
        throw new Error(e);
    }
});

const removeProductCart = asyncHandler(async (req, res) => {
    const { _id } = req.user;
    const { cartItemId } = req.params;
    validateMongoDBId(_id);
    try {
        const deleteProductCart = await Cart.deleteOne({userId: _id, _id: cartItemId})
        res.json(deleteProductCart);
    } catch (e) {
        throw new Error(e);
    }
});
const updateProductQuantityCart = asyncHandler(async (req, res) => {
    const { _id } = req.user;
    const { cartItemId, newQuantity } = req.params;
    validateMongoDBId(_id);
    try {
        const updateProductCart = await Cart.findOne({userId: _id, _id: cartItemId})
        updateProductCart.quantity = newQuantity
        updateProductCart.save()
        res.json(updateProductCart);
    } catch (e) {
        throw new Error(e);
    }
});

const createOrder = asyncHandler(async(req, res) => {
    const {
        shippingInfo,
        orderItems,
        totalPrice,
        totalPriceAfterDiscount,
    } = req.body;
    const { _id } = req.user;
    try {
        const order = await Order.create({
            shippingInfo,
            orderItems,
            totalPrice,
            totalPriceAfterDiscount,
            user:_id
        })
        res.json(order)
    } catch (e) {
        throw new Error(e);
    }
})

const getMyOrders = asyncHandler(async(req, res) => {
    const {_id} = req.user;
    try{
        const orders = await Order.find({user: _id})
            .populate("user")
            .populate("orderItems.product")
            .populate("orderItems.color")
        res.json(orders)
    }catch (e) {
        throw new Error(e);
    }
})

const getAllOrders = asyncHandler(async(req, res) => {
    try{
        const orders = await Order.find()
            .populate("user")
            .populate("orderItems.product")
            .populate("orderItems.color")
        res.json(orders)
    }catch (e) {
        throw new Error(e);
    }
})
const getOrderById = asyncHandler(async (req, res) => {
    const { id } = req.params;
    try {
        const orders = await Order.findOne({_id:id})
            .populate("orderItems.product")
            .populate("orderItems.color")
        res.json(orders);
    } catch (e) {
        throw new Error(e);
    }
})
const getMonthWiseOrderIncome = asyncHandler(async(req, res) => {
    let monthNames = ["January","February","March","April","May","June","July",
                        "August","September","October","November","December"];
    let d = new Date();
    let endDate = "";
    d.setDate(1)
    for (let index = 0; index < 11; index++){
        d.setMonth(d.getMonth() - 1)
        endDate = monthNames[d.getMonth()] + " " + d.getFullYear()
    }
    const data = await Order.aggregate([
        {
            $match: {
                createdAt: {
                    $lte: new Date(),
                    $gte: new Date(endDate)
                }
            }
        }, {
            $group: {
                _id: {
                    month: "$month"
                },
                amount: {$sum: "$totalPriceAfterDiscount"},
                count: {$sum: 1}
            }
        }
    ])
    res.json(data)
})
const getYearlyTotalOrders = asyncHandler(async(req, res) => {
    let monthNames = ["January","February","March","April","May","June","July",
                        "August","September","October","November","December"];
    let d = new Date();
    let endDate = "";
    d.setDate(1)
    for (let index = 0; index < 11; index++){
        d.setMonth(d.getMonth() - 1)
        endDate = monthNames[d.getMonth()] + " " + d.getFullYear()
    }
    const data = await Order.aggregate([
        {
            $match: {
                createdAt: {
                    $lte: new Date(),
                    $gte: new Date(endDate)
                }
            }
        }, {
            $group: {
                _id: null,
                count: {$sum: 1},
                amount: {$sum: "$totalPriceAfterDiscount"}
            }
        }
    ])
    res.json(data)
})
//xử giỏ thành giỏ hàng trống sau khi mua
const emptyCart = asyncHandler(async (req, res) => {
    const { _id } = req.user;
    validateMongoDBId(_id);
    try {
        const cart = await Cart.deleteMany({ userId: _id });
        res.json(cart);
    } catch (e) {
        throw new Error(e);
    }
});
// //áp mã giảm giá
// const applyCoupon = asyncHandler(async (req, res) => {
//     const { coupon } = req.body;
//     const { _id } = req.user;
//     validateMongoDBId(_id);
//     const validCoupon = await Coupon.findOne({ name: coupon });//thay cái name bằng một cái mã random để ng dùng tự nhập
//     if (validCoupon === null) {
//         throw new Error('Mã giảm giá không hợp lệ');
//     }
//     const user = await User.findOne({ _id });
//     let { cartTotal } = await Cart.findOne({
//         orderby: user._id,
//     }).populate('products.product');
//     //tính giá sau khi giảm
//     let totalAfterDiscount = (
//         cartTotal -
//         (cartTotal * validCoupon.discount) / 100
//     ).toFixed(2);
//     // cập nhật giả giảm lại vào giỏ hàng
//     await Cart.findOneAndUpdate(
//         { orderby: user._id },
//         { totalAfterDiscount },
//         { new: true }
//     );
//     res.json(totalAfterDiscount);
// })

const updateOrderStatus = asyncHandler(async (req, res) => {
    const { status } = req.body;
    const { id } = req.params;
    validateMongoDBId(id);
    try {
        const updateOrderStatus = await Order.findByIdAndUpdate(
            id,
            {
            orderStatus: status, //chọn order status
            },
            { new: true }
        );
        res.json(updateOrderStatus);
    } catch (e) {
      throw new Error(e);
    }
  });
module.exports = { 
    createUser, 
    loginUser, 
    logoutUser,
    getallUser, 
    getaUser, 
    deleteaUser,
    updateaUser,
    blockUser,
    unblockUser,
    handlerRefreshToken,
    updatePassword,
    forgotPasswordToken,
    resetPassword,
    loginAdmin,
    getWishlist,
    saveAddress,
    userCart,
    getUserCart,
    removeProductCart,
    updateProductQuantityCart,
    createOrder,
    getMyOrders,
    getAllOrders,
    getMonthWiseOrderIncome,
    getYearlyTotalOrders,
    getOrderById,
    updateOrderStatus,
    emptyCart  
}