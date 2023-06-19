const express = require('express')
const { 
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
    getOrderById,
    getMonthWiseOrderIncome,
    getYearlyTotalOrders,
    updateOrderStatus,
    emptyCart
} = require('../controller/userController')
const { 
    authMiddleware,
    isAdmin
} = require('../middlewares/authMiddleware')

const router = express.Router()

//Router
//Login/Logout/Register
router.post('/register', createUser)
router.post('/login', loginUser)
router.post('/admin-login', loginAdmin)
router.get('/refresh', handlerRefreshToken)
router.get('/logout', logoutUser)

//password handle
router.put('/password',authMiddleware, updatePassword)
router.post('/forgot-password-token', forgotPasswordToken)
router.put('/reset-password/:token', resetPassword) 

//tác vụ của client
router.put('/edit-user', authMiddleware, updateaUser)
router.put('/save-address', authMiddleware, saveAddress)
router.get('/wishlist', authMiddleware, getWishlist)

//Xử lý giỏ hàng
router.post('/cart', authMiddleware, userCart)
router.get('/cart', authMiddleware, getUserCart)
router.delete('/delete-product-cart/:cartItemId', authMiddleware, removeProductCart)
router.delete('/update-product-cart/:cartItemId/:newQuantity', authMiddleware, updateProductQuantityCart)


//Xử lý đặt hàng/ hóa đơn
router.post("/cart/create-order", authMiddleware, createOrder);
router.get("/getmyorders", authMiddleware, getMyOrders)
router.delete("/empty", authMiddleware, emptyCart)
//admin xử lý order
router.get("/getMonthWiseOrderIncome", authMiddleware, getMonthWiseOrderIncome)
router.get("/getYearlyTotalOrders", authMiddleware, getYearlyTotalOrders)
router.get("/getallorders", authMiddleware, isAdmin, getAllOrders)
router.get("/getorderbyid/:id", authMiddleware, isAdmin, getOrderById)
router.put("/updateorder-status/:id", authMiddleware, isAdmin, updateOrderStatus)
//admin CRUD user
router.get('/all-users', getallUser)
router.get('/:id', authMiddleware, isAdmin, getaUser)
router.delete('/:id', deleteaUser)
router.put('/block-user/:id',authMiddleware, isAdmin, blockUser)
router.put('/unblock-user/:id',authMiddleware, isAdmin, unblockUser)

module.exports = router