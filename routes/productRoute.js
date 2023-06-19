const express = require('express')
const router = express.Router()
const {
    createProduct,
    getaProduct,
    getAllProduct,
    updateProduct,
    deleteProduct,
    addToWishList,
    rating
} = require('../controller/productController')
const {
    isAdmin,
    authMiddleware
} = require('../middlewares/authMiddleware')

//Client addwishlist and rating
router.put('/wishlist',authMiddleware , addToWishList)
router.put('/rating',authMiddleware, rating)
//router
//CRUD product by Admin
router.post('/', authMiddleware, isAdmin, createProduct)
router.put('/:id', authMiddleware, isAdmin, updateProduct)
router.delete('/:id', authMiddleware, isAdmin, deleteProduct)

//Get Product
router.get('/:id', getaProduct)
router.get('/', getAllProduct)






module.exports = router