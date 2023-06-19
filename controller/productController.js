const Product = require('../models/productModel')
const User = require('../models/userModel')
const asyncHandler = require('express-async-handler')
const slugify = require('slugify')
const validateMongoDBId = require('../utils/validateMongoDBId')

//create Product
const createProduct = asyncHandler( async (req, res) => {
    try{
        if (req.body.title){
            req.body.slug = slugify(req.body.title, {lower: true})
        }
        const newProduct = await Product.create(req.body)
        res.json(newProduct)
    } catch (e){
        throw new Error(e)
    }
})

//get 1 Product
const getaProduct = asyncHandler( async (req, res) => {
    const {id} = req.params
    validateMongoDBId(id)
    try{
        const findProduct = await Product.findById(id).populate("color")
        res.json(findProduct)
    }catch (e){
        throw new Error(e)
    }
})

//get all Product
const getAllProduct = asyncHandler( async (req, res) => {
    try{
        //lọc theo điều kiện
        const queryObj = { ...req.query }
        const excludeFields = ['page', 'sort', 'limit', 'fields']
        excludeFields.forEach((el) => delete queryObj[el])
        //lấy theo khoảng giá
        let queryStr = JSON.stringify(queryObj)
        queryStr = queryStr.replace(/\b(gte|gt|lte|lt)\b/g, (match) => `$${match}`)
        
        let query = Product.find(JSON.parse(queryStr))

        //sort
        if(req.query.sort){
            const sortBy = req.query.sort.split(",").join(" ")
            query = query.sort(sortBy)
        } else {
            query = query.sort("-createdAt")

        }

        //lọc thuộc tính cần lấy
        if (req.query.fields) {
            const fields = req.query.fields.split(",").join(" ")
            query = query.select(fields)
        } else {
            query = query.select("-__v")
        }

        //phân trang pagination
        const page = req.query.page //số thứ tự trang
        const limit = req.query.limit //số product 1 trang
        const skip = (page - 1) * limit //só product bỏ qua
        query = query.skip(skip).limit(limit)

        if (req.query.page) {
            const productCount = await Product.countDocuments();
            if(skip >= productCount) throw new Error ('Trang này không tồn tại')
        }

        const getallProducts = await query.populate("color")
        res.json(getallProducts)
    }catch (e){
        throw new Error(e)
    }
})

//update Product
const updateProduct = asyncHandler( async (req, res) => {
    const  id  = req.params
    validateMongoDBId(id)
    try{
        if(req.body.title){
            req.body.slug = slugify(req.body.title, {lower: true})
        }
        const updateProduct = await Product.findByIdAndUpdate(
            {id}, 
            req.body, 
            {new: true}
        )
        res.json({updateProduct})
    }catch (e) {
        throw new Error(e)
    }
})

//delete Product
const deleteProduct = asyncHandler( async (req, res) => {
    const  id  = req.params
    validateMongoDBId(id)
    try{
        const deleteProduct = await Product.findByIdAndDelete(id)
        res.json(deleteProduct)
    }catch (e) {
        throw new Error(e)
    }
})

//add vào wishlist
const addToWishList = asyncHandler( async(req, res) => {
    const {_id} = req.user
    const {prodId} = req.body
    try{
        const user = await User.findById(_id)
        const alreadyAdded = user.wishlist.find((id) => id.toString() === prodId)
        if (alreadyAdded){
            let user = await User.findByIdAndUpdate(
                _id, 
                {$pull: {wishlist: prodId}},
                {
                // new: true, 
                }
            )
            res.json(user)  
        } else{
            let user = await User.findByIdAndUpdate(
                _id, 
                {$push: {wishlist: prodId}},
                {
                new: true, 
                }
            )
            res.json(user)
        }
    } catch (e){
        throw new Error(e)
    }
})

const rating = asyncHandler( async(req, res) => {
    const {_id} = req.user
    const {star, prodId, comment} = req.body
    try{
        const product = await Product.findById(prodId)
        let alreadyRated = product.ratings.find(
            (userId) => userId.postedby.toString() === _id.toString())
        if (alreadyRated){
            const updateRating = await Product.updateOne(
                {
                ratings: {$elemMatch: alreadyRated},
                },
                {
                    $set: {"ratings.$.star":star, "ratings.$.comment": comment}
                },
                {
                    new: true
                }
            )
        } else {
            const rateProduct = await Product.findByIdAndUpdate(
                prodId,{
                    $push: {
                        ratings: {
                            star: star,
                            comment: comment,
                            postedby: _id
                        }
                    }
                },
                {
                    new: true,
                }
            )
        }
        const getallratings = await Product.findById(prodId)
        let totalRating = getallratings.ratings.length
        let ratingsum = getallratings.ratings
            .map((item) => item.star)
            .reduce((prev, curr) => prev + curr, 0)
        let actualRating = Math.round(ratingsum / totalRating)
        let finalproduct = await Product.findByIdAndUpdate(
            prodId,
            {
            totalrating: actualRating,
            },{
                new: true
            }
        )
        res.json(finalproduct)
    } catch (e){
        throw new Error(e)
    }   
})


module.exports = {
    createProduct,
    getaProduct,
    getAllProduct,
    updateProduct,
    deleteProduct,
    addToWishList,
    rating,
}