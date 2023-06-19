const BlogCategory = require('../models/blogCategoryModel')
const asyncHandler = require('express-async-handler')
const validateMongoDBId = require('../utils/validateMongoDBId')

const createBlogCategory = asyncHandler( async(req, res) => {
    try{
        const newBlogCategory = await BlogCategory.create(req.body)
        res.json(newBlogCategory)
    }catch (e){
        throw new Error(e)
    }
})
const updateBlogCategory = asyncHandler( async(req, res) => {
    const { id } = req.params
    try{
        const updateBlogCategory = await BlogCategory.findByIdAndUpdate(
            id, 
            req.body, 
            {new: true}
        )
        res.json(updateBlogCategory)
    }catch (e) {
        throw new Error(e)
    }
})
const deleteBlogCategory = asyncHandler( async(req, res) => {
    const { id } = req.params
    try{
        const deleteBlogCategory = await BlogCategory.findByIdAndDelete(id)
        res.json(deleteBlogCategory)
    }catch (e) {
        throw new Error(e)
    }
})
const getBlogCategory = asyncHandler( async(req, res) => {
    const { id } = req.params
    validateMongoDBId(id)
    try{
        const getBlogCategory = await BlogCategory.findById(id)
        res.json(getBlogCategory)
}catch (e) {
    throw new Error(e)
}
})
const getAllBlogCategory = asyncHandler( async(req, res) => {
    try{
        const getAllBlogCategory = await BlogCategory.find()
        res.json(getAllBlogCategory)
}catch (e) {
    throw new Error(e)
}
})


module.exports = {
    createBlogCategory,
    updateBlogCategory,
    deleteBlogCategory,
    getBlogCategory,
    getAllBlogCategory
    
}