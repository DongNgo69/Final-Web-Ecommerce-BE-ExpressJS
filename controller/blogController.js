const Blog = require('../models/blogModel')
const User = require('../models/userModel')
const asyncHandler = require('express-async-handler')
const validateMongoDBId = require('../utils/validateMongoDBId')
const {
    cloudinaryUploadImg 
}= require('../utils/cloudinary')
const fs = require('fs')
const createBlog = asyncHandler(async (req, res) => {
    try{
        const newBlog = await Blog.create(req.body)
        res.json(newBlog)
    }catch (e){
        throw new Error(e)
    }
})

const updateBlog = asyncHandler(async (req, res) => {
    const {id} = req.params
    validateMongoDBId(id)
    try{
        const updateBlog = await Blog.findByIdAndUpdate(id, req.body, {
            new: true
        })
        res.json(updateBlog)
    }catch (e){
        throw new Error(e)
    }
})

const getBlog = asyncHandler(async (req, res) => {
    const {id} = req.params
    validateMongoDBId(id)
    try{
        const getBlog = await Blog.findById(id)
        .populate('likes')
        .populate('dislikes')
        //tăng view mỗi khi có ng xem blog
        const updateViews = await Blog.findByIdAndUpdate(
            id,
            {$inc: {numViews: 1}},
            {new: true}
        )
        res.json(getBlog)
    }catch (e){
        throw new Error(e)
    }
})
const getAllBlogs = asyncHandler(async (req, res) => {
    try{
        const getBlogs = await Blog.find()
        res.json(getBlogs)
    } catch (e){
        throw new Error(e)
    }
})

const deleteBlog = asyncHandler(async (req, res) => {
    const {id} = req.params
    validateMongoDBId(id)
    try{
        const deleteBlog = await Blog.findByIdAndDelete(id)
        res.json(deleteBlog)
    }catch (e){
        throw new Error(e)
    }
})

const likeBlog = asyncHandler(async (req, res) => {
    const {blogId} = req.body
    validateMongoDBId(blogId)
    
    //tìm blog mà user muốn like
    const blog = await Blog.findById(blogId)
    //check id mà user đăng nhập
    const loginUserId = req?.user?._id
    //tìm xem người dùng có like/dislike blog không
    const isLiked = blog?.isLiked
    const alreadyDisliked = blog?.dislikes?.find(
        (userId) => userId?.toString() === loginUserId?.toString()
        )
        if(alreadyDisliked) {
            const blog = await Blog.findByIdAndUpdate(
                blogId, 
                {$pull: {dislikes: loginUserId},
                isDisliked: false
                },
                {new: true}
            )
            res.json(blog)
        }
        if (isLiked){
            const blog = await Blog.findByIdAndUpdate(
                blogId, 
                {$pull: {likes: loginUserId},
                isLiked: false
                },
                {new: true}
            )
            res.json(blog)
        } else {
            const blog = await Blog.findByIdAndUpdate(
                blogId, 
                {$push: {likes: loginUserId},
                isLiked: true
                },
                {new: true}
            )
            res.json(blog)
        }
})
const dislikeBlog = asyncHandler(async (req, res) => {
    const {blogId} = req.body
    validateMongoDBId(blogId)
    
    //tìm blog mà user muốn like
    const blog = await Blog.findById(blogId)
    //check id mà user đăng nhập
    const loginUserId = req?.user?._id
    //tìm xem người dùng có like/dislike blog không
    const isDisLiked = blog?.isDisliked
    const alreadyLiked = blog?.likes?.find(
        (userId) => userId?.toString() === loginUserId?.toString()
        )
        if(alreadyLiked) {
            const blog = await Blog.findByIdAndUpdate(
                blogId, 
                {$pull: {likes: loginUserId},
                isLiked: false
                },
                {new: true}
            )
            res.json(blog)
        }
        if (isDisLiked){
            const blog = await Blog.findByIdAndUpdate(
                blogId, 
                {$pull: {dislikes: loginUserId},
                isDisliked: false
                },
                {new: true}
            )
            res.json(blog)
        } else {
            const blog = await Blog.findByIdAndUpdate(
                blogId, 
                {$push: {dislikes: loginUserId},
                isDisliked: true
                },
                {new: true}
            )
            res.json(blog)
        }
})

const uploadImages = asyncHandler( async(req, res) => {
    const { id } = req.params
    validateMongoDBId(id)
    try{
        const uploader = (path) => cloudinaryUploadImg(path, "images")
        const urls = []
        const files = req.files
        for (const file of files) {
            const {path} = file
            const newpath = await uploader(path)
            urls.push(newpath)
            fs.unlinkSync(path)
        }
        const findBlog = await Blog.findByIdAndUpdate(
            id,
            {
                images: urls.map((file) => {
                    return file 
            }) 
        },
        {
            new: true
        })
        res.json(findBlog)
    }catch(e){
        throw new Error(e)
    }
})

module.exports = {
    createBlog,
    updateBlog,
    getBlog,
    getAllBlogs,
    deleteBlog,
    likeBlog,
    dislikeBlog, 
    uploadImages 
}

