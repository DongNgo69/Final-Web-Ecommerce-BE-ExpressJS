const Color = require('../models/colorModel')
const asyncHandler = require('express-async-handler')
const validateMongoDBId = require('../utils/validateMongoDBId')

const createColor = asyncHandler( async(req, res) => {
    try{
        const newColor= await Color.create(req.body)
        res.json(newColor)
    }catch (e){
        throw new Error(e)
    }
})
const updateColor = asyncHandler( async(req, res) => {
    const { id } = req.params
    try{
        const updateColor = await Color.findByIdAndUpdate(
            id, 
            req.body, 
            {new: true}
        )
        res.json(updateColor)
    }catch (e) {
        throw new Error(e)
    }
})
const deleteColor = asyncHandler( async(req, res) => {
    const { id } = req.params
    try{
        const deleteColor = await Color.findByIdAndDelete(id)
        res.json(deleteColor)
    }catch (e) {
        throw new Error(e)
    }
})
const getColor = asyncHandler( async(req, res) => {
    const { id } = req.params
    validateMongoDBId(id)
    try{
        const getColor = await Color.findById(id)
        res.json(getColor)
}catch (e) {
    throw new Error(e)
}
})
const getallColor = asyncHandler( async(req, res) => {
    try{
        const getallColor = await Color.find()
        res.json(getallColor)
}catch (e) {
    throw new Error(e)
}
})


module.exports = {
    createColor,
    updateColor,
    deleteColor,
    getColor,
    getallColor
}