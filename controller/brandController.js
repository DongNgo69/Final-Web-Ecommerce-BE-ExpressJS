const Brand = require('../models/brandModel')
const asyncHandler = require('express-async-handler')
const validateMongoDBId = require('../utils/validateMongoDBId')

const createBrand = asyncHandler( async(req, res) => {
    try{
        const newBrand = await Brand.create(req.body)
        res.json(newBrand)
    }catch (e){
        throw new Error(e)
    }
})
const updateBrand = asyncHandler( async(req, res) => {
    const { id } = req.params
    try{
        const updateBrand = await Brand.findByIdAndUpdate(
            id, 
            req.body, 
            {new: true}
        )
        res.json(updateBrand)
    }catch (e) {
        throw new Error(e)
    }
})
const deleteBrand = asyncHandler( async(req, res) => {
    const { id } = req.params
    try{
        const deleteBrand = await Brand.findByIdAndDelete(id)
        res.json(deleteBrand)
    }catch (e) {
        throw new Error(e)
    }
})
const getBrand = asyncHandler( async(req, res) => {
    const { id } = req.params
    validateMongoDBId(id)
    try{
        const getBrand = await Brand.findById(id)
        res.json(getBrand)
}catch (e) {
    throw new Error(e)
}
})
const getallBrand = asyncHandler( async(req, res) => {
    try{
        const getallBrand = await Brand.find()
        res.json(getallBrand)
}catch (e) {
    throw new Error(e)
}
})


module.exports = {
    createBrand,
    updateBrand,
    deleteBrand,
    getBrand,
    getallBrand
}