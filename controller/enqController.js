const Enquiry = require('../models/enqModel')
const asyncHandler = require("express-async-handler")
const validateMongoDBId = require("../utils/validateMongodbId")

const createEnquiry = asyncHandler(async (req, res) => {
    try {
        const newEnquiry = await Enquiry.create(req.body)
        res.json(newEnquiry)
    } catch (e) {
        throw new Error(e)
    }
});
const updateEnquiry = asyncHandler(async (req, res) => {
    const { id } = req.params
    validateMongoDBId(id)
    try {
        const updatedEnquiry = await Enquiry.findByIdAndUpdate(id, req.body, {
            new: true,
        });
        res.json(updatedEnquiry)
    } catch (e) {
        throw new Error(e)
    }
});
const deleteEnquiry = asyncHandler(async (req, res) => {
    const { id } = req.params
    validateMongoDBId(id)
    try {
        const deletedEnquiry = await Enquiry.findByIdAndDelete(id);
        res.json(deletedEnquiry)
    } catch (e) {
        throw new Error(e)
    }
});
const getEnquiry = asyncHandler(async (req, res) => {
    const { id } = req.params
    validateMongoDBId(id)
    try {
        const getaEnquiry = await Enquiry.findById(id)
        res.json(getaEnquiry)
    } catch (e) {
        throw new Error(e)
    }
});
const getallEnquiry = asyncHandler(async (req, res) => {
    try {
        const getallEnquiry = await Enquiry.find()
        res.json(getallEnquiry)
    } catch (e) {
        throw new Error(e)
    }
});
module.exports = {
    createEnquiry,
    updateEnquiry,
    deleteEnquiry,
    getEnquiry,
    getallEnquiry,
};
