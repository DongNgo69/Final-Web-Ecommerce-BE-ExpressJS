const fs = require('fs')
const asyncHandler = require('express-async-handler')
const {
    cloudinaryUploadImg,
    cloudinaryDeleteImg
} = require('../utils/cloudinary')

const uploadImages = asyncHandler( async(req, res) => {
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
        const images = urls.map((file) => {
            return file  
        })
        res.json(images)
    }catch(e){
        throw new Error(e)
    }
})
const deleteImages = asyncHandler(async (req, res) => {
    const { id } = req.params;
    try {
        const deleted = cloudinaryDeleteImg(id, "images");
        res.json({ message: "Đã xóa ảnh" });
    } catch (e) {
        throw new Error(e);
    }
});
module.exports = {
    uploadImages,
    deleteImages
}