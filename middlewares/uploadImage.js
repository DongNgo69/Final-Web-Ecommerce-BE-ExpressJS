const multer = require('multer'); //thư viên uploadfile của nodejs
const sharp = require('sharp'); //thư viện giúp giảm dung lượng các file cho phù hợp với web
const path = require('path'); //module thao tác với các đường dẫn
const fs = require('fs')
//định dạng đường dẫn
const multerStorage = multer.diskStorage({
    //nơi đến
    destination: function (req, file, cb) {
        cb(null, path.join(__dirname, '../public/images/')) //kết hợp các tham số đg dãn ra đường dẫn chính
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + Math.round(Math.random() * 1e9)
        cb(null, file.fieldname + '-' + uniqueSuffix + ".jpeg")
    }
})
//định dạng file
const multerFilter = (req, file, cb) => {
    if (file.mimetype.startsWith("image")){
        cb(null, true)
    } else {
        cb({
            message: 'Không hỗ trợ định dạng file này'
        }, false)
    }
}

//giảm dung lượng file product
const productImgResize = async(req, res, next) => {
    if(!req.files) return next()
    await Promise.all(req.files.map( async (file) => {
        await sharp(file.path)
            .resize(300,300)
            .toFormat('jpeg')
            .jpeg({quality:90})
            .toFile(`public/images/products/${file.filename}`)
            fs.unlinkSync(`public/images/products/${file.filename}`)
        }))
    next()
}
//giảm dụng lượng file blog
const blogImgResize = async(req, res, next) => {
    if(!req.files) return next()
    await Promise.all(req.files.map( async (file) => {
        await sharp(file.path)
            .resize(300,300)
            .toFormat('jpeg')
            .jpeg({quality:90})
            .toFile(`public/images/blogs/${file.filename}`)
            fs.unlinkSync(`public/images/blogs/${file.filename}`)
    }))
    next()
}

const uploadPhoto = multer({
    storage: multerStorage,
    fileFilter: multerFilter,
    limits: { fileSize: 2000000}
})

module.exports = {
    uploadPhoto,
    productImgResize,
    blogImgResize
}