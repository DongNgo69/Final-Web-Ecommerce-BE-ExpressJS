const express = require('express')
const app = express()
const dotenv = require('dotenv').config()
const PORT = process.env.PORT || 5000

//import router
const authRouter = require('./routes/authRoute')
const productRouter = require('./routes/productRoute')
const blogRouter = require('./routes/blogRoute')
const categoryRouter = require('./routes/categoryRoute')
const blogcategoryRouter = require('./routes/blogCategoryRoute')
const brandRouter = require('./routes/brandRoute')
const couponRouter = require('./routes/couponRoute')
const uploadRouter = require('./routes/uploadRoute')
const colorRouter = require('./routes/colorRoute')
const enqRouter = require('./routes/enqRoute')

const dbConnect = require('./config/dbConnect')
const bodyParser = require('body-parser') //nhận dữ liệu post
const { errorHandler, notFound } = require('./middlewares/errorHandler')
const cookieParser = require('cookie-parser')
const morgan = require('morgan')
const cors = require('cors') //cho phép truy cập tài nguyên từ các domain khác
//dbConnect
dbConnect()

app.use(cors())
app.use(morgan("dev"))
app.use(bodyParser.json()) //thư viện chuyển thông tin nhập vào form vào req.body
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
//Router
app.use('/api/user', authRouter)
app.use('/api/product', productRouter)
app.use('/api/blog', blogRouter)
app.use('/api/category', categoryRouter)
app.use('/api/blogcategory', blogcategoryRouter)
app.use('/api/brand', brandRouter)
app.use('/api/coupon', couponRouter)
app.use('/api/upload', uploadRouter) 
app.use('/api/color', colorRouter)
app.use('/api/enquiry', enqRouter)
//Middleware
app.use(notFound)
app.use(errorHandler)

app.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`)
})