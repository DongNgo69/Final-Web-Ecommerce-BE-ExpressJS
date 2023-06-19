const { default: mongoose } = require('mongoose');

const dbConnect = () => {
    try{
        const conn = mongoose.connect(process.env.MONGODB_URL)
        console.log('Kết nối DB thành công')
    }
    catch(e){
        console.log('Kết nối DB thất bại')
    }
}

module.exports = dbConnect