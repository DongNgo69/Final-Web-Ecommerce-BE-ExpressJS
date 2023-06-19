const mongoose = require('mongoose'); // Erase if already required

// Declare the Schema of the Mongo model
var orderSchema = new mongoose.Schema(
    {
      user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
      },
      shippingInfo: {
        fullname: {
          type: String,
          required: true
        },
        address: {
          type: String,
          required: true
        },
        city: {
          type: String,
          required: true
        },
        mobile: {
          type: String,
          required: true
        },
      },
      orderItems: [
        {
          product: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Product",
            required: true
          },
          color: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Color",
            required: true
          },
          quantity: {
            type: Number,
            required: true
          },
          price: {
            type: Number,
            required: true
          }
        }
      ],
      paidAt: {
        type: Date,
        default: Date.now()
      },
      month: {
        type: String,
        default:new Date().getMonth()
      },
      totalPrice: {
        type: Number,
        required: true
      },
      totalPriceAfterDiscount: {
        type: Number,
        required: true
      },
      orderStatus: {
        type: String,
        default: 'Đã đặt hàng'
      }
    },
    {
      timestamps: true,
    }
    );

//Export the model
module.exports = mongoose.model('Order', orderSchema);