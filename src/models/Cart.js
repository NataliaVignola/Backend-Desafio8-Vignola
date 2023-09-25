import mongoose from 'mongoose';

const cartSchema = new mongoose.Schema({
    products: [
        {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'Product',
        },
    ],
    totalPrice: Number,
    timestamp: { type: Date, default: Date.now },
});

export default mongoose.model('Cart', cartSchema);
