import mongoose from 'mongoose';

export const dbConnection = async ()=>{
    try {
        await mongoose.connect('mongodb://127.0.0.1/cultura-cafe');
        console.log('db conectada')
    } catch (error) {
        console.log(error)
    }
}