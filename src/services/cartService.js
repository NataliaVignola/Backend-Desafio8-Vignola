import CartsModel from "../models/Cart.js"
import ProductsModel from "../models/Product.js"

export const createNewCartService = async ()=>{
    try {
        
        const newCart = await CartsModel.create({})

        if(!newCart) throw {name: 'server error', httpcode: 500, description: 'Error en crear producto nuevo service'}

        return newCart
    } catch (error) {
        throw error
    }
}

export const getCartByIdService = async (cid)=>{
    try {
        
        const cart = await CartsModel.findById(cid).populate('products.product')

        if(!cart) throw {name: 'client error', httpcode: 404, description: 'Cart not found service'}

        return cart
    } catch (error) {
        throw error
    }
}

export const setProductIntoCartService = async (cid, pid, quantity=1)=>{
    try {
        
        const cart = await CartsModel.findById(cid)
        if(!cart) throw {name: 'client error', httpcode: 404, description: 'Cart not found service'} 

        const product = await ProductsModel.findById(pid)
        if(!product) throw {name: 'client error', httpcode: 404, description: 'product not found service'}

        const validateProduct = cart.products.some(e=> e.product == pid)
        if(!validateProduct){
            cart.products.push({product: pid, quantity: quantity})
            await cart.save()
            return cart
        }else{
            const newArray = cart.products.filter(e=> e.product != pid)
            newArray.push({product: pid, quantity: quantity})
            await CartsModel.findByIdAndUpdate(cid, {products: newArray})
            return cart
        }
    } catch (error) {
        throw error
    }
}

export const deleteProductInCartByIdService = async (cid, pid)=>{
    try {
        const cart = await CartsModel.findById(cid)
        if(!cart) throw {name: 'client error', httpcode: 404, description: 'Cart not found service'} 

        const product = await ProductsModel.findById(pid)
        if(!product) throw {name: 'client error', httpcode: 404, description: 'product not found service'}

        const validateProduct = cart.products.some(e=> e.product == pid)
        if(!validateProduct){
            throw {name: 'client error', httpcode: 404, description: 'product no encontrado en cart'}
        }else{
            const newArray = cart.products.filter(e=> e.product != pid)
            await CartsModel.findByIdAndUpdate(cid, {products: newArray})
            return cart
        }

    } catch (error) {
        throw error
    }
}

export const replaceProductsInCartService = async (cid, newProducts)=>{
    try {
        const cart = await CartsModel.findById(cid)
        if(!cart) throw {name: 'client error', httpcode: 404, description: 'Cart not found service'} 

        if(newProducts.length <= 0) throw {name: 'client error', httpcode: 404, description: 'No se puede agergar una lista vacia'}

        await CartsModel.findByIdAndUpdate(cid, {products: newProducts})

        return cart
    } catch (error) {
        throw error
    }
}

export const updateProductQuantityInCartService = async (cid, pid, quantity)=>{
    try {
        const cart = await CartsModel.findById(cid)
        if(!cart) throw {name: 'client error', httpcode: 404, description: 'Cart not found service'} 

        const product = await ProductsModel.findById(pid)
        if(!product) throw {name: 'client error', httpcode: 404, description: 'product not found service'}

        if(!quantity) throw {name: 'client error', httpcode: 404, description: 'quantity al menos debe ser 1'}

        const validateProduct = cart.products.some(e=> e.product == pid)
        if(!validateProduct){
            throw {name: 'client error', httpcode: 404, description: 'product no encontrado en cart'}
        }else{
            const newArray = cart.products.filter(e=> e.product != pid)
            console.log(newArray)
            newArray.push({product: pid, quantity})
            await CartsModel.findByIdAndUpdate(cid, {products: newArray})

            return cart
        }

    } catch (error) {
        throw error
    }
}

export const deleteAllProductsInCartService = async (cid)=>{
    try {
        const cart = await CartsModel.findById(cid)
        if(!cart) throw {name: 'client error', httpcode: 404, description: 'Cart not found service'} 

        cart.products = []
        await cart.save()

        return cart
    } catch (error) {
        throw error
    }
}