import express, {response, request} from "express";
import { createNewCartService, 
    getCartByIdService, 
    setProductIntoCartService, 
    deleteProductInCartByIdService, 
    replaceProductsInCartService,
    updateProductQuantityInCartService,
    deleteAllProductsInCartService
} from '../services/cartService.js'

export const createNewCartController = async (req = request, res= response)=>{
    try {
        const data = await createNewCartService()

        return res.status(201).json(data)
    } catch (error) {
        return res.json(error)
    }
}

export const getCartByIdController = async(req = request, res= response)=>{
    try {
        const { cid } = req.params

        const data = await getCartByIdService(cid)

        return res.status(201).json(data)
    } catch (error) {
        return res.json(error)
    }
}

export const setProductToCart = async(req = request, res= response)=>{
    try {
        const {cid, pid} = req.params
        const {quantity} = req.query
        const data = await setProductIntoCartService(cid, pid, quantity)

        return res.status(201).json(data)
    } catch (error) {
        return res.json(error)
    }
}

export const deleteProductInCart = async (req = request, res= response)=>{
    try {
        const {cid, pid} = req.params

        const data = await deleteProductInCartByIdService(cid, pid)

        return res.status(200).json({
            "status": "success",
            "detail": `producto: ${pid} eliminado correctamente de cart ${cid}`,
            "payload": data
        })
    } catch (error) {
        return res.json(error)
    }
}

export const replaceProductsInCart = async (req = request, res= response)=>{
    try {
        const {cid} = req.params
        const productsList = req.body

        const data = await replaceProductsInCartService(cid, productsList)

        return res.status(201).json({
            "status": "success",
            "detail": `Se agrego una nueva lista de productos en cart:" ${cid}`,
            "payload": data
        })
    } catch (error) {
        return res.json(error)
    }
}

export const updateProductQuantityInCart = async (req = request, res= response)=>{
    try {
        const {cid, pid} = req.params
        const {quantity} = req.body
        
        const data = await updateProductQuantityInCartService(cid, pid, quantity)

        return res.status(201).json({
            "status": "success",
            "detail": `Se actualizo la cantidad del producto:" ${pid}`,
            "payload": data
        })
    } catch (error) {
        return res.json(error)
    }
} 


export const deleteAllProductsInCart = async (req = request, res= response)=>{
    try {
        const {cid} = req.params
        
        const data = await deleteAllProductsInCartService(cid)

        return res.status(201).json({
            "status": "success",
            "detail": `Se eliminaron los productos en cart:" ${cid}`,
            "payload": data
        })
    } catch (error) {
        return res.json(error)
    }
} 

