import express, {response, request} from "express";
import { getProductByIdService, getProductsService, setNewProductService, updateProductService, deleteProductService } from "../services/productService.js";

// { "title": "Nicaragua Jinotega",
// "description": "Bolsa de café 500gr.",
// "price": 940,
// "thumbnail": "bolsa-nicaragua.jpg",
// "code": 45,
// "stock": 37,
// "id": 9,
// "category": "500gr."}

export const getProductsController = async (req=request, res=response) =>{
    try {
        const { limit=10, category='all', sort=0 } = req.query

        const data = await getProductsService(Number(limit), category, sort)

        return res.status(200).json(data)
    } catch (error) {
        return res.json({error})
    }
}

export const getProductByIdController = async (req=request, res=response)=>{
    try {
        const { id } = req.params

        const data = await getProductByIdService(id)

        return res.status(200).json(data)
    } catch (error) {
        return res.json({error})
    }
}

export const postNewProductController = async (req=request, res=response)=>{
    try {
        const { title, description, price, thumbnail, code, stock, category } = req.body

        const data = await setNewProductService(title, description, price, thumbnail, code, stock, category)

        return res.status(201).json(data)
    } catch (error) {
        return res.json({error})
    }
}

export const updateNewProductController = async (req=request, res=response)=>{
    try {
        const { id } = req.params
        const newData = req.body

        const data = await updateProductService(id, newData)

        return res.status(201).json(data)
    } catch (error) {
        return res.json({error})
    }
}

export const deleteProductController = async (req=request, res=response)=>{
    try {
        const { id } = req.params

        const data = await deleteProductService(id)

        return res.status(201).json(data)
    } catch (error) {
        return res.json({error})
    }
}