import { Router } from "express";
import {createNewCartController, 
    getCartByIdController, 
    setProductToCart, 
    deleteProductInCart,
    replaceProductsInCart,
    updateProductQuantityInCart,
    deleteAllProductsInCart
} from '../controllers/cartController.js'

const router = Router()


router.post('/', createNewCartController )

router.get('/:cid', getCartByIdController)

router.post('/:cid/products/:pid', setProductToCart)

router.delete('/:cid/products/:pid', deleteProductInCart)

router.put('/:cid', replaceProductsInCart)

router.put('/:cid/products/:pid', updateProductQuantityInCart)

router.delete('/:cid', deleteAllProductsInCart)

export default router
