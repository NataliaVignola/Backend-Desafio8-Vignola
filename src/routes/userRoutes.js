import { Router } from "express";
import {signinController, signupController, logoutController} from '../controllers/userController.js'
import passport from "passport";

const router = Router()


router.post('/signup', passport.authenticate('signup'), signupController)

router.get('/signin', passport.authenticate('signin'), signinController)

router.get('/logout', logoutController)

export default router