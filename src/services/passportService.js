import passport from "passport";
import local from 'passport-local'
import UserModel from "../models/User";
import bcrypt from 'bcryptjs'

const LocalStrategy = local.Strategy

const initializePassport = ()=>{


    passport.use('signup', new LocalStrategy({passReqToCallback: true, usernameField: 'email'}, async (req, username, password, done)=>{

        const {first_name,last_name, email,age } = req.body
        
        try {

            const existsUser = await UserModel.findOne({email: username})
            if(existsUser){
                console.log('user ya existe registrado')
                return done(null, false)
            } 
    
            const user = await UserModel.create({
                first_name: first_name, 
                last_name: last_name,
                age: age, 
                email: email,
                password: bcrypt.hashSync(password)
            })
    
            return done(null, user)
        } catch (error) {
            return done("Error al obtener el usuario:" + error)
        }
    }))

    passport.use('signin', new LocalStrategy({usernameField: 'email'}, async (username, password, done)=>{

        try {
            const user = await UserModel.findOne({email: username})
            if(!user) {
                console.log('Invalid user')
                return done(null, false)
            } 
            const validatePassword = bcrypt.compareSync( password, user.password)
    
            if(!validatePassword) return done(null, false)
    
            return done(null, user)
        } catch (error) {
            return done(error)
        }
    }))

    passport.serializeUser((user, done)=>{
        done(null, user._id)
    })

    passport.deserializeUser( async (id, done)=>{
        let user = await UserModel.findById(id)
        done(null, user)
    })
}


export default initializePassport
