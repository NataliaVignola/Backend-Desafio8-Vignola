import passport from 'passport';
import LocalStrategy from 'passport-local';
import GitHubStrategy from 'passport-github';
import bcrypt from 'bcrypt';
import * as User from '../src/models/User.js';

// Configurar la estrategia local
passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
}, async (email, password, done) => {
    try {
        const user = await User.findOne({ email });

        if (!user) {
            return done(null, false, { message: 'Usuario no encontrado' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return done(null, false, { message: 'Contraseña incorrecta' });
        }

        return done(null, user);
    } catch (error) {
        return done(error);
    }
}));

// Configurar la estrategia de GitHub
passport.use(new GitHubStrategy({
    clientID: 'tu-client-id',
    clientSecret: 'tu-client-secret',
    callbackURL: 'http://localhost:8080/auth/github/callback'
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const email = profile.emails[0].value;
        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return done(null, existingUser);
        }

        const newUser = new User({
            email,
            // Otros campos del usuario
        });

        await newUser.save();
        return done(null, newUser);
    } catch (error) {
        return done(error);
    }
}));

// Serializar el usuario
passport.serializeUser((user, done) => {
    done(null, user.id);
});

// Deserializar el usuario
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (error) {
        done(error);
    }
});

export default passport;