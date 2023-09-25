import express from 'express';
import { signupService, signinService, logoutService } from '../services/userService.js';

export const signupController = async (req, res) => {
    try {
        // No es necesario almacenar el usuario en la sesión aquí

        return res.status(201).json({
            status: "success",
            detail: "Usuario registrado correctamente",
            payload: {} // No es necesario devolver información sensible aquí
        })
    } catch (error) {
        return res.status(500).json({ error });
    }
}

export const signinController = async (req, res) => {
    try {
        if (!req.user) {
            return res.status(400).json({ status: 'error', msg: 'Credenciales inválidas' });
        }

        // No es necesario almacenar el usuario en la sesión aquí

        return res.status(200).json({
            status: "success",
            detail: "Usuario inició sesión correctamente",
            payload: {} // No es necesario devolver información sensible aquí
        })
    } catch (error) {
        return res.status(500).json({ error });
    }
}

export const logoutController = async (req, res) => {
    try {
        req.session.destroy(function (err) {
            if (err) {
                console.log(err);
                return res.status(500).send('Error al cerrar sesión');
            } else {
                return res.status(200).json({
                    status: "success",
                    details: "Logout success"
                });
            }
        });
    } catch (error) {
        return res.status(500).json({ error });
    }
}

export const getCurrentUser = (req, res) => {
    try {
        if (!req.isAuthenticated()) {
            return res.status(401).json({ status: 'error', msg: 'Usuario no autenticado' });
        }

        const currentUser = {
            firstName: req.user.first_name,
            lastName: req.user.last_name,
            age: req.user.age,
            email: req.user.email,
        };

        return res.status(200).json({
            status: "success",
            detail: "Usuario autenticado",
            payload: currentUser,
        });
    } catch (error) {
        return res.status(500).json({ error });
    }
}
