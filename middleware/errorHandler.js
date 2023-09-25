// Manejar errores
export const errorHandler = (err, req, res, next) => {
    console.error(err);

    if (res.headersSent) {
        return next(err);
    }

    const statusCode = err.statusCode || 500;
    const message = err.message || 'Error en el servidor';

    res.status(statusCode).json({
        status: 'error',
        message
    });
};

// Manejar solicitudes a rutas no encontradas
export const notFoundHandler = (req, res, next) => {
    res.status(404).json({
        status: 'error',
        message: 'Ruta no encontrada'
    });
};
