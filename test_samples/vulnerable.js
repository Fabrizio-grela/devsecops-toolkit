// Archivo vulnerable de prueba para SAST
function ejecutarCodigo(entradaUsuario) {
    // Riesgo crítico de inyección de código
    eval(entradaUsuario);
}