// Prueba de vulnerabilidades en JS
const userContent = "<img src=x onerror=alert(1)>";
document.getElementById("output").innerHTML = userContent; // XSS Detectable

const code = "console.log('hola')";
eval(code); // Inyección de código Detectable