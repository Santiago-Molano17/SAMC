// Se carga de forma síncrona en <head> para aplicar el tema antes de pintar (evita el parpadeo)
(function () {
    var theme = null;
    try {
        theme = localStorage.getItem("sacm-theme");
    } catch (error) {
        theme = null;
    }
    if (!theme) theme = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", theme);
})();
