const registerForm = document.getElementById("registerForm");
const messageContainer = document.getElementById("messageContainer");

const showMessage = (message, type = "success") => {
    messageContainer.innerHTML = `
        <div class="alert alert-${type} alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Cerrar"></button>
        </div>
    `;
};

registerForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const fullname = document.getElementById("fullname").value;
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;

    try {
        const response = await fetch(
            "http://localhost:5000/api/auth/register",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    fullname,
                    email,
                    password
                })
            }
        );

        const data = await response.json();

        if (response.ok) {
            showMessage("✅ Registro exitoso. Redirigiendo a login...", "success");
            setTimeout(() => {
                window.location.href = "login.html";
            }, 1400);
        } else {
            showMessage(`❌ ${data.message || "No se pudo registrar"}`, "danger");
        }
    } catch (error) {
        console.error(error);
        showMessage("❌ Error en el servidor. Intenta de nuevo más tarde.", "danger");
    }
});