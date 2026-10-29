const loginForm = document.getElementById("loginForm");
const messageContainer = document.getElementById("messageContainer");

const showMessage = (message, type = "success") => {
    messageContainer.innerHTML = `
        <div class="alert alert-${type} alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Cerrar"></button>
        </div>
    `;
};

loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;

    try {
        const response = await fetch(
            "http://localhost:5000/api/auth/login",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    email,
                    password
                })
            }
        );

        const data = await response.json();

        if (response.ok) {
            localStorage.setItem("token", data.token);
            localStorage.setItem("user", JSON.stringify(data.user));

            showMessage("✅ Inicio de sesión exitoso. Cargando tu panel...", "success");

            const userRole = data.user.role;
            setTimeout(() => {
                if (userRole === "SUPER_ADMIN" || userRole === "ADMIN" || userRole === "ANALYST") {
                    window.location.href = "admin-dashboard.html";
                } else {
                    window.location.href = "user-dashboard.html";
                }
            }, 1200);
        } else {
            const detailMessage = data.message || "Email o contraseña incorrectos.";
            const alertType = detailMessage.toLowerCase().includes("password") || detailMessage.toLowerCase().includes("contraseña")
                ? "danger"
                : "warning";
            showMessage(`❌ ${detailMessage}`, alertType);
        }
    } catch (error) {
        console.error(error);
        showMessage("❌ Error de servidor. Comprueba tu conexión.", "danger");
    }
});