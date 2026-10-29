const user = JSON.parse(localStorage.getItem("user"));

if (!user) {

    window.location.href = "login.html";

}

document.getElementById("username").innerHTML =
    user.fullname;

document.getElementById("role").innerHTML =
    user.role;

// =========================
// ROLES SIDEBAR
// =========================

const sidebar =
    document.getElementById(
        "sidebarMenu"
    );

let menu = "";


if(user.role === "SUPER_ADMIN"){

    menu = `

        <li class="nav-item mb-3">
            <a class="nav-link text-white" href="#">
                Dashboard
            </a>
        </li>

        <li class="nav-item mb-3">
            <a class="nav-link text-white" href="#">
                Users
            </a>
        </li>

        <li class="nav-item mb-3">
            <a class="nav-link text-white" href="#">
                Roles
            </a>
        </li>

        <li class="nav-item mb-3">
            <a class="nav-link text-white" href="#">
                Statistics
            </a>
        </li>

        <li class="nav-item mb-3">
            <a class="nav-link text-white" href="#">
                Reports
            </a>
        </li>

    `;

}

else if(user.role === "ADMIN"){

    menu = `

        <li class="nav-item mb-3">
            <a class="nav-link text-white" href="#">
                Dashboard
            </a>
        </li>

        <li class="nav-item mb-3">
            <a class="nav-link text-white" href="#">
                Users
            </a>
        </li>

        <li class="nav-item mb-3">
            <a class="nav-link text-white" href="#">
                Malware Analysis
            </a>
        </li>

    `;

}

else if(user.role === "ANALYST"){

    menu = `

        <li class="nav-item mb-3">
            <a class="nav-link text-white" href="#">
                Malware Analysis
            </a>
        </li>

        <li class="nav-item mb-3">
            <a class="nav-link text-white" href="#">
                Reports
            </a>
        </li>

    `;

}

else{

    menu = `

        <li class="nav-item mb-3">
            <a class="nav-link text-white" href="#">
                Upload Files
            </a>
        </li>

        <li class="nav-item mb-3">
            <a class="nav-link text-white" href="#">
                My Analysis
            </a>
        </li>

    `;

}


// LOGOUT

menu += `

<li class="nav-item mb-3">
    <a
        class="nav-link text-danger"
        href="#"
        onclick="logout()"
    >
        Logout
    </a>
</li>

`;

sidebar.innerHTML = menu;

// CHART

const ctx = document.getElementById("malwareChart");

new Chart(ctx, {

    type: "bar",

    data: {

        labels: [
            "Trojan",
            "Spyware",
            "Ransomware",
            "Worm"
        ],

        datasets: [{

            label: "Detections",

            data: [12, 19, 8, 5],

            borderWidth: 1

        }]
    }

});


// UPLOAD FILE
// =========================

const uploadForm =
    document.getElementById("uploadForm");

uploadForm.addEventListener(
    "submit",
    async (e) => {

        e.preventDefault();

        const fileInput =
            document.getElementById("file");

        const formData = new FormData();

        formData.append(
            "file",
            fileInput.files[0]
        );

        formData.append(
            "user_id",
            user.id
        );

        try {

            const response = await fetch(
                "http://localhost:5000/api/files/upload",
                {
                    method: "POST",
                    body: formData
                }
            );

            const data =
                await response.json();

            alert(`

Malware:
${data.analysis.malware_type}

Risk:
${data.analysis.risk_level}

Vulnerabilities:
${data.analysis.vulnerabilities}

Behavior:
${data.analysis.behavior}

Recommendation:
${data.analysis.recommendation}

Security Score:
${data.analysis.score}/100

`);

// =========================
// LOAD DASHBOARD DATA
// =========================

async function loadDashboard(){

    try {

        const response =
            await fetch(
                "http://localhost:5000/api/dashboard/stats"
            );

        const data =
            await response.json();

        // =========================
        // CARDS
        // =========================

        document.getElementById(
            "totalUsers"
        ).innerHTML =
            data.totalUsers;

        document.getElementById(
            "totalAnalysis"
        ).innerHTML =
            data.totalAnalysis;

        document.getElementById(
            "totalReports"
        ).innerHTML =
            data.totalAnalysis;

        document.getElementById(
            "criticalRisk"
        ).innerHTML =
            data.criticalRisk;

        // =========================
        // TABLE
        // =========================

        const table =
            document.getElementById(
                "analysisTable"
            );

        table.innerHTML = "";

        data.recentAnalysis.forEach(
            (analysis) => {

                table.innerHTML += `
                    <tr>

                        <td>
                            ${analysis.original_name}
                        </td>

                        <td>
                            ${analysis.malware_type}
                        </td>

                        <td>
                            ${analysis.risk_level}
                        </td>

                        <td>
                            ${analysis.analysis_date}
                        </td>

                    </tr>
                `;

            }
        );

    } catch (error) {

        console.log(error);

    }

}

loadDashboard();

// LOGOUT

function logout(){

    localStorage.clear();

    window.location.href = "login.html";

}