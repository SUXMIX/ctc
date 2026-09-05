const API = window.CTC_CONFIG?.API_URL || "";

const tbody = document.querySelector("#adminTable tbody");
const modalEditor = document.getElementById("editorModal");
const form = document.getElementById("olympiadForm");
const message = document.getElementById("adminMessage");

let data = [];

function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  }[c]));
}

async function request(path, options = {}) {
  const response = await fetch(`${API}${path}`, {
    credentials: "include",
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });

  const body = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(body.error || "Erro na requisição");
  }

  return body;
}

async function init() {
  if (!API || API.includes("SEU-WORKER-AQUI")) {
    message.textContent =
      "Configure API_URL em js/config.js para usar o painel.";
    return;
  }

  try {
    const me = await request("/api/me");

    if (!me.authenticated) {
      window.location.href = "login.html";
      return;
    }

    document.getElementById("userGreeting").textContent =
      `Usuário: ${me.user.name} • Função: ${me.user.role}`;

    await load();

  } catch (e) {
    message.textContent = e.message;
  }
}

async function load() {
  try {
    const response = await request("/api/olympiads");

    // A API retorna { olympiads: [...] }
    if (!Array.isArray(response.olympiads)) {
      throw new Error("A API retornou um formato de dados inválido.");
    }

    data = response.olympiads;

    renderTable();

  } catch (e) {
    data = [];
    tbody.innerHTML = "";
    message.textContent = e.message;
  }
}

function renderTable() {
  if (!data.length) {
    tbody.innerHTML = `
      <tr>
        <td colspan="5" style="text-align:center;">
          Nenhuma olimpíada cadastrada.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = data.map(o => `
    <tr>
      <td>
        <strong>${esc(o.acronym)}</strong>
      </td>

      <td>
        ${esc(o.name)}
      </td>

      <td>
        ${esc(o.area) || "—"}
      </td>

      <td>
        ${esc(o.status) || "—"}
      </td>

      <td>
        <button
          class="admin-action"
          data-edit="${o.id}">
          Editar
        </button>

        <button
          class="admin-action delete"
          data-delete="${o.id}">
          Excluir
        </button>
      </td>
    </tr>
  `).join("");

  tbody.querySelectorAll("[data-edit]").forEach(button => {
    button.addEventListener("click", () => {
      openEditor(Number(button.dataset.edit));
    });
  });

  tbody.querySelectorAll("[data-delete]").forEach(button => {
    button.addEventListener("click", () => {
      remove(Number(button.dataset.delete));
    });
  });
}

function fill(id) {
  const olympiad = data.find(item => item.id === id);

  const fields = [
    "acronym",
    "name",
    "area",
    "modality",
    "registration_method",
    "registration_deadline",
    "number_of_phases",
    "status",
    "phase_1_date",
    "phase_2_date",
    "phase_3_date",
    "phase_4_date",
    "extra"
  ];

  document.getElementById("editId").value =
    olympiad?.id || "";

  fields.forEach(field => {
    const element = document.getElementById(field);

    if (element) {
      element.value = olympiad?.[field] ?? "";
    }
  });
}

function openEditor(id = null) {
  document.getElementById("editorTitle").textContent =
    id ? "Editar olimpíada" : "Nova olimpíada";

  fill(id);

  modalEditor.classList.remove("hidden");
}

async function remove(id) {
  if (!confirm("Excluir esta olimpíada?")) {
    return;
  }

  try {
    await request(`/api/olympiads/${id}`, {
      method: "DELETE"
    });

    message.textContent = "Olimpíada excluída com sucesso.";

    await load();

  } catch (e) {
    message.textContent = e.message;
  }
}

document
  .getElementById("newOlympiadButton")
  ?.addEventListener("click", () => {
    openEditor();
  });

document
  .getElementById("logoutButton")
  ?.addEventListener("click", async () => {

    if (!API || API.includes("SEU-WORKER-AQUI")) {
      return;
    }

    await request("/api/logout", {
      method: "POST"
    }).catch(() => {});

    window.location.href = "login.html";
  });

form?.addEventListener("submit", async event => {
  event.preventDefault();

  const id = document.getElementById("editId").value;

  const fields = [
    "acronym",
    "name",
    "area",
    "modality",
    "registration_method",
    "registration_deadline",
    "number_of_phases",
    "status",
    "phase_1_date",
    "phase_2_date",
    "phase_3_date",
    "phase_4_date",
    "extra"
  ];

  const payload = {};

  fields.forEach(field => {
    const element = document.getElementById(field);

    if (!element) {
      return;
    }

    const value = element.value;

    payload[field] =
      field === "number_of_phases" && value !== ""
        ? Number(value)
        : value;
  });

  try {
    await request(
      id
        ? `/api/olympiads/${id}`
        : "/api/olympiads",
      {
        method: id ? "PUT" : "POST",
        body: JSON.stringify(payload)
      }
    );

    modalEditor.classList.add("hidden");

    message.textContent =
      id
        ? "Olimpíada atualizada com sucesso."
        : "Olimpíada criada com sucesso.";

    await load();

  } catch (e) {
    message.textContent = e.message;
  }
});

init();
