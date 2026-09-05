const API_URL = window.CTC_CONFIG?.API_URL || "";

let olympiads = [];

const tableBody = document.querySelector("#olympiadsTable tbody");
const mobileList = document.getElementById("mobileList");
const loading = document.getElementById("loading");
const errorBox = document.getElementById("error");
const searchInput = document.getElementById("searchInput");
const modal = document.getElementById("detailsModal");

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  }[c]));
}

function formatDate(value) {
  if (!value) return "—";

  const [y, m, d] = value.split("-");

  return y && m && d
    ? `${d}/${m}/${y}`
    : value;
}

function render(items) {
  tableBody.innerHTML = items.map(o => `
    <tr data-id="${o.id}">
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
        ${esc(o.modality) || "—"}
      </td>

      <td>
        ${esc(o.registration_method) || "—"}
      </td>

      <td>
        ${formatDate(o.registration_deadline)}
      </td>

      <td>
        ${o.number_of_phases ?? "—"}
      </td>

      <td>
        <span class="status">
          ${esc(o.status) || "—"}
        </span>
      </td>
    </tr>
  `).join("");

  mobileList.innerHTML = items.map(o => `
    <button class="mobile-item" data-id="${o.id}">
      <span>
        <strong>${esc(o.acronym)}</strong>
        ${esc(o.name)}
      </span>

      <span>
        ${esc(o.area) || "—"} →
      </span>
    </button>
  `).join("");

  document.querySelectorAll("[data-id]").forEach(el => {
    el.addEventListener("click", () => {
      openDetails(Number(el.dataset.id));
    });
  });
}

function openDetails(id) {
  const o = olympiads.find(item => item.id === id);

  if (!o) return;

  document.getElementById("modalArea").textContent =
    o.area || "Oportunidade";

  document.getElementById("modalTitle").textContent =
    `${o.acronym} — ${o.name}`;

  const details = [
    ["Área", o.area],
    ["Modalidade", o.modality],
    ["Forma de inscrição", o.registration_method],
    ["Prazo de inscrição", formatDate(o.registration_deadline)],
    ["Número de fases", o.number_of_phases],
    ["Fase 1", formatDate(o.phase_1_date)],
    ["Fase 2", formatDate(o.phase_2_date)],
    ["Fase 3", formatDate(o.phase_3_date)],
    ["Fase 4", formatDate(o.phase_4_date)],
    ["Status", o.status],
    ["Observações", o.extra]
  ];

  document.getElementById("modalDetails").innerHTML = details
    .filter(([, value]) =>
      value !== null &&
      value !== undefined &&
      value !== ""
    )
    .map(([label, value]) => `
      <div class="detail">
        <small>${esc(label)}</small>
        <strong>${esc(value)}</strong>
      </div>
    `)
    .join("");

  modal.classList.remove("hidden");
}

async function loadOlympiads() {
  if (!API_URL || API_URL.includes("SEU-WORKER-AQUI")) {
    loading.classList.add("hidden");
    errorBox.classList.remove("hidden");
    return;
  }

  try {
    const response = await fetch(
      `${API_URL}/api/olympiads`
    );

    if (!response.ok) {
      throw new Error("Não foi possível carregar os dados.");
    }

    const result = await response.json();

    /*
      O Worker retorna:

      {
        olympiads: [...]
      }

      Portanto, precisamos pegar somente o array.
    */
    if (!Array.isArray(result.olympiads)) {
      throw new Error("Formato de dados inválido.");
    }

    olympiads = result.olympiads;

    loading.classList.add("hidden");
    errorBox.classList.add("hidden");

    render(olympiads);

  } catch (error) {
    console.error("Erro ao carregar olimpíadas:", error);

    loading.classList.add("hidden");
    errorBox.classList.remove("hidden");
  }
}

searchInput?.addEventListener("input", () => {
  const term = searchInput.value
    .toLowerCase()
    .trim();

  const filtered = olympiads.filter(o =>
    [
      o.acronym,
      o.name,
      o.area,
      o.modality,
      o.status
    ].some(value =>
      String(value ?? "")
        .toLowerCase()
        .includes(term)
    )
  );

  render(filtered);
});

loadOlympiads();
