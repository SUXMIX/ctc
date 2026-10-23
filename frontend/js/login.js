const loginForm = document.getElementById("loginForm");
const loginMessage = document.getElementById("loginMessage");
const loginButton = document.getElementById("loginButton");
const loginCard = document.getElementById("loginCard");
const togglePass = document.getElementById("togglePass");
const passwordInput = document.getElementById("password");
const API_URL_LOGIN = window.CTC_CONFIG?.API_URL || "";

const apiReady = API_URL_LOGIN && !API_URL_LOGIN.includes("SEU-WORKER-AQUI");

function setLoading(on) {
  loginButton.disabled = on;
  loginButton.innerHTML = on ? '<span class="spinner"></span>Entrando...' : "Entrar";
}

function showError(text) {
  loginMessage.textContent = text;
  loginCard.classList.remove("shake");
  void loginCard.offsetWidth; // reinicia a animação
  loginCard.classList.add("shake");
}

togglePass?.addEventListener("click", () => {
  const show = passwordInput.type === "password";
  passwordInput.type = show ? "text" : "password";
  togglePass.textContent = show ? "🙈" : "👁";
  togglePass.setAttribute("aria-pressed", String(show));
  togglePass.setAttribute("aria-label", show ? "Ocultar senha" : "Mostrar senha");
});

/* Se já estiver logado, vai direto para o painel */
if (apiReady) {
  fetch(`${API_URL_LOGIN}/api/me`, { credentials: "include" })
    .then(r => r.json())
    .then(d => { if (d.authenticated) window.location.replace("painel.html"); })
    .catch(() => {});
}

loginForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  loginMessage.textContent = "";

  if (!apiReady) {
    showError("A API ainda não foi configurada em js/config.js.");
    return;
  }

  const email = document.getElementById("email").value.trim();
  const password = passwordInput.value;

  if (!email || !password) {
    showError("Preencha o e-mail e a senha.");
    return;
  }

  setLoading(true);

  try {
    const response = await fetch(`${API_URL_LOGIN}/api/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ email, password })
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) throw new Error(data.error || "E-mail ou senha incorretos.");

    loginMessage.style.color = "var(--g800)";
    loginMessage.textContent = "Acesso liberado! Redirecionando...";
    window.location.href = "painel.html";
  } catch (error) {
    setLoading(false);
    loginMessage.style.color = "";
    showError(error.message === "Failed to fetch"
      ? "Não foi possível conectar ao servidor. Tente de novo."
      : error.message);
  }
});
