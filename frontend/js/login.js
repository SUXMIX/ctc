const loginForm = document.getElementById("loginForm");
const loginMessage = document.getElementById("loginMessage");
const API_URL_LOGIN = window.CTC_CONFIG?.API_URL || "";

loginForm?.addEventListener("submit", async (event) => {
  event.preventDefault();

  if (!API_URL_LOGIN || API_URL_LOGIN.includes("SEU-WORKER-AQUI")) {
    loginMessage.textContent = "A API ainda não foi configurada. A estrutura do login já está preparada.";
    return;
  }

  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value;

  try {
    const response = await fetch(`${API_URL_LOGIN}/api/login`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      credentials: "include",
      body: JSON.stringify({ email, password })
    });

    const data = await response.json();

    if (!response.ok) throw new Error(data.error || "Falha no login");

    window.location.href = "painel.html";
  } catch (error) {
    loginMessage.textContent = error.message;
  }
});
