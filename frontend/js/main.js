const menuToggle = document.getElementById("menuToggle");
const mainNav = document.getElementById("mainNav");

if (menuToggle && mainNav) {
  menuToggle.addEventListener("click", () => mainNav.classList.toggle("open"));
}

document.querySelectorAll("[data-close-modal], [data-close-editor]").forEach(btn => {
  btn.addEventListener("click", () => {
    const modal = btn.closest(".modal");
    if (modal) modal.classList.add("hidden");
  });
});
