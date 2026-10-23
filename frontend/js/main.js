const menuToggle = document.getElementById("menuToggle");
const mainNav = document.getElementById("mainNav");

if (menuToggle && mainNav) {
  menuToggle.addEventListener("click", () => mainNav.classList.toggle("open"));
  mainNav.addEventListener("click", e => {
    if (e.target.closest("a")) mainNav.classList.remove("open");
  });
}

document.querySelectorAll("[data-close-modal], [data-close-editor]").forEach(btn => {
  btn.addEventListener("click", () => {
    const modal = btn.closest(".modal");
    if (modal) modal.classList.add("hidden");
  });
});

document.addEventListener("keydown", e => {
  if (e.key === "Escape") {
    document.querySelectorAll(".modal:not(.hidden)").forEach(m => m.classList.add("hidden"));
  }
});

/* Cabeçalho compacto + barra de progresso de leitura */
(function () {
  const header = document.querySelector(".site-header");
  const bar = document.createElement("div");
  bar.className = "progress";
  document.body.appendChild(bar);

  let waiting = false;
  function update() {
    const total = document.documentElement.scrollHeight - window.innerHeight;
    bar.style.transform = `scaleX(${total > 0 ? window.scrollY / total : 0})`;
    header?.classList.toggle("scrolled", window.scrollY > 20);
    waiting = false;
  }
  window.addEventListener("scroll", () => {
    if (!waiting) { waiting = true; requestAnimationFrame(update); }
  }, { passive: true });
  update();
})();

/* Revelação ao rolar (em sequência dentro de cada grupo) */
(function () {
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const groups = ".about-grid, .quick-grid, .document-grid";
  const singles = ".section-heading, .highlight > *, .toolbar, .panel-actions, .table-wrap";

  document.documentElement.classList.add("js");

  const targets = [];
  document.querySelectorAll(groups).forEach(g =>
    [...g.children].forEach((el, i) => { el.style.setProperty("--i", i); targets.push(el); })
  );
  document.querySelectorAll(singles).forEach(el => targets.push(el));
  targets.forEach(el => el.classList.add("reveal"));

  if (reduce || !("IntersectionObserver" in window)) {
    targets.forEach(el => el.classList.add("in"));
    return;
  }

  const io = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); }
    });
  }, { threshold: 0.12, rootMargin: "0px 0px -6% 0px" });

  targets.forEach(el => io.observe(el));
})();
