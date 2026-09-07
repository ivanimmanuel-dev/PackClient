"use strict";
(() => {
  const dialog = document.querySelector("#figure-dialog");
  let opener = null;
  if (dialog && typeof dialog.showModal === "function") {
    const viewport = dialog.querySelector(".dialog-scroll");
    const scale = dialog.querySelector("#figure-scale");
    const resetScale = () => {
      viewport.classList.remove("native-size");
      viewport.scrollTop = viewport.scrollLeft = 0;
      scale.setAttribute("aria-pressed", "false");
      scale.textContent = "Native size";
    };
    document.querySelectorAll(".zoom-figure").forEach(link => {
      link.addEventListener("click", event => {
        // Retain ordinary link behavior for opening a figure in another tab.
        if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
        event.preventDefault();
        opener = link;
        const title = link.dataset.title || "Evidence figure";
        dialog.querySelector("#dialog-title").textContent = title;
        const img = dialog.querySelector("#dialog-image");
        img.src = link.href;
        img.alt = title + " " + (link.dataset.caption || "");
        dialog.querySelector("#dialog-caption").textContent = link.dataset.caption || "";
        dialog.querySelector("#dialog-original").href = link.href;
        resetScale();
        document.body.classList.add("dialog-open");
        dialog.showModal();
        dialog.querySelector(".close-dialog").focus();
      });
    });
    scale.addEventListener("click", () => {
      const native = viewport.classList.toggle("native-size");
      viewport.scrollTop = viewport.scrollLeft = 0;
      scale.setAttribute("aria-pressed", String(native));
      scale.textContent = native ? "Fit figure" : "Native size";
    });
    dialog.querySelector(".close-dialog").addEventListener("click", () => dialog.close());
    dialog.addEventListener("click", event => {
      if (event.target === dialog) {
        const r = dialog.getBoundingClientRect();
        if (event.clientX < r.left || event.clientX > r.right || event.clientY < r.top || event.clientY > r.bottom) dialog.close();
      }
    });
    dialog.addEventListener("close", () => {
      document.body.classList.remove("dialog-open");
      if (opener) opener.focus();
    });
  }
  const sections = [...document.querySelectorAll("article > .chapter")];
  const toc = [...document.querySelectorAll(".contents li a")];
  if (sections.length && toc.length) {
    let pending = false;
    const update = () => {
      let active = "";
      for (const section of sections) {
        if (section.getBoundingClientRect().top < innerHeight * 0.34) active = section.id;
      }
      for (const link of toc) {
        const match = link.hash === `#${active}`;
        link.classList.toggle("active", match);
        if (match) link.setAttribute("aria-current", "location");
        else link.removeAttribute("aria-current");
      }
      pending = false;
    };
    addEventListener("scroll", () => {
      if (!pending) { pending = true; requestAnimationFrame(update); }
    }, { passive: true });
    addEventListener("resize", update);
    update();
  }
  document.querySelectorAll(".mobile-toc a").forEach(link => {
    link.addEventListener("click", () => link.closest("details").removeAttribute("open"));
  });
})();
