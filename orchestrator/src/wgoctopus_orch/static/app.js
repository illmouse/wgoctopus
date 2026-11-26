"use strict";
const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";
const root = document.documentElement;
const toast = (message) => {
  const region = document.querySelector(".toast-region");
  if (!region) return;
  const item = document.createElement("div");
  item.className = "toast";
  item.setAttribute("role", "status");
  item.textContent = message;
  region.append(item);
  setTimeout(() => item.remove(), 3200);
};
document.querySelectorAll("[data-relative-time]").forEach((element) => {
  const date = new Date(element.dataset.relativeTime);
  if (Number.isNaN(date.valueOf())) return;
  const seconds = Math.round((date - Date.now()) / 1000);
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  const units = [["year", 31536000], ["month", 2592000], ["week", 604800], ["day", 86400], ["hour", 3600], ["minute", 60]];
  const [unit, size] = units.find(([, amount]) => Math.abs(seconds) >= amount) || ["second", 1];
  element.textContent = rtf.format(Math.round(seconds / size), unit);
});
document.addEventListener("input", (event) => {
  if (!event.target.matches("[data-table-search]")) return;
  const query = event.target.value.trim().toLocaleLowerCase();
  document.querySelectorAll(event.target.dataset.tableSearch).forEach((row) => {
    row.hidden = !row.textContent.toLocaleLowerCase().includes(query);
  });
});
function selectTab(name, updateUrl = true) {
  const tab = [...document.querySelectorAll("[data-ui-tab]")].find((item) => item.dataset.uiTab === name);
  if (!tab) return;
  document.querySelectorAll("[data-ui-tab]").forEach((item) => item.setAttribute("aria-selected", String(item === tab)));
  document.querySelectorAll("[data-ui-panel]").forEach((panel) => { panel.hidden = panel.dataset.uiPanel !== name; });
  if (updateUrl) history.replaceState(null, "", `#${name}`);
}
if (document.querySelector("[data-ui-tab]")) {
  selectTab(location.hash.slice(1) || new URLSearchParams(location.search).get("tab") || "overview", false);
  addEventListener("hashchange", () => selectTab(location.hash.slice(1), false));
}
document.addEventListener("click", async (event) => {
  const themeToggle = event.target.closest("[data-theme-toggle]");
  if (themeToggle) {
    const next = root.getAttribute("data-bs-theme") === "dark" ? "light" : "dark";
    root.setAttribute("data-bs-theme", next);
    localStorage.setItem("wgoctopus-theme", next);
    return;
  }
  const tab = event.target.closest("[data-ui-tab]");
  if (tab) { selectTab(tab.dataset.uiTab); return; }
  if (event.target.closest("[data-logout]")) {
    await fetch("/auth/logout", { method: "POST", headers: { "X-CSRF-Token": csrf() } });
    location.href = "/login";
    return;
  }
  const openDialog = event.target.closest("[data-open-dialog]");
  if (openDialog) {
    const dialog = document.getElementById(openDialog.dataset.openDialog);
    if (dialog) dialog.showModal();
  }
  const closeDialog = event.target.closest("[data-close-dialog]");
  if (closeDialog) closeDialog.closest("dialog")?.close();
  if (event.target.matches("dialog")) {
    const bounds = event.target.getBoundingClientRect();
    if (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom) event.target.close();
  }
  const qrButton = event.target.closest("[data-show-qr]");
  if (qrButton) {
    document.getElementById("qr-image").src = qrButton.dataset.showQr;
    document.getElementById("qr-dialog").showModal();
    return;
  }
  const button = event.target.closest("[data-copy], [data-copy-config]");
  if (!button) return;
  try {
    let value = button.dataset.copy;
    if (button.dataset.copyConfig) {
      const response = await fetch(button.dataset.copyConfig);
      if (!response.ok) throw new Error("Could not load config");
      value = await response.text();
    }
    await navigator.clipboard.writeText(value);
    toast("Copied to clipboard");
  } catch (_) { toast("Copy failed — check clipboard permissions"); }
});
document.addEventListener("submit", (event) => {
  const form = event.target.closest("[data-confirm-form]");
  if (!form || form.dataset.confirmed === "yes") { if (form) delete form.dataset.confirmed; return; }
  event.preventDefault();
  const dialog = document.getElementById("confirm-dialog");
  dialog.querySelector("#confirm-question").textContent = form.dataset.confirmForm;
  dialog.showModal();
  dialog.addEventListener("close", function decide() {
    dialog.removeEventListener("close", decide);
    if (dialog.returnValue === "confirm") {
      form.dataset.confirmed = "yes";
      form.requestSubmit(event.submitter);
    }
  });
});
document.addEventListener("htmx:beforeRequest", (event) => {
  event.target.classList.add("is-loading");
  const activeForm = document.activeElement.closest("form");
  window.pendingToast = activeForm?.dataset.toastSuccess
    || activeForm?.closest("dialog")?.dataset.toastSuccess
    || document.querySelector("dialog[open]")?.dataset.toastSuccess || null;
});
document.addEventListener("htmx:afterRequest", (event) => {
  event.target.classList.remove("is-loading");
  if (!event.detail.successful) delete window.pendingToast;
});
document.addEventListener("htmx:afterSwap", (event) => {
  if (event.detail.target === document.body && document.querySelector("[data-ui-tab]")) {
    selectTab(location.hash.slice(1) || new URLSearchParams(location.search).get("tab") || "overview", false);
  }
  if (event.detail.target === document.body && window.pendingToast) {
    toast(window.pendingToast);
    delete window.pendingToast;
  }
  const error = event.detail.target?.querySelector(".error,[role='alert']");
  if (error) event.detail.target.closest("dialog")?.querySelector("input,select,textarea")?.focus();
});
document.addEventListener("htmx:afterRequest", (event) => {
  const elt = event.detail.elt;
  const form = elt.matches("form") ? elt : elt.closest("form");
  const dialog = document.querySelector("dialog[open]") || elt.closest("dialog");
  const message = elt.dataset.toastSuccess || form?.dataset.toastSuccess || dialog?.dataset.toastSuccess;
  if (!message || !event.detail.successful) return;
  if (event.detail.target === document.body) window.pendingToast = message;
  else { delete window.pendingToast; dialog?.close(); toast(message); }
});
document.addEventListener("htmx:confirm", (event) => {
  if (!event.detail.question) return;
  event.preventDefault();
  const dialog = document.getElementById("confirm-dialog");
  dialog.querySelector("#confirm-question").textContent = event.detail.question;
  dialog.showModal();
  dialog.addEventListener("close", function decide() {
    dialog.removeEventListener("close", decide);
    if (dialog.returnValue === "confirm") event.detail.issueRequest(true);
  });
});

document.addEventListener("htmx:configRequest", (e) => { e.detail.headers["X-CSRF-Token"] = csrf(); });
document.addEventListener("htmx:responseError", (e) => {
  if (e.detail.xhr.status === 401) location.href = "/login";
  else {
    const form = e.detail.elt.closest("form");
    const errors = form?.querySelector(".form-errors") || document.querySelector("dialog[open] .form-errors");
    if (errors && e.detail.xhr.status >= 400 && e.detail.xhr.status < 500) {
      const parsed = new DOMParser().parseFromString(e.detail.xhr.responseText, "text/html");
      errors.textContent = parsed.querySelector(".narrow p, .error, [role='alert']")?.textContent.trim()
        || (e.detail.xhr.status === 403 ? "You are not allowed to perform this action." : "Check the form and try again.");
      return;
    }
    toast(e.detail.xhr.status === 403 ? "You are not allowed to perform this action." : "The request could not be completed.");
  }
});

document.getElementById("login-form")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target, err = document.getElementById("login-error");
  err.hidden = true;
  const res = await fetch("/auth/login", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: form.username.value, password: form.password.value }),
  });
  if (res.ok) { location.href = "/"; return; }
  err.textContent = res.status === 429 ? "Too many attempts, try again later." : "Invalid username or password.";
  err.hidden = false;
});

const generator = document.getElementById("awg-generator");
if (generator) {
  const params = document.getElementById("awg-obfuscation");
  const findings = document.getElementById("awg-findings");
  const showFindings = (items) => {
    findings.replaceChildren(...items.map((item) => {
      const li = document.createElement("li");
      li.textContent = `${item.severity}: ${item.message}`;
      li.className = item.severity;
      return li;
    }));
  };
  const hStatus = (values) => {
    const ranges = [1, 2, 3, 4].map((i) => {
      const parts = String(values[`h${i}`] || "").split("-").map(Number);
      return parts.length === 1 ? [parts[0], parts[0]] : parts;
    });
    const clash = ranges.some(([lo, hi], i) => ranges.slice(i + 1).some(([a, b]) => Math.max(lo, a) <= Math.min(hi, b)));
    document.getElementById("awg-h-status").textContent = clash ? "clash — overlapping H ranges" : "ok — ranges do not overlap";
    document.getElementById("awg-h-status").className = clash ? "bad" : "ok";
  };
  document.querySelectorAll("[data-awg-tab]").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll("[data-awg-tab]").forEach((item) => item.setAttribute("aria-selected", String(item === tab)));
      document.querySelectorAll("[data-awg-panel]").forEach((panel) => { panel.hidden = panel.dataset.awgPanel !== tab.dataset.awgTab; });
    });
  });
  generator.elements.awg_version.addEventListener("change", (event) => {
    generator.elements.mtu.value = event.target.value === "2.0" ? 1500 : 1280;
  });
  const requestValidate = async () => {
    const values = JSON.parse(params.value);
    const form = new FormData(generator);
    const response = await fetch("/ui/instances/validate", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
      body: JSON.stringify({ awg_version: form.get("awg_version"), mtu: Number(form.get("mtu")), obfuscation: values }),
    });
    const result = await response.json();
    showFindings(result.findings || []);
    hStatus(values);
    return response.ok;
  };
  generator.elements.junk_level.addEventListener("input", (event) => {
    generator.elements.junk_level.nextElementSibling.value = event.target.value;
  });
  generator.elements.junk_preset.addEventListener("change", (event) => {
    if (event.target.value !== "") {
      generator.elements.junk_level.value = event.target.value;
      generator.elements.junk_level.nextElementSibling.value = event.target.value;
    }
  });
  generator.addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = new FormData(generator);
    const body = Object.fromEntries(form.entries());
    delete body.junk_preset;
    body.mtu = Number(body.mtu);
    body.junk_level = Number(body.junk_level);
    body.mimic_host = body.mimic_host || null;
    for (const key of ["s1", "s2", "s3", "s4"]) body[key] = body[key] ? Number(body[key]) : null;
    for (const key of ["narrow_h", "header_protection", "content_padding", "random_timings",
      "random_trailers", "disable_cookies", "disable_h", "unite_s"]) body[key] = form.has(key);
    try {
      const response = await fetch("/ui/instances/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf() },
        body: JSON.stringify(body),
      });
      const result = await response.json();
      if (result.obfuscation) params.value = JSON.stringify(result.obfuscation, null, 2);
      showFindings(result.findings || []);
      if (result.obfuscation) hStatus(result.obfuscation);
    } catch (_) {
      showFindings([{ severity: "error", message: "Generation request failed." }]);
    }
  });
  document.getElementById("awg-validate").addEventListener("click", async () => {
    try { await requestValidate(); }
    catch (_) { showFindings([{ severity: "error", message: "Enter valid JSON parameters." }]); }
  });
  document.getElementById("instance-create").addEventListener("submit", (event) => {
    const form = event.currentTarget;
    const generatorForm = new FormData(generator);
    form.elements.obfuscation_json.value = params.value === "{}" ? "" : params.value;
    form.elements.awg_version.value = generatorForm.get("awg_version");
    form.elements.mtu.value = generatorForm.get("mtu");
  });
}
