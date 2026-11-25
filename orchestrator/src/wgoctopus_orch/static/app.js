"use strict";
const csrf = () => document.querySelector('meta[name="csrf-token"]')?.content || "";

document.addEventListener("htmx:configRequest", (e) => { e.detail.headers["X-CSRF-Token"] = csrf(); });
document.addEventListener("htmx:responseError", (e) => { if (e.detail.xhr.status === 401) location.href = "/login"; });

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

document.querySelector("[data-logout]")?.addEventListener("click", async () => {
  await fetch("/auth/logout", { method: "POST", headers: { "X-CSRF-Token": csrf() } });
  location.href = "/login";
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
