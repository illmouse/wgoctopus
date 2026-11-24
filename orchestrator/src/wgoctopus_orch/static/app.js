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
