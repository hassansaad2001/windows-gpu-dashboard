document.getElementById("f").addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const err = document.getElementById("err");
  const btn = e.target.querySelector("button");
  err.textContent = "";
  btn.disabled = true;
  try {
    const r = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Requested-With": "aidash" },
      body: JSON.stringify({ username: fd.get("username"), password: fd.get("password") }),
    });
    if (r.ok) { location.href = "/"; return; }
    const j = await r.json().catch(() => ({}));
    err.textContent = j.detail || "Sign-in failed.";
  } catch {
    err.textContent = "Cannot reach the server.";
  } finally {
    btn.disabled = false;
  }
});
