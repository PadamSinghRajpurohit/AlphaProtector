"use strict";

const pages = {
  overview: "Login monitoring dashboard",
  breach: "Free email breach check",
  footprint: "Behind the Email",
  epieos: "Epieos email OSINT",
  password: "Password tester",
};

const sampleRecords = [
  ["2024-06-01 08:02:11", "alice", "192.168.1.10", "Success"],
  ["2024-06-01 08:14:33", "bob", "192.168.1.22", "Success"],
  ["2024-06-01 08:31:05", "carol", "10.0.0.5", "Success"],
  ["2024-06-01 08:45:50", "dave", "203.0.113.99", "Failed"],
  ["2024-06-01 08:46:12", "admin", "203.0.113.99", "Failed"],
  ["2024-06-01 08:46:44", "root", "203.0.113.99", "Failed"],
  ["2024-06-01 08:47:01", "admin", "203.0.113.99", "Failed"],
  ["2024-06-01 08:47:29", "alice", "203.0.113.99", "Failed"],
  ["2024-06-01 09:03:18", "eve", "172.16.0.8", "Success"],
  ["2024-06-01 09:15:44", "frank", "192.168.1.44", "Success"],
  ["2024-06-01 09:28:02", "grace", "10.0.0.12", "Success"],
  ["2024-06-01 09:41:57", "henry", "192.168.1.55", "Failed"],
  ["2024-06-01 10:05:30", "isabel", "10.0.0.21", "Success"],
  ["2024-06-01 10:22:14", "jack", "172.16.0.33", "Success"],
  ["2024-06-01 10:38:49", "karen", "192.168.1.66", "Success"],
  ["2024-06-01 11:00:05", "liam", "10.0.0.30", "Failed"],
  ["2024-06-01 11:17:33", "mia", "192.168.1.77", "Success"],
  ["2024-06-01 11:35:20", "noah", "172.16.0.50", "Success"],
  ["2024-06-01 11:52:08", "olivia", "10.0.0.44", "Success"],
  ["2024-06-01 12:10:47", "peter", "192.168.1.88", "Success"],
];

function appendCell(row, value, className = "") {
  const cell = document.createElement("td");
  cell.textContent = value;
  if (className) cell.className = className;
  row.append(cell);
}

function chartRow(container, label, count, max, kind, detail = "") {
  const row = document.createElement("div");
  row.className = "bar-row";
  const name = document.createElement("span");
  name.className = "bar-label";
  name.textContent = label;
  name.title = label;
  const track = document.createElement("div");
  track.className = "bar-track";
  const bar = document.createElement("div");
  bar.className = `bar-fill ${kind}`;
  bar.style.width = `${Math.max(count ? 5 : 0, (count / Math.max(max, 1)) * 100)}%`;
  track.append(bar);
  const value = document.createElement("span");
  value.className = "bar-value";
  value.textContent = String(count);
  value.title = detail;
  row.append(name, track, value);
  container.append(row);
}

const failedByIp = new Map();
const failedByUser = new Map();
const successfulCount = sampleRecords.filter((record) => record[3] === "Success").length;
const failedCount = sampleRecords.length - successfulCount;
for (const [, username, ip, result] of sampleRecords) {
  if (result !== "Failed") continue;
  failedByIp.set(ip, (failedByIp.get(ip) || 0) + 1);
  failedByUser.set(username, (failedByUser.get(username) || 0) + 1);
}
const suspiciousIpCounts = [...failedByIp.entries()].filter(([, count]) => count >= 5).sort((a, b) => b[1] - a[1]);

function riskLevel(count) {
  if (count >= 10) return "High";
  if (count >= 7) return "Medium";
  return "Low";
}

function renderDashboard() {
  document.getElementById("metric-total").textContent = String(sampleRecords.length);
  document.getElementById("metric-success").textContent = String(successfulCount);
  document.getElementById("metric-failed").textContent = String(failedCount);
  document.getElementById("metric-suspicious").textContent = String(suspiciousIpCounts.length);

  const resultsChart = document.getElementById("login-chart");
  chartRow(resultsChart, "Successful", successfulCount, sampleRecords.length, "bar-success", "Successful login events");
  chartRow(resultsChart, "Failed", failedCount, sampleRecords.length, "bar-failed", "Failed login events");

  const ipChart = document.getElementById("ip-chart");
  const ipEntries = [...failedByIp.entries()].sort((a, b) => b[1] - a[1]);
  const maxIpCount = Math.max(...ipEntries.map(([, count]) => count), 1);
  ipEntries.forEach(([ip, count]) => chartRow(ipChart, ip, count, maxIpCount, count >= 5 ? "bar-failed" : "bar-neutral", `${count} failed attempts`));

  const userList = document.getElementById("user-failures");
  [...failedByUser.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).forEach(([username, count]) => {
    const row = document.createElement("div");
    row.className = "user-failure-row";
    const user = document.createElement("span");
    user.textContent = username;
    const attempts = document.createElement("span");
    attempts.className = "attempt-count";
    attempts.textContent = `${count} failed`;
    row.append(user, attempts);
    userList.append(row);
  });

  renderAlerts();
  renderRecords();
}

function renderAlerts() {
  const container = document.getElementById("alerts-list");
  const filter = document.getElementById("risk-filter").value;
  container.replaceChildren();
  const entries = suspiciousIpCounts.filter(([, count]) => filter === "All" || riskLevel(count) === filter);
  if (!entries.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "No sample alerts match this risk filter.";
    container.append(empty);
    return;
  }
  entries.forEach(([ip, count]) => {
    const card = document.createElement("div");
    card.className = "alert-item";
    const title = document.createElement("strong");
    title.textContent = `Suspicious IP · ${riskLevel(count)}`;
    const detail = document.createElement("p");
    detail.textContent = `${ip} made ${count} failed attempts, trying ${sampleRecords.filter((row) => row[2] === ip && row[3] === "Failed").reduce((users, row) => users.add(row[1]), new Set()).size} different username(s). This meets the threshold of 5.`;
    card.append(title, detail);
    container.append(card);
  });
}

function renderRecords() {
  const tbody = document.getElementById("records-body");
  const filter = document.getElementById("result-filter").value;
  tbody.replaceChildren();
  sampleRecords.filter((record) => filter === "All" || record[3] === filter).forEach(([time, username, ip, result]) => {
    const row = document.createElement("tr");
    appendCell(row, time);
    appendCell(row, username);
    appendCell(row, ip);
    appendCell(row, result, result === "Success" ? "result-success" : "result-failed");
    tbody.append(row);
  });
}

document.getElementById("risk-filter").addEventListener("change", renderAlerts);
document.getElementById("result-filter").addEventListener("change", renderRecords);
document.getElementById("records-toggle").addEventListener("click", (event) => {
  const button = event.currentTarget;
  const wrapper = document.getElementById("records-wrap");
  const expanded = button.getAttribute("aria-expanded") === "true";
  button.setAttribute("aria-expanded", String(!expanded));
  wrapper.hidden = expanded;
  button.textContent = expanded ? "Show sample login records" : "Hide sample login records";
});
renderDashboard();

const pageTitle = document.getElementById("page-title");
const sideMenu = document.getElementById("sidebar");
const menuToggle = document.getElementById("menu-toggle");

function showPage(name) {
  if (!Object.hasOwn(pages, name)) return;
  document.querySelectorAll(".page").forEach((page) => {
    const active = page.id === `page-${name}`;
    page.hidden = !active;
    page.classList.toggle("active", active);
  });
  document.querySelectorAll("[data-page]").forEach((button) => {
    button.classList.toggle("active", button.dataset.page === name && button.classList.contains("nav-button"));
  });
  pageTitle.textContent = pages[name];
  history.replaceState(null, "", `#${name}`);
  sideMenu.classList.remove("open");
  menuToggle.setAttribute("aria-expanded", "false");
  window.scrollTo({ top: 0, behavior: "smooth" });
}

document.querySelectorAll("[data-page]").forEach((button) => {
  button.addEventListener("click", () => showPage(button.dataset.page));
});

menuToggle.addEventListener("click", () => {
  const open = sideMenu.classList.toggle("open");
  menuToggle.setAttribute("aria-expanded", String(open));
});

const initialPage = window.location.hash.slice(1);
if (Object.hasOwn(pages, initialPage)) showPage(initialPage);

function setResult(element, kind, title, message) {
  element.className = `result ${kind}`;
  element.replaceChildren();
  const heading = document.createElement("h3");
  heading.textContent = title;
  element.append(heading);
  const paragraph = document.createElement("p");
  paragraph.textContent = message;
  element.append(paragraph);
  element.hidden = false;
}

function setBusy(button, busy, busyText, idleText) {
  button.disabled = busy;
  button.textContent = busy ? busyText : idleText;
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
}

function breachNames(payload) {
  const groups = Array.isArray(payload?.breaches) ? payload.breaches : [];
  return groups.flatMap((group) => Array.isArray(group) ? group : [group])
    .filter((name) => typeof name === "string" && name.trim())
    .map((name) => name.trim());
}

document.getElementById("breach-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const email = document.getElementById("breach-email").value.trim();
  const result = document.getElementById("breach-result");
  const button = document.getElementById("breach-submit");
  if (!validEmail(email)) {
    setResult(result, "warning", "Check the email address", "Enter an address in a valid email format and try again.");
    return;
  }
  setBusy(button, true, "Checking…", "Check breaches");
  result.hidden = true;
  try {
    const url = `https://api.xposedornot.com/v1/check-email/${encodeURIComponent(email)}`;
    const response = await fetch(url, { headers: { Accept: "application/json" }, cache: "no-store" });
    if (response.status === 404) {
      setResult(result, "success", "No matches found", "XposedOrNot returned no breach matches for this address.");
    } else if (response.status === 429) {
      setResult(result, "warning", "Free lookup limit reached", "XposedOrNot has rate-limited this network. Wait before trying again.");
    } else if (!response.ok) {
      throw new Error(`The lookup service returned HTTP ${response.status}.`);
    } else {
      const payload = await response.json();
      const names = breachNames(payload);
      if (!names.length) {
        setResult(result, "success", "No matches found", "No breach matches were returned from XposedOrNot’s current dataset.");
      } else {
        result.className = "result warning";
        result.replaceChildren();
        const heading = document.createElement("h3");
        heading.textContent = `${names.length} breach match${names.length === 1 ? "" : "es"} found`;
        result.append(heading);
        const intro = document.createElement("p");
        intro.textContent = "This address appears in these records in XposedOrNot’s dataset:";
        result.append(intro);
        const list = document.createElement("ul");
        names.forEach((name) => {
          const item = document.createElement("li");
          item.textContent = name;
          list.append(item);
        });
        result.append(list);
        result.hidden = false;
      }
    }
  } catch (error) {
    setResult(result, "warning", "Could not complete the check", `${error.message} Check your internet connection, then retry. The service may also be temporarily unavailable.`);
  } finally {
    setBusy(button, false, "Checking…", "Check breaches");
  }
});

function scorePassword(password) {
  let score = 0;
  const suggestions = [];
  if (password.length >= 12) score += 1;
  else suggestions.push("Use at least 12 characters.");
  if (password.length >= 16) score += 1;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score += 1;
  else suggestions.push("Mix uppercase and lowercase letters, or use a longer passphrase.");
  if (/\d/.test(password) && /[^A-Za-z0-9]/.test(password)) score += 1;
  else suggestions.push("Add numbers and symbols, or use a longer passphrase.");
  if (new Set(password).size >= Math.min(8, password.length)) score += 1;
  return { score, suggestions };
}

async function checkPwnedPassword(password) {
  const bytes = new TextEncoder().encode(password);
  const digest = await crypto.subtle.digest("SHA-1", bytes);
  const hash = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, { cache: "no-store" });
  if (!response.ok) throw new Error(`HIBP returned HTTP ${response.status}.`);
  const lines = (await response.text()).split(/\r?\n/);
  for (const line of lines) {
    const [candidate, count] = line.trim().split(":");
    if (candidate?.toUpperCase() === suffix) return Number.parseInt(count, 10) || 0;
  }
  return 0;
}

document.getElementById("password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const password = document.getElementById("password-input").value;
  const result = document.getElementById("password-result");
  const button = document.getElementById("password-submit");
  if (!password) {
    setResult(result, "warning", "Enter a password", "Type a password to run the local strength estimate and exposure check.");
    return;
  }
  const strength = scorePassword(password);
  const labels = ["Very weak", "Weak", "Fair", "Good", "Strong", "Very strong"];
  setBusy(button, true, "Checking…", "Test password");
  setResult(result, "info", `Strength estimate: ${labels[strength.score]}`, "Checking HIBP’s compromised-password corpus…");
  try {
    const count = await checkPwnedPassword(password);
    result.className = `result ${count ? "warning" : "success"}`;
    result.replaceChildren();
    const heading = document.createElement("h3");
    heading.textContent = `Strength estimate: ${labels[strength.score]}`;
    result.append(heading);
    const status = document.createElement("p");
    status.textContent = count
      ? `This password appears ${count.toLocaleString()} times in known breach data. Do not use it.`
      : "No match was found in HIBP’s current compromised-password corpus.";
    status.className = count ? "status-bad" : "status-good";
    result.append(status);
    if (strength.suggestions.length) {
      const intro = document.createElement("p");
      intro.textContent = "Suggestions to improve it:";
      result.append(intro);
      const list = document.createElement("ul");
      strength.suggestions.forEach((suggestion) => {
        const item = document.createElement("li");
        item.textContent = suggestion;
        list.append(item);
      });
      result.append(list);
    }
    result.hidden = false;
  } catch (error) {
    setResult(result, "warning", `Strength estimate: ${labels[strength.score]}`, `The local estimate completed, but the free HIBP check failed: ${error.message} Check your connection and retry.`);
  } finally {
    setBusy(button, false, "Checking…", "Test password");
    document.getElementById("password-input").value = "";
  }
});

// Hosted authentication: Supabase's browser SDK stores and refreshes the session.
const authScreen = document.getElementById("auth-screen");
const appShell = document.getElementById("app-shell");
const authForm = document.getElementById("auth-form");
const authStatus = document.getElementById("auth-status");
const authSetup = document.getElementById("auth-setup");
const authMode = document.getElementById("auth-mode");
const authReset = document.getElementById("auth-reset");
const authName = document.getElementById("auth-name");
const authNameLabel = document.getElementById("name-label");
const authPassword = document.getElementById("auth-password");
const authSubmit = document.getElementById("auth-submit");
let supabaseClient = null;
let creatingAccount = false;

function showAuthMessage(element, kind, message) {
  element.className = `auth-message ${kind}`;
  element.textContent = message;
  element.hidden = false;
}

function setAuthView(user) {
  const signedIn = Boolean(user);
  authScreen.hidden = signedIn;
  appShell.hidden = !signedIn;
  if (signedIn) {
    const metadata = user.user_metadata || {};
    const displayName = metadata.display_name || metadata.full_name || metadata.name || user.email || "Account";
    document.getElementById("user-name").textContent = displayName;
  }
}

function setAccountMode(enabled) {
  creatingAccount = enabled;
  authName.hidden = !enabled;
  authNameLabel.hidden = !enabled;
  authPassword.autocomplete = enabled ? "new-password" : "current-password";
  authSubmit.textContent = enabled ? "Create account" : "Sign in";
  authMode.textContent = enabled ? "Already have an account? Sign in" : "Create an account";
  authReset.hidden = enabled;
  authStatus.hidden = true;
}

authMode.addEventListener("click", () => setAccountMode(!creatingAccount));

authForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!supabaseClient) return;
  const email = document.getElementById("auth-email").value.trim();
  const password = authPassword.value;
  if (!validEmail(email) || password.length < 8) {
    showAuthMessage(authStatus, "error", "Enter a valid email and a password with at least 8 characters.");
    return;
  }
  authSubmit.disabled = true;
  authSubmit.textContent = creatingAccount ? "Creating account…" : "Signing in…";
  authStatus.hidden = true;
  try {
    if (creatingAccount) {
      const displayName = authName.value.trim();
      if (!displayName) {
        showAuthMessage(authStatus, "error", "Enter your name to create your account.");
        return;
      }
      const { data, error } = await supabaseClient.auth.signUp({
        email,
        password,
        options: { data: { display_name: displayName }, emailRedirectTo: window.location.origin },
      });
      if (error) throw error;
      if (data.session) setAuthView(data.user);
      else showAuthMessage(authStatus, "success", "Account created. Check your email for the verification link, then sign in.");
    } else {
      const { data, error } = await supabaseClient.auth.signInWithPassword({ email, password });
      if (error) throw error;
      setAuthView(data.user);
    }
  } catch (error) {
    showAuthMessage(authStatus, "error", error.message || "Authentication failed. Check your details and try again.");
  } finally {
    authSubmit.disabled = false;
    authSubmit.textContent = creatingAccount ? "Create account" : "Sign in";
  }
});

authReset.addEventListener("click", async () => {
  if (!supabaseClient) return;
  const email = document.getElementById("auth-email").value.trim();
  if (!validEmail(email)) {
    showAuthMessage(authStatus, "error", "Enter your account email above, then choose forgot password.");
    return;
  }
  authReset.disabled = true;
  try {
    const { error } = await supabaseClient.auth.resetPasswordForEmail(email, { redirectTo: window.location.origin });
    if (error) throw error;
    showAuthMessage(authStatus, "success", "If an account exists for that address, Supabase will send a password reset link.");
  } catch (error) {
    showAuthMessage(authStatus, "error", error.message || "Could not send the reset link. Try again.");
  } finally {
    authReset.disabled = false;
  }
});

document.getElementById("sign-out").addEventListener("click", async () => {
  if (!supabaseClient) return;
  const { error } = await supabaseClient.auth.signOut();
  if (error) showAuthMessage(authStatus, "error", error.message || "Could not sign out.");
});

async function initializeHostedAuth() {
  const config = window.ALPHAPROTECTOR_SUPABASE || {};
  if (!config.url || !config.publishableKey) {
    authSetup.hidden = false;
    authSetup.textContent = "Hosted sign-in needs your Supabase project URL and public publishable key. Add both to supabase-config.js, then reload. Do not put a secret or service-role key in this file.";
    authSubmit.disabled = true;
    authMode.disabled = true;
    authReset.disabled = true;
    return;
  }
  try {
    const { createClient } = await import("https://esm.sh/@supabase/supabase-js@2");
    supabaseClient = createClient(config.url, config.publishableKey, {
      auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true },
    });
    const { data: { session }, error } = await supabaseClient.auth.getSession();
    if (error) throw error;
    setAuthView(session?.user || null);
    supabaseClient.auth.onAuthStateChange((_event, nextSession) => setAuthView(nextSession?.user || null));
  } catch (error) {
    showAuthMessage(authSetup, "error", `Could not connect to hosted sign-in: ${error.message || "check the project URL and browser connection"}`);
    authSetup.hidden = false;
  }
}

initializeHostedAuth();
