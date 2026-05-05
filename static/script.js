/*
  script.js — Behaviour Layer
  Fortress Advisory Group — Browser Fingerprint Analyser
 
  This file controls WHAT the page does.
  It has no HTML structure and no CSS styling.
  It reads from the DOM (HTML elements) and the Flask API only.
 
  HOW IT CONNECTS:
  - Reads HTML elements using document.getElementById()
  - Sends data to Flask using the Fetch API (HTTP POST)
  - Updates HTML elements using .textContent (never .innerHTML — XSS risk)
 
  KEY SECURITY DECISION:
  All user-supplied data (browser attributes) is inserted into the DOM
  using .textContent exclusively. textContent treats the string as plain
  text — angle brackets become visible characters, not HTML tags.
  innerHTML would allow stored XSS attacks, as demonstrated by the
  vulnerability in the code review application (OWASP, 2021).
*/
 
"use strict";
/*
  Enables strict mode — catches common mistakes JavaScript would otherwise
  silently ignore. Always include this at the top of every JS file. 
  */

const analyseBtn = document.getElementById("analyseBtn");
const statusMsg  = document.getElementById("statusMsg");
const errorMsg   = document.getElementById("errorMsg");
const resultsDiv = document.getElementById("results");

/* Note resultsDiv not results — we avoid naming a variable the same as an HTML id, it can cause confusion in some browsers. */

analyseBtn.addEventListener("click", async () => {

  analyseBtn.disabled = // ??? (true or false — disable while running)
  errorMsg.style.display  = // ??? ("none" or "block" — hide previous errors)
  resultsDiv.style.display = // ??? ("none" or "block" — hide previous results)
  showStatus("Collecting browser attributes…");

  try {
    const attributes = await collectFingerprint();
    showStatus("Analysing your fingerprint…");
    const response = await submitFingerprint(attributes);

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || `Server returned ${response.status}`);
    }

    const data = await response.json();
    displayResults(data);

  } catch (err) {
    showError(`Something went wrong: ${err.message}`);

  } finally {
    analyseBtn.disabled = // ??? (re-enable when done)
    statusMsg.style.display = "none";
  }

});

async function collectFingerprint() {
  const attributes = {};

  attributes.user_agent           = safeGet(() => navigator.userAgent);
  attributes.language             = safeGet(() => navigator.language);
  attributes.platform             = safeGet(() => navigator.platform);
  attributes.hardware_concurrency = safeGet(() => String(navigator.hardwareConcurrency));
  attributes.pixel_ratio          = safeGet(() => String(window.devicePixelRatio));
  attributes.touch_points         = safeGet(() => String(navigator.maxTouchPoints));
  attributes.screen_resolution    = safeGet(() => `${screen.width}x${screen.height}`);
  attributes.color_depth          = safeGet(() => String(screen.colorDepth));
  attributes.timezone             = safeGet(() => Intl.DateTimeFormat().resolvedOptions().timeZone);
  attributes.canvas_hash          = await getCanvasFingerprint();

  return attributes;
}

function safeGet(accessor) {
  try {
    const value = accessor();
    if (value === null || value === undefined || value === "") {
      return "unavailable";
    }
    return String(value);
  } catch (e) {
    return "unavailable";
  }
}

async function getCanvasFingerprint() {
  try {
    const canvas  = document.createElement("canvas");
    canvas.width  = 200;
    canvas.height = 50;

    const ctx = canvas.getContext("2d");
    if (!ctx) return "unavailable";

    ctx.textBaseline = "top";
    ctx.font         = "14px Arial";
    ctx.fillStyle    = "#f60";
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = "#069";
    ctx.fillText("BrowserPrint", 2, 15);
    ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
    ctx.fillText("BrowserPrint", 4, 17);

    const dataURL    = canvas.toDataURL();
    const encoded    = new TextEncoder().encode(dataURL);
    const hashBuffer = await crypto.subtle.digest("SHA-256", encoded);
    const hashArray  = Array.from(new Uint8Array(hashBuffer));

    return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");

  } catch (e) {
    return "blocked";
  }
}

async function submitFingerprint(attributes) {
  return fetch("/fingerprint", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(attributes),
  });
}

function displayResults(data) {
  const { hash, uniqueness, attributes } = data;

  document.getElementById("hashDisplay").textContent    = hash;
  document.getElementById("uniquenessScore").textContent = `${uniqueness.uniqueness_pct}%`;
  document.getElementById("statTotal").textContent      = uniqueness.total_seen + 1;
  document.getElementById("statUnique").textContent     = uniqueness.unique_hashes;

  const pct   = uniqueness.uniqueness_pct;
  const total = uniqueness.total_seen + 1;
  document.getElementById("uniquenessLabel").textContent =
    pct <= 1
      ? "Your browser is highly unique — almost no-one else matches."
      : `${uniqueness.matching} of ${total} submissions share your fingerprint.`;

  buildAttributeTable(attributes);

  resultsDiv.style.display = "block";
  resultsDiv.scrollIntoView({ behavior: "smooth" });
}

function buildAttributeTable(attributes) {
  const table = document.getElementById("attrTable");
  table.innerHTML = "";

  const labels = {
    user_agent:           "User Agent",
    language:             "Language",
    platform:             "Platform",
    screen_resolution:    "Screen Resolution",
    color_depth:          "Colour Depth",
    timezone:             "Timezone",
    hardware_concurrency: "CPU Threads",
    pixel_ratio:          "Pixel Ratio",
    touch_points:         "Touch Points",
    canvas_hash:          "Canvas Hash",
  };

  for (const [key, label] of Object.entries(labels)) {
    const row   = table.insertRow();
    const cell1 = row.insertCell();
    const cell2 = row.insertCell();
    cell1.textContent = label;
    cell2.textContent = attributes[key] || "unavailable";
  }
}

function showStatus(msg) {
  statusMsg.textContent   = msg;
  statusMsg.style.display = "block";
}

function showError(msg) {
  errorMsg.textContent   = msg;
  errorMsg.style.display = "block";
}
