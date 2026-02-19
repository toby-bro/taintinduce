// ─────────────────────────────────────────────────────────────────────────────
// M-Replica tab  –  state, rendering, and API calls
// ─────────────────────────────────────────────────────────────────────────────

// ── tab-local state ──────────────────────────────────────────────────────────
let mrCells = []; // [{mask, value}] – mirrors backend
let mrInputMode = "bits"; // 'bits' | 'hex'
let mrIsTaintMode = true; // true = taint marking, false = value editing
let mrTaintBits = new Set(); // "reg:bit" strings
let mrAutoAdapt = false; // when true: adapt M-Replica on every taint change
let mrFocusedCell = null; // {register, bit} for edit-mode keyboard nav

let mrZoom = 1;
let mrPanX = 0;
let mrPanY = 0;
let mrIsPanning = false;
let mrPanStart = { x: 0, y: 0 };
let mrSimResult = null; // last simulate response

// ── init ──────────────────────────────────────────────────────────────────────
function initMReplicaTab() {
  if (!currentRuleData) return;
  mrRenderInputRegisters();
  mrRefreshCellList();
  mrRunSimulation();
  mrRenderMatrix();
}

// ─────────────────────────────────────────────────────────────────────────────
// Input panel  (re-uses the same pattern as simulator.js)
// ─────────────────────────────────────────────────────────────────────────────
function mrSwitchInputMode(mode) {
  mrInputMode = mode;
  const bitDiv = document.getElementById("mr-bit-input-mode");
  const hexDiv = document.getElementById("mr-hex-input-mode");
  const btnBit = document.getElementById("mrBtnBits");
  const btnHex = document.getElementById("mrBtnHex");
  const active = "#667eea",
    inactive = "#e0e0e0",
    inactiveText = "#333";
  if (mode === "bits") {
    bitDiv.style.display = "block";
    hexDiv.style.display = "none";
    btnBit.style.cssText = `background:${active};color:white;`;
    btnHex.style.cssText = `background:${inactive};color:${inactiveText};`;
  } else {
    bitDiv.style.display = "block";
    hexDiv.style.display = "block";
    btnBit.style.cssText = `background:${inactive};color:${inactiveText};`;
    btnHex.style.cssText = `background:${active};color:white;`;
  }
}

function mrToggleMode() {
  mrIsTaintMode = !mrIsTaintMode;
  const btn = document.getElementById("mrBtnToggleMode");
  const desc = document.getElementById("mrModeDesc");
  const adaptBtn = document.getElementById("mrBtnAdapt");
  if (mrIsTaintMode) {
    btn.textContent = "🎨 Taint Mode";
    btn.style.background = "#ff9800";
    desc.textContent =
      'Click bits to mark tainted (orange). Use "Adapt M-Replica" to generate cells from the current taint selection.';
    desc.style.color = "#ff9800";
    adaptBtn.style.display = "inline-block";
  } else {
    btn.textContent = "📝 Edit Mode";
    btn.style.background = "#667eea";
    desc.textContent =
      "Click a bit then type 0/1. Arrow keys and Enter to navigate.";
    desc.style.color = "#667eea";
    adaptBtn.style.display = "none";
    // Reset auto-adapt when leaving taint mode
    if (mrAutoAdapt) {
      mrAutoAdapt = false;
      adaptBtn.textContent = "🔗 Auto-Adapt: OFF";
      adaptBtn.style.background = "#e84393";
      adaptBtn.style.outline = "none";
      adaptBtn.style.boxShadow = "none";
    }
    // Clear focus
    if (mrFocusedCell) {
      const el = document.querySelector(
        `[data-mr-reg="${mrFocusedCell.register}"][data-mr-bit="${mrFocusedCell.bit}"]`,
      );
      if (el) el.style.outline = "none";
      mrFocusedCell = null;
    }
  }
}

function mrRenderInputRegisters() {
  if (!currentRuleData) return;
  const container = document.getElementById("mr-register-inputs");
  if (!container) return;
  let html = "";
  currentRuleData.format.registers.forEach((reg) => {
    html += `<div class="mr-reg-box">
      <div class="mr-reg-title">${reg.name} <span style="font-weight:400;font-size:12px;color:#888">(${reg.bits} bits)</span></div>
      <div class="mr-bit-row">`;
    for (let b = reg.bits - 1; b >= 0; b--) {
      const key = `${reg.name}:${b}`;
      const tainted = mrTaintBits.has(key);
      const flag = getFlagName(reg.name, b);
      html += `<div class="mr-bit-wrapper">
        ${flag ? `<div class="mr-flag-label">${flag}</div>` : '<div class="mr-flag-label">&nbsp;</div>'}
        <div class="mr-bit-cell ${tainted ? "mr-tainted" : ""}"
             data-mr-reg="${reg.name}" data-mr-bit="${b}"
             onclick="mrToggleBit('${reg.name}',${b},event)"
             title="${reg.name}[${b}]${flag ? " (" + flag + ")" : ""}">
          <span class="mr-bit-idx">${b}</span>
          <span id="mrv-${reg.name}-${b}">0</span>
        </div></div>`;
    }
    html += `</div>
      <div class="mr-reg-actions">
        <button onclick="mrSetRegHex('${reg.name}')" class="mr-mini-btn">Set Hex</button>
        <button onclick="mrTaintReg('${reg.name}')" class="mr-mini-btn mr-mini-orange">Taint All</button>
        <button onclick="mrClearReg('${reg.name}')" class="mr-mini-btn mr-mini-gray">Clear</button>
      </div>
    </div>`;
  });
  container.innerHTML = html;
}

function mrToggleBit(reg, bit, event) {
  if (event && event.shiftKey) {
    mrToggleTaintBit(reg, bit);
    return;
  }
  if (mrIsTaintMode) mrToggleTaintBit(reg, bit);
  else mrFocusBitCell(reg, bit);
}

function mrToggleTaintBit(reg, bit) {
  const key = `${reg}:${bit}`;
  const el = document.querySelector(
    `[data-mr-reg="${reg}"][data-mr-bit="${bit}"]`,
  );
  if (mrTaintBits.has(key)) {
    mrTaintBits.delete(key);
    el && el.classList.remove("mr-tainted");
  } else {
    mrTaintBits.add(key);
    el && el.classList.add("mr-tainted");
  }
  mrRunSimulation();
  mrAdaptIfAuto();
}

function mrToggleAutoAdapt() {
  mrAutoAdapt = !mrAutoAdapt;
  const btn = document.getElementById("mrBtnAdapt");
  if (mrAutoAdapt) {
    btn.textContent = "🔗 Auto-Adapt: ON";
    btn.style.background = "#e84393";
    btn.style.outline = "3px solid #fff";
    btn.style.boxShadow = "0 0 8px #e84393";
    mrAdaptToTaint(); // apply immediately
  } else {
    btn.textContent = "🔗 Auto-Adapt: OFF";
    btn.style.background = "#9e4370";
    btn.style.outline = "none";
    btn.style.boxShadow = "none";
  }
}

function mrAdaptIfAuto() {
  if (mrAutoAdapt) mrAdaptToTaint();
}

function mrFocusBitCell(reg, bit) {
  if (mrFocusedCell) {
    const prev = document.querySelector(
      `[data-mr-reg="${mrFocusedCell.register}"][data-mr-bit="${mrFocusedCell.bit}"]`,
    );
    if (prev) prev.style.outline = "none";
  }
  const el = document.querySelector(
    `[data-mr-reg="${reg}"][data-mr-bit="${bit}"]`,
  );
  if (el) {
    el.style.outline = "2px solid #667eea";
    el.style.outlineOffset = "-2px";
  }
  mrFocusedCell = { register: reg, bit };
}

function mrSetBitValue(reg, bit, val) {
  const el = document.getElementById(`mrv-${reg}-${bit}`);
  if (el) el.textContent = val;
  mrUpdateHexFromBits();
  mrRunSimulation();
}

function mrTaintAll() {
  if (!currentRuleData) return;
  currentRuleData.format.registers.forEach((reg) => {
    for (let b = 0; b < reg.bits; b++) {
      const key = `${reg.name}:${b}`;
      mrTaintBits.add(key);
      const el = document.querySelector(
        `[data-mr-reg="${reg.name}"][data-mr-bit="${b}"]`,
      );
      if (el) el.classList.add("mr-tainted");
    }
  });
  mrRunSimulation();
  mrAdaptIfAuto();
}

function mrClearTaint() {
  mrTaintBits.clear();
  document
    .querySelectorAll(".mr-bit-cell")
    .forEach((el) => el.classList.remove("mr-tainted"));
  mrRunSimulation();
  mrAdaptIfAuto();
}

function mrTaintReg(regName) {
  if (!currentRuleData) return;
  const reg = currentRuleData.format.registers.find((r) => r.name === regName);
  if (!reg) return;
  const allTainted = [...Array(reg.bits)].every((_, b) =>
    mrTaintBits.has(`${regName}:${b}`),
  );
  for (let b = 0; b < reg.bits; b++) {
    const key = `${regName}:${b}`;
    const el = document.querySelector(
      `[data-mr-reg="${regName}"][data-mr-bit="${b}"]`,
    );
    if (allTainted) {
      mrTaintBits.delete(key);
      el && el.classList.remove("mr-tainted");
    } else {
      mrTaintBits.add(key);
      el && el.classList.add("mr-tainted");
    }
  }
  mrRunSimulation();
  mrAdaptIfAuto();
}

function mrClearReg(regName) {
  if (!currentRuleData) return;
  const reg = currentRuleData.format.registers.find((r) => r.name === regName);
  if (!reg) return;
  for (let b = 0; b < reg.bits; b++) {
    const key = `${regName}:${b}`;
    mrTaintBits.delete(key);
    const el = document.querySelector(
      `[data-mr-reg="${regName}"][data-mr-bit="${b}"]`,
    );
    if (el) el.classList.remove("mr-tainted");
    const vel = document.getElementById(`mrv-${regName}-${b}`);
    if (vel) vel.textContent = "0";
  }
  mrUpdateHexFromBits();
  mrRunSimulation();
}

function mrSetRegHex(regName) {
  const val = prompt(`Enter hex value for ${regName}:`);
  if (val == null) return;
  if (!currentRuleData) return;
  const reg = currentRuleData.format.registers.find((r) => r.name === regName);
  if (!reg) return;
  try {
    const n = parseInt(val, val.startsWith("0x") ? 16 : 10);
    for (let b = 0; b < reg.bits; b++) {
      const el = document.getElementById(`mrv-${regName}-${b}`);
      if (el) el.textContent = (n >> b) & 1;
    }
    mrUpdateHexFromBits();
    mrRunSimulation();
  } catch {
    alert("Invalid value");
  }
}

function mrUpdateHexFromBits() {
  if (!currentRuleData) return;
  const hexInput = document.getElementById("mr-input-hex");
  if (!hexInput) return;
  let val = 0n,
    offset = 0;
  currentRuleData.format.registers.forEach((reg) => {
    for (let b = 0; b < reg.bits; b++) {
      const el = document.getElementById(`mrv-${reg.name}-${b}`);
      if (el && el.textContent === "1") val |= 1n << BigInt(offset + b);
    }
    offset += reg.bits;
  });
  hexInput.value = "0x" + val.toString(16).toUpperCase();
}

function mrUpdateBitsFromHex() {
  const hexInput = document.getElementById("mr-input-hex");
  if (!hexInput || !currentRuleData) return;
  const raw = hexInput.value.trim();
  if (!raw || raw === "0x" || raw === "0X") return;
  try {
    const hexDigits =
      raw.startsWith("0x") || raw.startsWith("0X") ? raw.substring(2) : raw;
    if (!/^[0-9a-fA-F]*$/.test(hexDigits)) return;
    const val = raw.startsWith("0") ? BigInt(raw) : BigInt(raw);
    let offset = 0;
    currentRuleData.format.registers.forEach((reg) => {
      for (let b = 0; b < reg.bits; b++) {
        const el = document.getElementById(`mrv-${reg.name}-${b}`);
        if (el) el.textContent = ((val >> BigInt(offset + b)) & 1n).toString();
      }
      offset += reg.bits;
    });
    mrRunSimulation();
  } catch {
    /* ignore partial input */
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cell management
// ─────────────────────────────────────────────────────────────────────────────
async function mrRefreshCellList() {
  const r = await fetch("/api/mreplica");
  const data = await r.json();
  mrCells = data.cells || [];
  mrRenderCellList();
}

function mrRenderCellList() {
  const container = document.getElementById("mr-cell-list");
  if (!container) return;
  if (mrCells.length === 0) {
    container.innerHTML =
      '<p style="color:#888;font-style:italic;padding:10px;">No cells yet.</p>';
    return;
  }
  const numBits = currentRuleData
    ? currentRuleData.format.registers.reduce((a, r) => a + r.bits, 0)
    : 32;
  let html = `<div style="font-size:12px;color:#888;margin-bottom:6px">${mrCells.length} cell${mrCells.length === 1 ? "" : "s"}</div>`;
  html += '<div class="mr-cell-table">';
  html +=
    '<div class="mr-cell-row mr-cell-header"><span>Mask (hex)</span><span>Value (hex)</span><span>Active bits</span><span></span></div>';
  mrCells.forEach((cell) => {
    const maskBits = [...Array(numBits)]
      .map((_, i) =>
        (cell.mask >> i) & 1 ? ((cell.value >> i) & 1 ? "1" : "0") : "·",
      )
      .reverse()
      .join("");
    html += `<div class="mr-cell-row">
      <span class="mr-mono">0x${cell.mask.toString(16)}</span>
      <span class="mr-mono">0x${cell.value.toString(16)}</span>
      <span class="mr-mono mr-maskbits" title="Bit pattern (MSB→LSB: · = pass-through)">${maskBits}</span>
      <span><button class="mr-del-btn" onclick="mrDeleteCell(${cell.mask},${cell.value})">✕</button></span>
    </div>`;
  });
  html += "</div>";
  container.innerHTML = html;
}

async function mrAddCellDialog() {
  const maskStr = prompt("Mask (hex or decimal, e.g. 0xFF or 255):");
  if (maskStr == null) return;
  const valueStr = prompt("Value (hex or decimal):");
  if (valueStr == null) return;
  try {
    const mask = parseInt(maskStr, maskStr.startsWith("0x") ? 16 : 10);
    const value = parseInt(valueStr, valueStr.startsWith("0x") ? 16 : 10);
    await mrAPIAddCell(mask, value);
  } catch {
    alert("Invalid input");
  }
}

async function mrAPIAddCell(mask, value) {
  await fetch("/api/mreplica/add-cell", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mask, value }),
  });
  await mrRefreshCellList();
  mrRunSimulation();
}

async function mrDeleteCell(mask, value) {
  await fetch("/api/mreplica/delete-cell", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mask, value }),
  });
  await mrRefreshCellList();
  mrRunSimulation();
}

async function mrResetCells() {
  await fetch("/api/mreplica/reset", { method: "POST" });
  await mrRefreshCellList();
  mrRunSimulation();
}

async function mrMakeFullDialog() {
  // Build a bit selector from the current register format
  const bits_mask = mrGetMakeFullMask();
  if (bits_mask === 0) {
    alert(
      'Please select at least one bit. Use the bit selector below the "Make Full" button or set bits in the input panel.',
    );
    return;
  }
  const n = popcount(bits_mask);
  if (n > 16) {
    if (
      !confirm(
        `This will generate 2^${n} = ${Math.pow(2, n).toLocaleString()} cells. Proceed?`,
      )
    )
      return;
  }
  await fetch("/api/mreplica/make-full", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ bits_mask }),
  });
  await mrRefreshCellList();
  mrRunSimulation();
}

function popcount(n) {
  let c = 0;
  while (n) {
    c += n & 1;
    n >>>= 1;
  }
  return c;
}

function mrGetMakeFullMask() {
  // Read from the "make-full bits selector" checkboxes
  let mask = 0;
  document.querySelectorAll(".mr-makebit-cb:checked").forEach((cb) => {
    mask |= 1 << parseInt(cb.dataset.bitpos);
  });
  return mask;
}

function mrRenderMakeFullSelector() {
  if (!currentRuleData) return;
  const container = document.getElementById("mr-makebit-selector");
  if (!container) return;
  let html =
    '<div style="display:flex;flex-wrap:wrap;gap:6px;align-items:flex-end">';
  let bitPos = 0;
  currentRuleData.format.registers.forEach((reg) => {
    html += `<div style="background:#f8f9fa;border-radius:6px;padding:6px 10px;border:1px solid #dee2e6">
      <div style="font-size:11px;font-weight:bold;color:#667eea;margin-bottom:4px">${reg.name}</div>
      <div style="display:flex;gap:3px;flex-wrap:wrap">`;
    for (let b = reg.bits - 1; b >= 0; b--) {
      const pos = bitPos + b;
      html += `<label style="display:flex;flex-direction:column;align-items:center;cursor:pointer">
        <span style="font-size:9px;color:#888">${b}</span>
        <input type="checkbox" class="mr-makebit-cb" data-bitpos="${pos}" style="cursor:pointer">
      </label>`;
    }
    html += "</div></div>";
    bitPos += reg.bits;
  });
  html += "</div>";
  container.innerHTML = html;
}

// ─────────────────────────────────────────────────────────────────────────────
// Adapt M-Replica to current taint selection
// ─────────────────────────────────────────────────────────────────────────────
async function mrAdaptToTaint() {
  const taintedList = [];
  mrTaintBits.forEach((key) => {
    const [reg, bit] = key.split(":");
    taintedList.push([reg, parseInt(bit)]);
  });
  if (taintedList.length === 0) {
    alert("No bits are tainted. Mark some bits first.");
    return;
  }
  const n = taintedList.length;
  if (n > 16) {
    if (
      !confirm(
        `This will generate 2^${n} = ${Math.pow(2, n).toLocaleString()} cells. Proceed?`,
      )
    )
      return;
  }
  const r = await fetch("/api/mreplica/adapt", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ tainted_bits: taintedList }),
  });
  const data = await r.json();
  if (data.error) {
    alert("Error: " + data.error);
    return;
  }
  await mrRefreshCellList();
  mrRunSimulation();
}

// ─────────────────────────────────────────────────────────────────────────────
// Simulation  →  matrix rendering
// ─────────────────────────────────────────────────────────────────────────────
let _mrSimTimer = null;
function mrRunSimulation() {
  clearTimeout(_mrSimTimer);
  _mrSimTimer = setTimeout(_mrDoSimulation, 80);
}

async function _mrDoSimulation() {
  if (!currentRuleData) return;
  const inputVal = mrGetInputStateInt();
  const r = await fetch("/api/mreplica/simulate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ input_state: inputVal }),
  });
  if (!r.ok) {
    console.error("M-Replica simulation failed");
    return;
  }
  mrSimResult = await r.json();
  mrRenderMatrix();
  mrRenderOutputPanel();
}

function mrGetInputStateInt() {
  if (!currentRuleData) return 0;
  let val = 0n,
    offset = 0;
  currentRuleData.format.registers.forEach((reg) => {
    for (let b = 0; b < reg.bits; b++) {
      const el = document.getElementById(`mrv-${reg.name}-${b}`);
      if (el && el.textContent === "1") val |= 1n << BigInt(offset + b);
    }
    offset += reg.bits;
  });
  return Number(val);
}

// ─────────────────────────────────────────────────────────────────────────────
// Matrix visualization (SVG)
// ─────────────────────────────────────────────────────────────────────────────
const MR_CELL_W = 22,
  MR_CELL_H = 26,
  MR_ROW_LABEL_W = 130,
  MR_HEADER_H = 44;

function mrRenderMatrix() {
  const svg = document.getElementById("mr-matrix-svg");
  if (!svg) return;
  if (!currentRuleData) {
    svg.innerHTML =
      '<text x="20" y="30" fill="#888" font-size="14">Load a rule first.</text>';
    return;
  }

  const regs = currentRuleData.format.registers;
  const numBits = regs.reduce((a, r) => a + r.bits, 0);
  const cells = mrSimResult
    ? mrSimResult.cell_results
    : mrCells.map((c) => ({ ...c, output: null, contributes_to_taint: false }));
  const taintOut = mrSimResult ? mrSimResult.taint_output : 0;
  const inputVal = mrGetInputStateInt();

  // --- layout dimensions ---
  const numRows = cells.length + 2; // header(input) + cells + footer(taint)
  const W = MR_ROW_LABEL_W + numBits * MR_CELL_W + 10;
  const H = MR_HEADER_H + numRows * MR_CELL_H + 60;
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("width", W);
  svg.setAttribute("height", H);

  let s = "";

  // --- register name headers (column groups) ---
  let bOff = 0;
  regs.forEach((reg) => {
    const x = MR_ROW_LABEL_W + (numBits - bOff - reg.bits) * MR_CELL_W;
    const gw = reg.bits * MR_CELL_W;
    s += `<rect x="${x}" y="5" width="${gw - 2}" height="17" rx="3" fill="#e8eaff"/>`;
    s += `<text x="${x + gw / 2}" y="17" text-anchor="middle" font-size="11" font-weight="bold" fill="#667eea">${reg.name}</text>`;
    bOff += reg.bits;
  });

  // -- bit index header --
  for (let b = numBits - 1; b >= 0; b--) {
    const col = numBits - 1 - b;
    const cx = MR_ROW_LABEL_W + col * MR_CELL_W + MR_CELL_W / 2;
    s += `<text x="${cx}" y="${MR_HEADER_H - 6}" text-anchor="middle" font-size="8" fill="#aaa">${b}</text>`;
  }

  // helper: draw one data row
  function drawRow(rowIdx, label, labelColor, getValue, getBg, rowBg) {
    const y = MR_HEADER_H + rowIdx * MR_CELL_H;
    if (rowBg)
      s += `<rect x="0" y="${y}" width="${W}" height="${MR_CELL_H}" fill="${rowBg}"/>`;
    s += `<text x="${MR_ROW_LABEL_W - 6}" y="${y + MR_CELL_H / 2 + 4}" text-anchor="end" font-size="11" fill="${labelColor}" font-weight="bold">${label}</text>`;
    for (let b = numBits - 1; b >= 0; b--) {
      const col = numBits - 1 - b;
      const cx = MR_ROW_LABEL_W + col * MR_CELL_W;
      const cy = y;
      const bg = getBg(b);
      const v = getValue(b);
      s += `<rect x="${cx + 1}" y="${cy + 1}" width="${MR_CELL_W - 2}" height="${MR_CELL_H - 2}" rx="2" fill="${bg}"/>`;
      s += `<text x="${cx + MR_CELL_W / 2}" y="${cy + MR_CELL_H / 2 + 4}" text-anchor="middle" font-size="11" fill="white" font-weight="bold">${v}</text>`;
    }
  }

  // Row 0: INPUT state
  drawRow(
    0,
    "INPUT",
    "#555",
    (b) => (inputVal >> b) & 1,
    (b) => {
      const tainted = mrTaintBits.has(mrBitToKey(b, regs));
      return tainted ? "#ff9800" : (inputVal >> b) & 1 ? "#28a745" : "#adb5bd";
    },
    "#f0f4ff",
  );

  // Rows 1..N: cells
  cells.forEach((cell, idx) => {
    const rowBg = idx % 2 === 0 ? "white" : "#fafafa";
    const active = cell.contributes_to_taint;
    const label = `#${idx + 1} m:${cell.mask.toString(16)} v:${cell.value.toString(16)}`;
    drawRow(
      idx + 1,
      label,
      active ? "#d63031" : "#636e72",
      (b) => {
        // output value if we have it, else show the masked/input bit
        if (cell.output != null) return (cell.output >> b) & 1;
        if ((cell.mask >> b) & 1) return (cell.value >> b) & 1;
        return (inputVal >> b) & 1;
      },
      (b) => {
        const isMasked = (cell.mask >> b) & 1;
        const outVal =
          cell.output != null
            ? (cell.output >> b) & 1
            : isMasked
              ? (cell.value >> b) & 1
              : (inputVal >> b) & 1;
        const taintedBit = (taintOut >> b) & 1;
        if (isMasked && active) return outVal ? "#e17055" : "#b2bec3"; // active cell: orange-red / gray
        if (isMasked) return outVal ? "#74b9ff" : "#dfe6e9"; // inactive masked
        return outVal ? "#55efc4" : "#dfe6e9"; // pass-through
      },
      active ? "#fff5f5" : rowBg,
    );
  });

  // Footer row: TAINT output
  const taintRowIdx = cells.length + 1;
  drawRow(
    taintRowIdx,
    "⊕ TAINT",
    "#d63031",
    (b) => (taintOut >> b) & 1,
    (b) => ((taintOut >> b) & 1 ? "#d63031" : "#dfe6e9"),
    "#fff0f0",
  );

  // Separator lines
  s += `<line x1="${MR_ROW_LABEL_W}" y1="${MR_HEADER_H}" x2="${W}" y2="${MR_HEADER_H}" stroke="#dee2e6" stroke-width="1"/>`;
  s += `<line x1="${MR_ROW_LABEL_W}" y1="${MR_HEADER_H + MR_CELL_H}" x2="${W}" y2="${MR_HEADER_H + MR_CELL_H}" stroke="#dee2e6" stroke-width="1"/>`;
  const lastRowY = MR_HEADER_H + taintRowIdx * MR_CELL_H;
  s += `<line x1="${MR_ROW_LABEL_W}" y1="${lastRowY}" x2="${W}" y2="${lastRowY}" stroke="#dee2e6" stroke-width="1"/>`;
  s += `<line x1="${MR_ROW_LABEL_W}" y1="${lastRowY + MR_CELL_H}" x2="${W}" y2="${lastRowY + MR_CELL_H}" stroke="#dee2e6" stroke-width="1"/>`;

  // Legend below
  const ly = lastRowY + MR_CELL_H + 12;
  const legendItems = [
    ["#ff9800", "Tainted input bit"],
    ["#28a745", "Input bit = 1"],
    ["#adb5bd", "Input bit = 0"],
    ["#e17055", "Active cell overrides → 1"],
    ["#b2bec3", "Active cell overrides → 0"],
    ["#74b9ff", "Inactive cell overrides → 1"],
    ["#d63031", "Taint output bit = 1"],
  ];
  let lx = MR_ROW_LABEL_W;
  legendItems.forEach(([color, text]) => {
    s += `<rect x="${lx}" y="${ly}" width="14" height="14" rx="2" fill="${color}"/>`;
    s += `<text x="${lx + 18}" y="${ly + 11}" font-size="10" fill="#555">${text}</text>`;
    lx += text.length * 6.2 + 26;
    if (lx > W - 100) {
      /* wrap */
    }
  });

  svg.innerHTML = s;

  // Apply current zoom/pan transform to the inner g
  mrApplyTransform();
}

function mrBitToKey(globalBitPos, regs) {
  let offset = 0;
  for (const reg of regs) {
    if (globalBitPos < offset + reg.bits)
      return `${reg.name}:${globalBitPos - offset}`;
    offset += reg.bits;
  }
  return `?:${globalBitPos}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Output panel
// ─────────────────────────────────────────────────────────────────────────────
function mrRenderOutputPanel() {
  if (!mrSimResult || !currentRuleData) return;
  const panel = document.getElementById("mr-output-panel");
  if (!panel) return;

  const taint = mrSimResult.taint_output;
  const regs = mrSimResult.register_format || currentRuleData.format.registers;
  const real = mrSimResult.real_output || {};

  // Render taint bits per register
  let taintHtml = "";
  let bitOffset = 0;
  regs.forEach((reg) => {
    taintHtml += `<div class="mr-out-reg-box">
      <div class="mr-out-reg-title">${reg.name}</div>
      <div class="mr-bit-row">`;
    for (let b = reg.bits - 1; b >= 0; b--) {
      const gp = bitOffset + b;
      const tv = (taint >> gp) & 1;
      const flag = getFlagName(reg.name, b);
      taintHtml += `<div class="mr-bit-wrapper">
        ${flag ? `<div class="mr-flag-label">${flag}</div>` : '<div class="mr-flag-label">&nbsp;</div>'}
        <div class="mr-out-bit ${tv ? "mr-taint-on" : ""}" title="${reg.name}[${b}]">
          <span class="mr-bit-idx">${b}</span>${tv}
        </div></div>`;
    }
    taintHtml += "</div></div>";
    bitOffset += reg.bits;
  });

  // Render real output bits per register
  let realHtml = "";
  regs.forEach((reg) => {
    const regVals = real[reg.name] || {};
    realHtml += `<div class="mr-out-reg-box">
      <div class="mr-out-reg-title">${reg.name}</div>
      <div class="mr-bit-row">`;
    for (let b = reg.bits - 1; b >= 0; b--) {
      const val = regVals[b] !== undefined ? regVals[b] : 0;
      const flag = getFlagName(reg.name, b);
      realHtml += `<div class="mr-bit-wrapper">
        ${flag ? `<div class="mr-flag-label">${flag}</div>` : '<div class="mr-flag-label">&nbsp;</div>'}
        <div class="mr-out-bit ${val ? "mr-real-on" : ""}" title="${reg.name}[${b}]">
          <span class="mr-bit-idx">${b}</span>${val}
        </div></div>`;
    }
    realHtml += "</div></div>";
  });

  panel.innerHTML = `
    <div class="mr-output-section">
      <h4 style="color:#d63031">⊕ Taint Output (hex: ${mrSimResult.taint_output_hex || "0x" + taint.toString(16)})</h4>
      <div style="display:flex;flex-wrap:wrap;gap:12px">${taintHtml}</div>
    </div>
    <div class="mr-output-section" style="margin-top:20px">
      <h4 style="color:#28a745">▶ Real Instruction Output</h4>
      <div style="display:flex;flex-wrap:wrap;gap:12px">${realHtml}</div>
    </div>`;
  panel.style.display = "block";
}

// ─────────────────────────────────────────────────────────────────────────────
// Zoom / pan / fullscreen
// ─────────────────────────────────────────────────────────────────────────────
function mrApplyTransform() {
  const wrapper = document.getElementById("mr-matrix-wrapper");
  if (wrapper)
    wrapper.style.transform = `translate(${mrPanX}px,${mrPanY}px) scale(${mrZoom})`;
}

function mrZoomIn() {
  mrZoom = Math.min(mrZoom * 1.2, 8);
  mrApplyTransform();
}
function mrZoomOut() {
  mrZoom = Math.max(mrZoom / 1.2, 0.1);
  mrApplyTransform();
}
function mrZoomReset() {
  mrZoom = 1;
  mrPanX = 0;
  mrPanY = 0;
  mrApplyTransform();
}

function mrInitPanZoom() {
  const container = document.getElementById("mr-matrix-container");
  if (!container) return;

  // Wheel → zoom centered on cursor
  container.addEventListener(
    "wheel",
    (e) => {
      e.preventDefault();
      const factor = e.deltaY < 0 ? 1.1 : 0.9;
      mrZoom = Math.min(Math.max(mrZoom * factor, 0.1), 8);
      mrApplyTransform();
    },
    { passive: false },
  );

  // Drag → pan
  container.addEventListener("mousedown", (e) => {
    if (e.button !== 0) return;
    mrIsPanning = true;
    mrPanStart = { x: e.clientX - mrPanX, y: e.clientY - mrPanY };
    container.style.cursor = "grabbing";
  });
  window.addEventListener("mousemove", (e) => {
    if (!mrIsPanning) return;
    mrPanX = e.clientX - mrPanStart.x;
    mrPanY = e.clientY - mrPanStart.y;
    mrApplyTransform();
  });
  window.addEventListener("mouseup", () => {
    mrIsPanning = false;
    const c = document.getElementById("mr-matrix-container");
    if (c) c.style.cursor = "grab";
  });
  container.style.cursor = "grab";
}

function mrEnterFullscreen() {
  const el = document.getElementById("mr-matrix-section");
  if (!el) return;
  el.classList.add("mr-fullscreen");
  document.getElementById("mr-fs-exit").style.display = "flex";
  document.getElementById("mr-fs-enter").style.display = "none";
  document.addEventListener("keydown", mrEscapeFullscreen);
}

function mrExitFullscreen() {
  const el = document.getElementById("mr-matrix-section");
  if (!el) return;
  el.classList.remove("mr-fullscreen");
  document.getElementById("mr-fs-exit").style.display = "none";
  document.getElementById("mr-fs-enter").style.display = "flex";
  document.removeEventListener("keydown", mrEscapeFullscreen);
}

function mrEscapeFullscreen(e) {
  if (e.key === "Escape") mrExitFullscreen();
}

// ─────────────────────────────────────────────────────────────────────────────
// Keyboard navigation (edit mode)
// ─────────────────────────────────────────────────────────────────────────────
document.addEventListener("keydown", (e) => {
  if (
    document.activeElement.tagName === "INPUT" ||
    document.activeElement.tagName === "TEXTAREA"
  )
    return;
  // Only act if in M-Replica tab and edit mode
  const mrTab = document.getElementById("mreplica-tab");
  if (!mrTab || !mrTab.classList.contains("active")) return;
  if (mrIsTaintMode || !mrFocusedCell) return;

  const { register: reg, bit } = mrFocusedCell;
  if (e.key === "0" || e.key === "1") {
    mrSetBitValue(reg, bit, e.key);
    mrMoveFocusNext();
    e.preventDefault();
  } else if (e.key === "Enter") {
    mrMoveFocusNext();
    e.preventDefault();
  } else if (e.key === "ArrowLeft") {
    mrMoveFocusLeft();
    e.preventDefault();
  } else if (e.key === "ArrowRight") {
    mrMoveFocusRight();
    e.preventDefault();
  } else if (e.key === "ArrowUp") {
    mrMoveFocusUp();
    e.preventDefault();
  } else if (e.key === "ArrowDown") {
    mrMoveFocusDown();
    e.preventDefault();
  } else if (e.key === "Escape") {
    mrFocusBitCell(null, null);
    e.preventDefault();
  }
});

function mrMoveFocusNext() {
  if (!mrFocusedCell || !currentRuleData) return;
  const regs = currentRuleData.format.registers;
  const reg = regs.find((r) => r.name === mrFocusedCell.register);
  if (!reg) return;
  if (mrFocusedCell.bit > 0)
    mrFocusBitCell(mrFocusedCell.register, mrFocusedCell.bit - 1);
  else {
    const i = regs.findIndex((r) => r.name === mrFocusedCell.register);
    if (i < regs.length - 1)
      mrFocusBitCell(regs[i + 1].name, regs[i + 1].bits - 1);
  }
}
function mrMoveFocusLeft() {
  if (!mrFocusedCell || !currentRuleData) return;
  const regs = currentRuleData.format.registers;
  const reg = regs.find((r) => r.name === mrFocusedCell.register);
  if (!reg) return;
  if (mrFocusedCell.bit < reg.bits - 1)
    mrFocusBitCell(mrFocusedCell.register, mrFocusedCell.bit + 1);
}
function mrMoveFocusRight() {
  if (!mrFocusedCell || !currentRuleData) return;
  if (mrFocusedCell.bit > 0)
    mrFocusBitCell(mrFocusedCell.register, mrFocusedCell.bit - 1);
}
function mrMoveFocusUp() {
  if (!mrFocusedCell || !currentRuleData) return;
  const regs = currentRuleData.format.registers;
  const i = regs.findIndex((r) => r.name === mrFocusedCell.register);
  if (i > 0)
    mrFocusBitCell(
      regs[i - 1].name,
      Math.min(mrFocusedCell.bit, regs[i - 1].bits - 1),
    );
}
function mrMoveFocusDown() {
  if (!mrFocusedCell || !currentRuleData) return;
  const regs = currentRuleData.format.registers;
  const i = regs.findIndex((r) => r.name === mrFocusedCell.register);
  if (i < regs.length - 1)
    mrFocusBitCell(
      regs[i + 1].name,
      Math.min(mrFocusedCell.bit, regs[i + 1].bits - 1),
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Hook into rule-load lifecycle
// ─────────────────────────────────────────────────────────────────────────────
const _origUpdateAllDisplays =
  typeof updateAllDisplays === "function" ? updateAllDisplays : null;
// Override called after rule loads (defined in visualizer-new.js after this file)
function onMReplicaRuleLoaded() {
  // Reset local state
  mrCells = [];
  mrTaintBits.clear();
  mrFocusedCell = null;
  mrSimResult = null;
  mrZoom = 1;
  mrPanX = 0;
  mrPanY = 0;

  // Re-render if the tab is visible
  mrRenderInputRegisters();
  mrRenderMakeFullSelector();
  mrRefreshCellList();
  mrRunSimulation();
  mrRenderMatrix();
  mrInitPanZoom();
}
