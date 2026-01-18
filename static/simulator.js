// Enhanced interactive taint simulator for TaintInduce Visualizer

// Global state for simulator
let taintedBitsSet = new Set(); // Set of "register:bit" strings
let currentInputMode = "bits";
let isEditMode = false; // false = taint mode, true = edit mode
let focusedCell = null; // Currently focused cell for keyboard input

function switchInputMode(mode) {
  currentInputMode = mode;

  const bitMode = document.getElementById("bit-input-mode");
  const hexMode = document.getElementById("hex-input-mode");
  const btnBits = document.getElementById("btnInputBits");
  const btnHex = document.getElementById("btnInputHex");

  if (mode === "bits") {
    bitMode.style.display = "block";
    hexMode.style.display = "none";
    btnBits.style.background = "#667eea";
    btnBits.style.color = "white";
    btnHex.style.background = "#e0e0e0";
    btnHex.style.color = "#333";
  } else {
    bitMode.style.display = "none";
    hexMode.style.display = "block";
    btnBits.style.background = "#e0e0e0";
    btnBits.style.color = "#333";
    btnHex.style.background = "#667eea";
    btnHex.style.color = "white";
  }
}

function renderRegisterInputs() {
  if (!currentRuleData || !currentRuleData.format) {
    console.error("No rule loaded");
    return;
  }

  const container = document.getElementById("register-inputs");
  let html = "";

  const format = currentRuleData.format;

  // Render each register
  format.registers.forEach((reg) => {
    html += `
      <div class="register-input-box" style="margin-bottom: 20px; padding: 15px; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1)">
        <h4 style="margin: 0 0 10px 0">${reg.name} (${reg.bits} bits)</h4>
        <div class="bit-input-grid" style="display: flex; gap: 2px; flex-wrap: wrap; max-width: 100%; overflow-x: auto">
    `;

    // Render bits from MSB to LSB
    for (let bitIdx = reg.bits - 1; bitIdx >= 0; bitIdx--) {
      const bitKey = `${reg.name}:${bitIdx}`;
      const isTainted = taintedBitsSet.has(bitKey);
      const bgColor = isTainted ? "#ff9800" : "#f5f5f5";
      const textColor = isTainted ? "white" : "#333";

      html += `
        <div class="bit-input-cell" 
             data-register="${reg.name}" 
             data-bit="${bitIdx}"
             onclick="toggleBit('${reg.name}', ${bitIdx})"
             style="
               width: 32px;
               height: 32px;
               background: ${bgColor};
               color: ${textColor};
               border: 1px solid #ddd;
               border-radius: 4px;
               display: flex;
               align-items: center;
               justify-content: center;
               font-size: 11px;
               font-weight: bold;
               cursor: pointer;
               user-select: none;
               font-family: monospace;
               position: relative;
             "
             title="${reg.name}[${bitIdx}] - Click to toggle value, Shift+Click to toggle taint">
          <div style="font-size: 9px; position: absolute; top: 1px; right: 2px; color: #999">${bitIdx}</div>
          <div id="bit-value-${reg.name}-${bitIdx}">0</div>
        </div>
      `;
    }

    html += `
        </div>
        <div style="margin-top: 10px; display: flex; gap: 8px; font-size: 13px">
          <button onclick="setRegisterHex('${reg.name}', prompt('Enter hex value for ${reg.name}:'))" 
                  style="padding: 4px 8px; background: #667eea; color: white; border: none; border-radius: 4px; cursor: pointer">
            Set Hex
          </button>
          <button onclick="taintRegister('${reg.name}')" 
                  style="padding: 4px 8px; background: #ff9800; color: white; border: none; border-radius: 4px; cursor: pointer">
            Toggle Taint
          </button>
          <div style="flex: 1"></div>
          <button onclick="clearRegister('${reg.name}')" 
                  style="padding: 4px 8px; background: #757575; color: white; border: none; border-radius: 4px; cursor: pointer">
            Clear
          </button>
        </div>
      </div>
    `;
  });

  // Handle memory slots if present
  if (format.mem_slots && format.mem_slots > 0) {
    for (let memIdx = 0; memIdx < format.mem_slots; memIdx++) {
      const memBits = 64; // Default memory slot size
      html += `
        <div class="register-input-box" style="margin-bottom: 20px; padding: 15px; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1)">
          <h4 style="margin: 0 0 10px 0">MEM${memIdx} (${memBits} bits)</h4>
          <div class="bit-input-grid" style="display: flex; gap: 2px; flex-wrap: wrap">
      `;

      for (let bitIdx = memBits - 1; bitIdx >= 0; bitIdx--) {
        const bitKey = `MEM${memIdx}:${bitIdx}`;
        const isTainted = taintedBitsSet.has(bitKey);
        const bgColor = isTainted ? "#ff9800" : "#f5f5f5";
        const textColor = isTainted ? "white" : "#333";

        html += `
          <div class="bit-input-cell" 
               data-register="MEM${memIdx}" 
               data-bit="${bitIdx}"
               onclick="toggleBit('MEM${memIdx}', ${bitIdx})"
               style="width: 32px; height: 32px; background: ${bgColor}; color: ${textColor}; border: 1px solid #ddd; border-radius: 4px; display: flex; align-items: center; justify-content: center; font-size: 11px; font-weight: bold; cursor: pointer; user-select: none; font-family: monospace"
               title="MEM${memIdx}[${bitIdx}]">
            <div id="bit-value-MEM${memIdx}-${bitIdx}">0</div>
          </div>
        `;
      }

      html += `
          </div>
        </div>
      `;
    }
  }

  container.innerHTML = html;
}

function toggleBit(registerName, bitIdx) {
  if (isEditMode) {
    // Edit mode: clicking focuses cell for keyboard input
    focusCell(registerName, bitIdx);
  } else {
    // Taint mode: clicking toggles taint
    toggleBitTaint(registerName, bitIdx);
  }
}

function focusCell(registerName, bitIdx) {
  // Remove focus from previous cell
  if (focusedCell) {
    const prevCell = document.querySelector(
      `[data-register="${focusedCell.register}"][data-bit="${focusedCell.bit}"]`,
    );
    if (prevCell) {
      prevCell.style.outline = "none";
    }
  }

  // Focus new cell
  const cell = document.querySelector(
    `[data-register="${registerName}"][data-bit="${bitIdx}"]`,
  );
  if (cell) {
    cell.style.outline = "2px solid #667eea";
    cell.style.outlineOffset = "-2px";
    focusedCell = { register: registerName, bit: bitIdx };
  }
}

function toggleBitValue(registerName, bitIdx) {
  const valueEl = document.getElementById(
    `bit-value-${registerName}-${bitIdx}`,
  );
  const currentValue = parseInt(valueEl.textContent);
  const newValue = currentValue === 0 ? 1 : 0;
  valueEl.textContent = newValue;
  // Auto-trigger simulation
  runDetailedSimulation();
}

function toggleBitTaint(registerName, bitIdx) {
  const bitKey = `${registerName}:${bitIdx}`;
  const cell = document.querySelector(
    `[data-register="${registerName}"][data-bit="${bitIdx}"]`,
  );

  if (taintedBitsSet.has(bitKey)) {
    taintedBitsSet.delete(bitKey);
    cell.style.background = "#f5f5f5";
    cell.style.color = "#333";
  } else {
    taintedBitsSet.add(bitKey);
    cell.style.background = "#ff9800";
    cell.style.color = "white";
  }
  // Auto-trigger simulation
  runDetailedSimulation();
}

function moveToNextBit() {
  if (!focusedCell || !currentRuleData) return;

  const format = currentRuleData.format;
  const currentReg = format.registers.find(
    (r) => r.name === focusedCell.register,
  );
  if (!currentReg) return;

  // Try to move to previous bit (we go MSB to LSB, so "next" is lower bit index)
  if (focusedCell.bit > 0) {
    focusCell(focusedCell.register, focusedCell.bit - 1);
  } else {
    // Move to next register
    const currentRegIdx = format.registers.findIndex(
      (r) => r.name === focusedCell.register,
    );
    if (currentRegIdx < format.registers.length - 1) {
      const nextReg = format.registers[currentRegIdx + 1];
      focusCell(nextReg.name, nextReg.bits - 1);
    }
  }
}

function taintAll() {
  if (!currentRuleData || !currentRuleData.format) return;

  const format = currentRuleData.format;

  // Check if all bits are tainted
  let allTainted = true;
  for (const reg of format.registers) {
    for (let bitIdx = 0; bitIdx < reg.bits; bitIdx++) {
      const bitKey = `${reg.name}:${bitIdx}`;
      if (!taintedBitsSet.has(bitKey)) {
        allTainted = false;
        break;
      }
    }
    if (!allTainted) break;
  }

  if (allTainted) {
    // Untaint all
    clearTaint();
  } else {
    // Taint all
    format.registers.forEach((reg) => {
      for (let bitIdx = 0; bitIdx < reg.bits; bitIdx++) {
        const bitKey = `${reg.name}:${bitIdx}`;
        taintedBitsSet.add(bitKey);
        const cell = document.querySelector(
          `[data-register="${reg.name}"][data-bit="${bitIdx}"]`,
        );
        if (cell) {
          cell.style.background = "#ff9800";
          cell.style.color = "white";
        }
      }
    });
    // Auto-trigger simulation
    runDetailedSimulation();
  }
}

function clearTaint() {
  taintedBitsSet.clear();

  document.querySelectorAll(".bit-input-cell").forEach((cell) => {
    cell.style.background = "#f5f5f5";
    cell.style.color = "#333";
  });
  // Auto-trigger simulation
  runDetailedSimulation();
}

function taintRegister(registerName) {
  if (!currentRuleData || !currentRuleData.format) return;

  const reg = currentRuleData.format.registers.find(
    (r) => r.name === registerName,
  );
  if (!reg) return;

  // Check if all bits in this register are tainted
  let allTainted = true;
  for (let bitIdx = 0; bitIdx < reg.bits; bitIdx++) {
    const bitKey = `${registerName}:${bitIdx}`;
    if (!taintedBitsSet.has(bitKey)) {
      allTainted = false;
      break;
    }
  }

  if (allTainted) {
    // Untaint all bits in this register
    for (let bitIdx = 0; bitIdx < reg.bits; bitIdx++) {
      const bitKey = `${registerName}:${bitIdx}`;
      taintedBitsSet.delete(bitKey);
      const cell = document.querySelector(
        `[data-register="${registerName}"][data-bit="${bitIdx}"]`,
      );
      if (cell) {
        cell.style.background = "#f5f5f5";
        cell.style.color = "#333";
      }
    }
  } else {
    // Taint all bits in this register
    for (let bitIdx = 0; bitIdx < reg.bits; bitIdx++) {
      const bitKey = `${registerName}:${bitIdx}`;
      taintedBitsSet.add(bitKey);
      const cell = document.querySelector(
        `[data-register="${registerName}"][data-bit="${bitIdx}"]`,
      );
      if (cell) {
        cell.style.background = "#ff9800";
        cell.style.color = "white";
      }
    }
  }
  // Auto-trigger simulation
  runDetailedSimulation();
}

function clearRegister(registerName) {
  if (!currentRuleData || !currentRuleData.format) return;

  const reg = currentRuleData.format.registers.find(
    (r) => r.name === registerName,
  );
  if (!reg) return;

  for (let bitIdx = 0; bitIdx < reg.bits; bitIdx++) {
    const bitKey = `${registerName}:${bitIdx}`;
    taintedBitsSet.delete(bitKey);
    const cell = document.querySelector(
      `[data-register="${registerName}"][data-bit="${bitIdx}"]`,
    );
    if (cell) {
      cell.style.background = "#f5f5f5";
      cell.style.color = "#333";
    }

    // Also clear bit value
    const valueEl = document.getElementById(
      `bit-value-${registerName}-${bitIdx}`,
    );
    if (valueEl) valueEl.textContent = "0";
  }
  // Auto-trigger simulation
  runDetailedSimulation();
}

function setRegisterHex(registerName, hexValue) {
  if (!hexValue) return;
  if (!currentRuleData || !currentRuleData.format) return;

  const reg = currentRuleData.format.registers.find(
    (r) => r.name === registerName,
  );
  if (!reg) return;

  try {
    let value;
    if (hexValue.startsWith("0x") || hexValue.startsWith("0X")) {
      value = parseInt(hexValue, 16);
    } else {
      value = parseInt(hexValue);
    }

    // Set bit values from the integer
    for (let bitIdx = 0; bitIdx < reg.bits; bitIdx++) {
      const bitValue = (value >> bitIdx) & 1;
      const valueEl = document.getElementById(
        `bit-value-${registerName}-${bitIdx}`,
      );
      if (valueEl) valueEl.textContent = bitValue;
    }
    // Auto-trigger simulation
    runDetailedSimulation();
  } catch (e) {
    alert("Invalid value: " + hexValue);
  }
}

function updateBitsFromHex() {
  const hexInput = document.getElementById("input-state-hex");
  const hexValue = hexInput.value;

  if (!hexValue || !currentRuleData || !currentRuleData.format) return;

  try {
    let value;
    if (hexValue.startsWith("0x") || hexValue.startsWith("0X")) {
      value = parseInt(hexValue, 16);
    } else {
      value = parseInt(hexValue);
    }

    // Update all register bit values
    let bitOffset = 0;
    currentRuleData.format.registers.forEach((reg) => {
      for (let bitIdx = 0; bitIdx < reg.bits; bitIdx++) {
        const bitValue = (value >> (bitOffset + bitIdx)) & 1;
        const valueEl = document.getElementById(
          `bit-value-${reg.name}-${bitIdx}`,
        );
        if (valueEl) valueEl.textContent = bitValue;
      }
      bitOffset += reg.bits;
    });
    // Auto-trigger simulation
    runDetailedSimulation();
  } catch (e) {
    // Invalid input, ignore
  }
}

async function runDetailedSimulation() {
  if (!currentRuleData) return;

  const outputEl = document.getElementById("output-registers");
  const resultsDiv = document.getElementById("simulation-results-detailed");

  if (!outputEl || !resultsDiv) return;

  try {
    // Build register values from UI
    const registerValues = {};
    const format = currentRuleData.format;

    format.registers.forEach((reg) => {
      registerValues[reg.name] = {};
      for (let bitIdx = 0; bitIdx < reg.bits; bitIdx++) {
        const valueEl = document.getElementById(
          `bit-value-${reg.name}-${bitIdx}`,
        );
        if (valueEl) {
          registerValues[reg.name][bitIdx] = parseInt(valueEl.textContent);
        }
      }
    });

    // Build tainted bits list
    const taintedBits = [];
    taintedBitsSet.forEach((bitKey) => {
      const [register, bit] = bitKey.split(":");
      taintedBits.push([register, parseInt(bit)]);
    });

    // Call API
    const response = await fetch("/api/simulate-detailed", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        register_values: registerValues,
        tainted_bits: taintedBits,
      }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || "Simulation failed");
    }

    const result = await response.json();

    // Build set of tainted output bits for quick lookup
    const taintedOutputsSet = new Set();
    if (result.tainted_outputs_detailed) {
      result.tainted_outputs_detailed.forEach((output) => {
        taintedOutputsSet.add(`${output.register}:${output.bit}`);
      });
    }

    // Render output registers in bit-by-bit format like inputs
    let html = "";

    format.registers.forEach((reg) => {
      html += `
        <div class="register-output-box" style="margin-bottom: 20px; padding: 15px; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1)">
          <h4 style="margin: 0 0 10px 0">${reg.name} (${reg.bits} bits)</h4>
          <div class="bit-output-grid" style="display: flex; gap: 2px; flex-wrap: wrap; max-width: 100%; overflow-x: auto">
      `;

      // Render bits from MSB to LSB
      for (let bitIdx = reg.bits - 1; bitIdx >= 0; bitIdx--) {
        const bitKey = `${reg.name}:${bitIdx}`;
        const isTainted = taintedOutputsSet.has(bitKey);
        const bgColor = isTainted ? "#ff9800" : "#e0e0e0";
        const textColor = isTainted ? "white" : "#666";

        // Get the output bit value from backend
        let bitValue = "0";
        if (
          result.output_register_values &&
          result.output_register_values[reg.name] &&
          result.output_register_values[reg.name][bitIdx] !== undefined
        ) {
          bitValue = result.output_register_values[reg.name][bitIdx].toString();
        }

        html += `
          <div class="bit-output-cell" 
               style="
                 width: 32px;
                 height: 32px;
                 background: ${bgColor};
                 color: ${textColor};
                 border: 1px solid #ddd;
                 border-radius: 4px;
                 display: flex;
                 align-items: center;
                 justify-content: center;
                 font-size: 11px;
                 font-weight: bold;
                 font-family: monospace;
                 position: relative;
               "
          >
            <div style="font-size: 14px">${bitValue}</div>
            <div style="position: absolute; top: 2px; right: 2px; font-size: 8px; opacity: 0.7">${bitIdx}</div>
          </div>
        `;
      }

      html += `
          </div>
        </div>
      `;
    });

    outputEl.innerHTML = html;
    resultsDiv.style.display = "block";
  } catch (error) {
    outputEl.innerHTML = `<p style="color: #dc3545; padding: 15px">Error: ${error.message}</p>`;
    console.error("Simulation error:", error);
  }
}

function toggleEditMode() {
  isEditMode = !isEditMode;

  const btn = document.getElementById("btnToggleEditMode");
  const modeText = document.getElementById("editModeText");

  if (isEditMode) {
    btn.style.background = "#667eea";
    btn.textContent = "📝 Edit Mode";
    modeText.textContent =
      "Click a bit to focus it, then type 0 or 1. Auto-advances to next bit.";
    modeText.style.color = "#667eea";
  } else {
    btn.style.background = "#ff9800";
    btn.textContent = "🎨 Taint Mode";
    modeText.textContent = "Click bits to mark them as tainted (orange).";
    modeText.style.color = "#ff9800";

    // Clear focus when leaving edit mode
    if (focusedCell) {
      const cell = document.querySelector(
        `[data-register="${focusedCell.register}"][data-bit="${focusedCell.bit}"]`,
      );
      if (cell) {
        cell.style.outline = "none";
      }
      focusedCell = null;
    }
  }
}

// Initialize simulator when rule is loaded
function initializeSimulator() {
  renderRegisterInputs();
  taintedBitsSet.clear();
  isEditMode = false;
  focusedCell = null;

  // Add keyboard event listener for edit mode
  document.addEventListener("keydown", handleKeyPress);

  // Run initial simulation to show output
  runDetailedSimulation();
}

function handleKeyPress(event) {
  if (!isEditMode || !focusedCell) return;

  const key = event.key;

  if (key === "0" || key === "1") {
    // Set the bit value
    const valueEl = document.getElementById(
      `bit-value-${focusedCell.register}-${focusedCell.bit}`,
    );
    if (valueEl) {
      valueEl.textContent = key;
      // Auto-trigger simulation
      runDetailedSimulation();
      // Auto-advance to next bit
      moveToNextBit();
    }
    event.preventDefault();
  } else if (key === "Enter") {
    // Manually move to next bit
    moveToNextBit();
    event.preventDefault();
  } else if (key === "ArrowLeft") {
    // Move to higher bit index (MSB direction)
    moveLeft();
    event.preventDefault();
  } else if (key === "ArrowRight") {
    // Move to lower bit index (LSB direction)
    moveRight();
    event.preventDefault();
  } else if (key === "ArrowUp") {
    // Move to previous register at same bit position
    moveUp();
    event.preventDefault();
  } else if (key === "ArrowDown") {
    // Move to next register at same bit position
    moveDown();
    event.preventDefault();
  } else if (key === "Escape") {
    // Clear focus
    const cell = document.querySelector(
      `[data-register="${focusedCell.register}"][data-bit="${focusedCell.bit}"]`,
    );
    if (cell) {
      cell.style.outline = "none";
    }
    focusedCell = null;
    event.preventDefault();
  }
}

function moveLeft() {
  if (!focusedCell || !currentRuleData) return;

  const format = currentRuleData.format;
  const currentReg = format.registers.find(
    (r) => r.name === focusedCell.register,
  );
  if (!currentReg) return;

  // Move to higher bit index (left in visual display)
  if (focusedCell.bit < currentReg.bits - 1) {
    // Move within same register
    focusCell(focusedCell.register, focusedCell.bit + 1);
  } else {
    // At MSB, wrap to previous register's LSB
    const currentRegIdx = format.registers.findIndex(
      (r) => r.name === focusedCell.register,
    );
    if (currentRegIdx > 0) {
      const prevReg = format.registers[currentRegIdx - 1];
      focusCell(prevReg.name, 0);
    }
  }
}

function moveRight() {
  if (!focusedCell || !currentRuleData) return;

  const format = currentRuleData.format;
  const currentReg = format.registers.find(
    (r) => r.name === focusedCell.register,
  );
  if (!currentReg) return;

  // Move to lower bit index (right in visual display)
  if (focusedCell.bit > 0) {
    // Move within same register
    focusCell(focusedCell.register, focusedCell.bit - 1);
  } else {
    // At LSB, wrap to next register's MSB
    const currentRegIdx = format.registers.findIndex(
      (r) => r.name === focusedCell.register,
    );
    if (currentRegIdx < format.registers.length - 1) {
      const nextReg = format.registers[currentRegIdx + 1];
      focusCell(nextReg.name, nextReg.bits - 1);
    }
  }
}

function moveUp() {
  if (!focusedCell || !currentRuleData) return;

  const format = currentRuleData.format;
  const currentRegIdx = format.registers.findIndex(
    (r) => r.name === focusedCell.register,
  );
  if (currentRegIdx > 0) {
    const prevReg = format.registers[currentRegIdx - 1];
    // Move to same bit position modulo the previous register's size
    const targetBit = focusedCell.bit % prevReg.bits;
    focusCell(prevReg.name, targetBit);
  }
}

function moveDown() {
  if (!focusedCell || !currentRuleData) return;

  const format = currentRuleData.format;
  const currentRegIdx = format.registers.findIndex(
    (r) => r.name === focusedCell.register,
  );
  if (currentRegIdx < format.registers.length - 1) {
    const nextReg = format.registers[currentRegIdx + 1];
    // Move to same bit position modulo the next register's size
    const targetBit = focusedCell.bit % nextReg.bits;
    focusCell(nextReg.name, targetBit);
  }
}
