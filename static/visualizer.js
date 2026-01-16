// TaintInduce Visualizer JavaScript

function switchTab(tabName) {
  // Hide all tabs
  document
    .querySelectorAll(".tab-content")
    .forEach((el) => el.classList.remove("active"));
  document
    .querySelectorAll(".tab")
    .forEach((el) => el.classList.remove("active"));

  // Show selected tab
  document.getElementById(tabName + "-tab").classList.add("active");
  event.target.classList.add("active");
}

async function loadRuleData() {
  const response = await fetch("/api/rule");
  const data = await response.json();

  // Update overview
  document.getElementById("rule-file").textContent = data.filename;
  document.getElementById("arch").textContent = data.format.arch;
  document.getElementById("num-regs").textContent =
    data.format.registers.length;
  document.getElementById("num-mem").textContent = data.format.mem_slots.length;
  document.getElementById("num-pairs").textContent = data.num_pairs;

  // Show registers
  let regsHTML =
    '<div class="rule-info"><h3>Registers</h3><div class="info-grid">';
  data.format.registers.forEach((reg, idx) => {
    regsHTML += `
            <div class="info-item">
                <div class="info-label">Register ${idx + 1}</div>
                <div class="info-value">${reg.name} (${reg.bits}b)</div>
            </div>
        `;
  });
  regsHTML += "</div></div>";
  document.getElementById("registers-list").innerHTML = regsHTML;

  // Load pairs
  loadPairs(data.pairs);

  // Load test cases
  loadTestCases();
}

function loadPairs(pairs) {
  const container = document.getElementById("pair-list");
  let html = "";

  pairs.forEach((pair, idx) => {
    const numFlows = pair.num_dataflows;
    const totalPropagations = pair.total_propagations;

    html += `
            <div class="pair-card">
                <div class="pair-header">
                    <span class="pair-number">Pair ${idx + 1}</span>
                    <span class="pair-stats">
                        ${numFlows} input bits → ${totalPropagations} propagations
                        ${
                          pair.is_unconditional
                            ? '<span class="badge badge-success">UNCONDITIONAL</span>'
                            : ""
                        }
                    </span>
                </div>
                <div class="condition-box">
                    <strong>CONDITION:</strong> ${pair.condition_text}
                </div>
                <div class="dataflow-preview" style="max-height: 400px; overflow-y: auto;">
                    <strong>All Dataflows:</strong>
                    ${pair.sample_flows
                      .map(
                        (f) =>
                          `<div class="flow-item">Bit ${f.input} → [${f.outputs}]</div>`
                      )
                      .join("")}
                </div>
            </div>
        `;
  });

  container.innerHTML = html;
}

async function runSimulation() {
  const inputValue = document.getElementById("input-state").value;

  const response = await fetch("/api/simulate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ input_state: inputValue }),
  });

  const results = await response.json();

  const container = document.getElementById("matching-pairs");
  const resultsDiv = document.getElementById("simulation-results");
  resultsDiv.classList.add("show");

  if (results.error) {
    container.innerHTML = `<div class="result-card no-match">❌ Error: ${results.error}</div>`;
    return;
  }

  let html = `
        <div class="result-card">
            <h4>Input State: ${results.input_state_hex} (${results.input_state_bin})</h4>
            <p><strong>${results.matching_pairs.length}</strong> condition(s) matched</p>
        </div>
    `;

  results.matching_pairs.forEach((pair) => {
    html += `
            <div class="result-card">
                <h4>✅ Pair ${pair.pair_index + 1} Matched ${
      pair.is_unconditional
        ? '<span class="badge badge-success">UNCONDITIONAL</span>'
        : ""
    }</h4>
                <div class="condition-box">${pair.condition_text}</div>
                <p><strong>Taint Propagation:</strong> ${
                  pair.num_flows
                } input bits will propagate taint</p>
                <div class="dataflow-preview">
                    ${pair.sample_flows
                      .map(
                        (f) =>
                          `<div class="flow-item">Bit ${f.input} → [${f.outputs}]</div>`
                      )
                      .join("")}
                </div>
            </div>
        `;
  });

  if (results.matching_pairs.length === 0) {
    html += `<div class="result-card no-match">⚠️ No conditions matched this input state</div>`;
  }

  container.innerHTML = html;
}

async function loadTestCases() {
  const response = await fetch("/api/test-cases");
  const data = await response.json();

  const container = document.getElementById("test-cases");
  let html = "";

  data.test_cases.forEach((test, idx) => {
    html += `
            <div class="test-card">
                <h4>Test Case ${idx + 1}: ${test.description}</h4>
                <div class="test-detail">
                    <strong>Pair Index:</strong> ${test.pair_index}<br>
                    <strong>Input State:</strong> ${
                      test.input_state_hex || "0x0"
                    }<br>
                    <strong>Condition Matches:</strong> ${
                      test.condition_matches ? "✅ Yes" : "❌ No"
                    }
                </div>
                ${
                  test.bitmask
                    ? `<div class="test-detail"><strong>Bitmask:</strong> ${test.bitmask} | <strong>Expected:</strong> ${test.expected_value}</div>`
                    : ""
                }
            </div>
        `;
  });

  container.innerHTML = html;
}

// Load data on page load
document.addEventListener("DOMContentLoaded", () => {
  loadRuleData();
  populatePairSelector();
});

// Graph visualization functions
let currentRuleData = null;

async function populatePairSelector() {
  const response = await fetch("/api/rule");
  currentRuleData = await response.json();

  const select = document.getElementById("pairSelect");
  select.innerHTML = "";

  currentRuleData.pairs.forEach((pair, idx) => {
    const option = document.createElement("option");
    option.value = idx;
    option.textContent = `Pair ${idx + 1}: ${
      pair.condition_readable || "Unconditional"
    }`;
    select.appendChild(option);
  });

  if (currentRuleData.pairs.length > 0) {
    renderGraph();
  }
}

function decodeFlags(regName, bits, value = null) {
  // EFLAGS/RFLAGS flag decoding for x86/AMD64
  const flagDefs = {
    EFLAGS: [
      { bit: 0, name: "CF", desc: "Carry" },
      { bit: 2, name: "PF", desc: "Parity" },
      { bit: 4, name: "AF", desc: "Auxiliary" },
      { bit: 6, name: "ZF", desc: "Zero" },
      { bit: 7, name: "SF", desc: "Sign" },
      { bit: 8, name: "TF", desc: "Trap" },
      { bit: 9, name: "IF", desc: "Interrupt" },
      { bit: 10, name: "DF", desc: "Direction" },
      { bit: 11, name: "OF", desc: "Overflow" },
      { bit: 14, name: "NT", desc: "Nested Task" },
      { bit: 16, name: "RF", desc: "Resume" },
      { bit: 17, name: "VM", desc: "Virtual 8086" },
      { bit: 18, name: "AC", desc: "Alignment" },
      { bit: 19, name: "VIF", desc: "Virtual IF" },
      { bit: 20, name: "VIP", desc: "Virtual IP" },
      { bit: 21, name: "ID", desc: "ID" },
    ],
    RFLAGS: [
      // Same as EFLAGS for 64-bit
      { bit: 0, name: "CF", desc: "Carry" },
      { bit: 2, name: "PF", desc: "Parity" },
      { bit: 4, name: "AF", desc: "Auxiliary" },
      { bit: 6, name: "ZF", desc: "Zero" },
      { bit: 7, name: "SF", desc: "Sign" },
      { bit: 8, name: "TF", desc: "Trap" },
      { bit: 9, name: "IF", desc: "Interrupt" },
      { bit: 10, name: "DF", desc: "Direction" },
      { bit: 11, name: "OF", desc: "Overflow" },
      { bit: 14, name: "NT", desc: "Nested Task" },
      { bit: 16, name: "RF", desc: "Resume" },
      { bit: 17, name: "VM", desc: "Virtual 8086" },
      { bit: 18, name: "AC", desc: "Alignment" },
      { bit: 19, name: "VIF", desc: "Virtual IF" },
      { bit: 20, name: "VIP", desc: "Virtual IP" },
      { bit: 21, name: "ID", desc: "ID" },
    ],
  };

  const flags = flagDefs[regName] || [];
  let html = '<div class="flag-decode">';

  if (flags.length > 0) {
    flags.forEach((flag) => {
      const bitVal = value !== null ? (value >> flag.bit) & 1 : "?";
      html += `<span class="flag-item">${flag.name}[${flag.bit}]=${bitVal} <small>(${flag.desc})</small></span>`;
    });
  } else {
    html += "No flag decoding available for this register";
  }

  html += "</div>";
  return html;
}

function renderGraph() {
  if (!currentRuleData) return;

  const pairIdx = parseInt(document.getElementById("pairSelect").value);
  const pair = currentRuleData.pairs[pairIdx];
  const format = currentRuleData.format;

  // Render register display
  renderRegisters(format, pair);

  // Render flow graph
  renderFlowGraph(pair, format);
}

function renderRegisters(format, pair) {
  const container = document.getElementById("registerDisplay");
  let html = "";

  format.registers.forEach((reg) => {
    html += `<div class="register-box">
            <h4>${reg.name} (${reg.bits} bits)</h4>
            <div class="bit-grid">`;

    // Show bits in groups of 8
    for (let i = reg.bits - 1; i >= 0; i--) {
      html += `<div class="bit-cell" title="Bit ${i}">${i}</div>`;
    }

    html += "</div>";

    // Add flag decoding if applicable
    if (reg.name === "EFLAGS" || reg.name === "RFLAGS") {
      html += decodeFlags(reg.name, reg.bits);
    }

    html += "</div>";
  });

  container.innerHTML = html;
}

function getRegisterIndex(bit, format) {
  // Find which register this bit belongs to
  for (let i = 0; i < format.registers.length; i++) {
    if (bit.type === "reg" && bit.name === format.registers[i].name) {
      return i;
    }
  }
  return 999; // Unknown - sort to end
}

function sortBitsByRegister(bitArray, format) {
  // Sort bits by: 1) register index, 2) bit number within register
  return bitArray.slice().sort((a, b) => {
    const regIdxA = getRegisterIndex(a, format);
    const regIdxB = getRegisterIndex(b, format);

    if (regIdxA !== regIdxB) {
      return regIdxA - regIdxB;
    }

    // Same register, sort by bit number
    return (a.bit || 0) - (b.bit || 0);
  });
}

function renderFlowGraph(pair, format) {
  const svg = document.getElementById("flowGraph");

  // Clear previous content
  svg.innerHTML = "";

  if (!pair.dataflow || !Array.isArray(pair.dataflow)) {
    svg.innerHTML =
      '<text x="50%" y="50%" text-anchor="middle" fill="#333">No dataflow to display</text>';
    return;
  }

  // Collect all input and output bits first to calculate size
  const inputBits = new Set();
  const outputBits = new Set();
  const edges = [];

  pair.dataflow.forEach((flow) => {
    const outBit = flow.output_bit;
    const inBits = flow.input_bits || [];

    outputBits.add(JSON.stringify(outBit));
    inBits.forEach((inBit) => {
      inputBits.add(JSON.stringify(inBit));
      edges.push({
        from: JSON.stringify(inBit),
        to: JSON.stringify(outBit),
      });
    });
  });

  let inputArray = Array.from(inputBits).map((s) => JSON.parse(s));
  let outputArray = Array.from(outputBits).map((s) => JSON.parse(s));
  inputArray = sortBitsByRegister(inputArray, format);
  outputArray = sortBitsByRegister(outputArray, format);

  // Calculate required height based on number of nodes
  const baseNodeSpacing = 25;
  const registerGapSpacing = 40;
  const margin = 150;

  function calculateHeight(bitArray) {
    let height = 0;
    let lastRegIdx = -1;
    bitArray.forEach((bit) => {
      const regIdx = getRegisterIndex(bit, format);
      if (lastRegIdx !== -1 && regIdx !== lastRegIdx) {
        height += registerGapSpacing;
      }
      height += baseNodeSpacing;
      lastRegIdx = regIdx;
    });
    return height;
  }

  const inputHeight = calculateHeight(inputArray);
  const outputHeight = calculateHeight(outputArray);
  const requiredHeight = Math.max(inputHeight, outputHeight) + 120;
  const width = 1200;
  const height = Math.max(600, requiredHeight);

  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("width", width);
  svg.setAttribute("height", height);

  // Calculate spacing with register group gaps
  const leftX = margin;
  const rightX = width - margin;
  const availableHeight = height - 80;

  // Calculate positions with gaps between registers
  function calculatePositions(bitArray, startY) {
    const positions = {};
    let currentY = startY;
    let lastRegIdx = -1;

    bitArray.forEach((bit, idx) => {
      const regIdx = getRegisterIndex(bit, format);

      // Add gap if we're starting a new register
      if (lastRegIdx !== -1 && regIdx !== lastRegIdx) {
        currentY += registerGapSpacing;
      }

      const key = JSON.stringify(bit);
      positions[key] = { x: 0, y: currentY }; // x will be set by caller
      currentY += baseNodeSpacing;
      lastRegIdx = regIdx;
    });

    return positions;
  }

  const inputY = 60;
  const outputY = 60;

  // Create separate position maps for inputs and outputs
  const inputPos = calculatePositions(inputArray, inputY);
  const outputPos = calculatePositions(outputArray, outputY);

  // Set x coordinates
  Object.keys(inputPos).forEach((key) => (inputPos[key].x = leftX));
  Object.keys(outputPos).forEach((key) => (outputPos[key].x = rightX));

  // Draw edges (behind nodes)
  edges.forEach((edge) => {
    const from = inputPos[edge.from];
    const to = outputPos[edge.to];
    if (from && to) {
      const path = document.createElementNS(
        "http://www.w3.org/2000/svg",
        "path"
      );
      const midX = (from.x + to.x) / 2;
      const d = `M ${from.x} ${from.y} C ${midX} ${from.y}, ${midX} ${to.y}, ${to.x} ${to.y}`;
      path.setAttribute("d", d);
      path.setAttribute("class", "flow-line");
      path.innerHTML = `<title>${edge.from} → ${edge.to}</title>`;
      svg.appendChild(path);
    }
  });

  // Draw input nodes
  inputArray.forEach((bit, idx) => {
    const key = JSON.stringify(bit);
    const pos = inputPos[key];
    const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
    g.setAttribute("class", "bit-node input");
    g.setAttribute("transform", `translate(${pos.x}, ${pos.y})`);

    const circle = document.createElementNS(
      "http://www.w3.org/2000/svg",
      "circle"
    );
    circle.setAttribute("r", 15);
    g.appendChild(circle);

    const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
    text.textContent = "IN";
    g.appendChild(text);

    const title = document.createElementNS(
      "http://www.w3.org/2000/svg",
      "title"
    );
    title.textContent = formatBitPosition(bit);
    g.appendChild(title);

    // Label (adjust x position to avoid overlap with circles)
    const label = document.createElementNS(
      "http://www.w3.org/2000/svg",
      "text"
    );
    label.setAttribute("x", -70); // Further left to avoid overlap
    label.setAttribute("y", 5);
    label.setAttribute("text-anchor", "start");
    label.setAttribute("font-size", "11");
    label.setAttribute("fill", "#000"); // Black, not white
    label.textContent = formatBitPosition(bit);
    g.appendChild(label);

    svg.appendChild(g);
  });

  // Draw output nodes
  outputArray.forEach((bit, idx) => {
    const key = JSON.stringify(bit);
    const pos = outputPos[key];
    const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
    g.setAttribute("class", "bit-node output");
    g.setAttribute("transform", `translate(${pos.x}, ${pos.y})`);

    const circle = document.createElementNS(
      "http://www.w3.org/2000/svg",
      "circle"
    );
    circle.setAttribute("r", 15);
    g.appendChild(circle);

    const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
    text.textContent = "OUT";
    g.appendChild(text);

    const title = document.createElementNS(
      "http://www.w3.org/2000/svg",
      "title"
    );
    title.textContent = formatBitPosition(bit);
    g.appendChild(title);

    // Label (adjust x position to not overlap)
    const label = document.createElementNS(
      "http://www.w3.org/2000/svg",
      "text"
    );
    label.setAttribute("x", 25); // Right of circle
    label.setAttribute("y", 5);
    label.setAttribute("text-anchor", "start");
    label.setAttribute("font-size", "11");
    label.setAttribute("fill", "#000"); // Black, not white
    label.textContent = formatBitPosition(bit);
    g.appendChild(label);

    svg.appendChild(g);
  });

  // Add legend
  const legend = document.createElementNS("http://www.w3.org/2000/svg", "g");
  legend.setAttribute("transform", `translate(${width / 2 - 100}, 20)`);

  // Input legend
  const inputCircle = document.createElementNS(
    "http://www.w3.org/2000/svg",
    "circle"
  );
  inputCircle.setAttribute("cx", 0);
  inputCircle.setAttribute("cy", 0);
  inputCircle.setAttribute("r", 8);
  inputCircle.setAttribute("fill", "#28a745");
  legend.appendChild(inputCircle);

  const inputText = document.createElementNS(
    "http://www.w3.org/2000/svg",
    "text"
  );
  inputText.setAttribute("x", 15);
  inputText.setAttribute("y", 5);
  inputText.setAttribute("font-size", "12");
  inputText.setAttribute("fill", "#000");
  inputText.textContent = "Input Bits";
  legend.appendChild(inputText);

  // Output legend
  const outputCircle = document.createElementNS(
    "http://www.w3.org/2000/svg",
    "circle"
  );
  outputCircle.setAttribute("cx", 100);
  outputCircle.setAttribute("cy", 0);
  outputCircle.setAttribute("r", 8);
  outputCircle.setAttribute("fill", "#ff6b6b");
  legend.appendChild(outputCircle);

  const outputText = document.createElementNS(
    "http://www.w3.org/2000/svg",
    "text"
  );
  outputText.setAttribute("x", 115);
  outputText.setAttribute("y", 5);
  outputText.setAttribute("font-size", "12");
  outputText.setAttribute("fill", "#000");
  outputText.textContent = "Output Bits";
  legend.appendChild(outputText);

  svg.appendChild(legend);
}

function getFlagName(regName, bitNum) {
  const flagDefs = {
    EFLAGS: {
      0: "CF",
      2: "PF",
      4: "AF",
      6: "ZF",
      7: "SF",
      8: "TF",
      9: "IF",
      10: "DF",
      11: "OF",
      14: "NT",
      16: "RF",
      17: "VM",
      18: "AC",
      19: "VIF",
      20: "VIP",
      21: "ID",
    },
    RFLAGS: {
      0: "CF",
      2: "PF",
      4: "AF",
      6: "ZF",
      7: "SF",
      8: "TF",
      9: "IF",
      10: "DF",
      11: "OF",
      14: "NT",
      16: "RF",
      17: "VM",
      18: "AC",
      19: "VIF",
      20: "VIP",
      21: "ID",
    },
  };

  if (flagDefs[regName] && flagDefs[regName][bitNum]) {
    return flagDefs[regName][bitNum];
  }
  return null;
}

function formatBitPosition(bit) {
  if (bit.type === "reg") {
    const flagName = getFlagName(bit.name, bit.bit);
    if (flagName) {
      return `${bit.name}[${bit.bit}:${flagName}]`;
    }
    return `${bit.name}[${bit.bit}]`;
  } else if (bit.type === "mem") {
    return `MEM${bit.slot}[${bit.bit}]`;
  }
  return JSON.stringify(bit);
}
