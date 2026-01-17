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
let graphNodeMap = null;
let graphEdgesByFrom = null;
let graphEdgesByTo = null;
let graphHighlightedElements = [];

async function populatePairSelector() {
  const response = await fetch("/api/rule");
  currentRuleData = await response.json();

  const select = document.getElementById("pairSelect");
  select.innerHTML = "";

  // Add "ALL" option
  const allOption = document.createElement("option");
  allOption.value = "ALL";
  allOption.textContent = `ALL (${currentRuleData.pairs.length} pairs)`;
  select.appendChild(allOption);

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
    CPSR: [
      // ARM/AArch32 flags
      { bit: 31, name: "N", desc: "Negative" },
      { bit: 30, name: "Z", desc: "Zero" },
      { bit: 29, name: "C", desc: "Carry" },
      { bit: 28, name: "V", desc: "Overflow" },
      { bit: 27, name: "Q", desc: "Saturation" },
      { bit: 24, name: "J", desc: "Jazelle" },
      { bit: 9, name: "E", desc: "Endianness" },
      { bit: 8, name: "A", desc: "Imprecise Abort" },
      { bit: 7, name: "I", desc: "IRQ disable" },
      { bit: 6, name: "F", desc: "FIQ disable" },
      { bit: 5, name: "T", desc: "Thumb" },
    ],
    APSR: [
      // ARM Application Program Status Register
      { bit: 31, name: "N", desc: "Negative" },
      { bit: 30, name: "Z", desc: "Zero" },
      { bit: 29, name: "C", desc: "Carry" },
      { bit: 28, name: "V", desc: "Overflow" },
      { bit: 27, name: "Q", desc: "Saturation" },
      { bit: 19, name: "GE0", desc: "Greater/Equal [0]" },
      { bit: 18, name: "GE1", desc: "Greater/Equal [1]" },
      { bit: 17, name: "GE2", desc: "Greater/Equal [2]" },
      { bit: 16, name: "GE3", desc: "Greater/Equal [3]" },
    ],
    NZCV: [
      // AArch64 condition flags
      { bit: 31, name: "N", desc: "Negative" },
      { bit: 30, name: "Z", desc: "Zero" },
      { bit: 29, name: "C", desc: "Carry" },
      { bit: 28, name: "V", desc: "Overflow" },
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

  const pairValue = document.getElementById("pairSelect").value;
  const format = currentRuleData.format;

  if (pairValue === "ALL") {
    // Combine all pairs' dataflows
    const combinedPair = {
      dataflow: [],
      condition_readable: "All pairs combined",
    };

    currentRuleData.pairs.forEach((pair) => {
      if (pair.dataflow && Array.isArray(pair.dataflow)) {
        combinedPair.dataflow.push(...pair.dataflow);
      }
    });

    // Count unique conditions
    const conditionCounts = {};
    combinedPair.dataflow.forEach((flow) => {
      const cond = flow.condition || "UNCONDITIONAL";
      conditionCounts[cond] = (conditionCounts[cond] || 0) + 1;
    });

    console.log(
      "Rendering ALL pairs:",
      currentRuleData.pairs.length,
      "pairs with",
      combinedPair.dataflow.length,
      "total dataflows"
    );
    console.log("Condition distribution:", conditionCounts);
    console.log("Sample dataflow entries:", combinedPair.dataflow.slice(0, 5));

    // Render register display (use first pair for display)
    renderRegisters(format, currentRuleData.pairs[0]);

    // Render combined flow graph
    renderFlowGraph(combinedPair, format);
  } else {
    const pairIdx = parseInt(pairValue);
    const pair = currentRuleData.pairs[pairIdx];

    // Render register display
    renderRegisters(format, pair);

    // Render flow graph
    renderFlowGraph(pair, format);
  }
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

function highlightConnectedEdges(nodeId, type) {
  console.log("Highlighting node:", nodeId, "type:", type);
  const startTime = performance.now();

  const svg = document.getElementById("flowGraph");
  const scrollWrapper = svg.closest(".graph-scroll-wrapper");

  // Use pre-built maps for O(1) lookup
  if (!graphNodeMap || !graphEdgesByFrom || !graphEdgesByTo) {
    console.error("Graph maps not initialized!");
    return;
  }

  const clickedNode = graphNodeMap.get(nodeId);

  // Check if clicking the same node again (to unselect)
  const wasAlreadyHighlighted = clickedNode?.classList.contains("highlighted");

  // Batch all DOM modifications in a single frame
  requestAnimationFrame(() => {
    // Clear previous highlights using tracked array
    graphHighlightedElements.forEach((el) => {
      el.classList.remove("highlighted");
    });
    graphHighlightedElements = [];

    // If was already highlighted, unselect (remove dimming) and return
    if (wasAlreadyHighlighted) {
      scrollWrapper.classList.remove("has-selection");
      console.log("Unselected node in", performance.now() - startTime, "ms");
      return;
    }

    // Add selection state to dim non-highlighted elements
    scrollWrapper.classList.add("has-selection");

    const toHighlight = [];

    if (clickedNode) {
      toHighlight.push(clickedNode);
    }

    // Find and collect all elements to highlight
    if (type === "input") {
      const edges = graphEdgesByFrom.get(nodeId) || [];
      console.log("Found", edges.length, "edges from this input node");
      edges.forEach((edge) => {
        toHighlight.push(edge);
        const toId = edge.getAttribute("data-to");
        const toNode = graphNodeMap.get(toId);
        if (toNode && !toHighlight.includes(toNode)) {
          toHighlight.push(toNode);
        }
      });
    } else if (type === "output") {
      const edges = graphEdgesByTo.get(nodeId) || [];
      console.log("Found", edges.length, "edges to this output node");
      edges.forEach((edge) => {
        toHighlight.push(edge);
        const fromId = edge.getAttribute("data-from");
        const fromNode = graphNodeMap.get(fromId);
        if (fromNode && !toHighlight.includes(fromNode)) {
          toHighlight.push(fromNode);
        }
      });
    }

    // Apply all highlights at once
    toHighlight.forEach((el) => {
      el.classList.add("highlighted");
    });
    graphHighlightedElements = toHighlight;

    console.log(
      "Highlighted",
      toHighlight.length,
      "elements in",
      performance.now() - startTime,
      "ms"
    );

    // Center the clicked node
    if (clickedNode) {
      const transform = clickedNode.getAttribute("transform");
      const match = transform.match(/translate\((\d+),\s*(\d+)\)/);
      if (match) {
        const x = parseInt(match[1]);
        const y = parseInt(match[2]);

        const scrollLeft = x - scrollWrapper.clientWidth / 2;
        const scrollTop = y - scrollWrapper.clientHeight / 2;

        scrollWrapper.scrollTo({
          left: Math.max(0, scrollLeft),
          top: Math.max(0, scrollTop),
          behavior: "smooth",
        });
      }
    }
  });
}

function renderFlowGraph(pair, format) {
  const svg = document.getElementById("flowGraph");

  console.log("=== renderFlowGraph called ===");
  console.log("Pair:", pair);
  console.log("Dataflow length:", pair.dataflow ? pair.dataflow.length : 0);

  // Clear previous content
  svg.innerHTML = "";

  // Add zoom controls
  const scrollWrapper = svg.closest(".graph-scroll-wrapper");
  if (!document.getElementById("zoom-controls")) {
    const zoomControls = document.createElement("div");
    zoomControls.id = "zoom-controls";
    zoomControls.style.cssText = `
      position: sticky;
      top: 10px;
      right: 10px;
      z-index: 1000;
      display: flex;
      gap: 5px;
      float: right;
      margin: 10px;
    `;

    const zoomInBtn = document.createElement("button");
    zoomInBtn.textContent = "+";
    zoomInBtn.style.cssText =
      "width: 30px; height: 30px; font-size: 18px; cursor: pointer; background: white; border: 1px solid #ccc; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.2);";
    zoomInBtn.onclick = () => {
      const currentScale = parseFloat(
        svg.style.transform?.match(/scale\(([\d.]+)\)/)?.[1] || 1
      );
      const newScale = Math.min(currentScale + 0.2, 3);
      svg.style.transform = `scale(${newScale})`;
      svg.style.transformOrigin = "top left";
    };

    const zoomOutBtn = document.createElement("button");
    zoomOutBtn.textContent = "-";
    zoomOutBtn.style.cssText =
      "width: 30px; height: 30px; font-size: 18px; cursor: pointer; background: white; border: 1px solid #ccc; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.2);";
    zoomOutBtn.onclick = () => {
      const currentScale = parseFloat(
        svg.style.transform?.match(/scale\(([\d.]+)\)/)?.[1] || 1
      );
      const newScale = Math.max(currentScale - 0.2, 0.2);
      svg.style.transform = `scale(${newScale})`;
      svg.style.transformOrigin = "top left";
    };

    const zoomResetBtn = document.createElement("button");
    zoomResetBtn.textContent = "100%";
    zoomResetBtn.style.cssText =
      "width: 50px; height: 30px; font-size: 12px; cursor: pointer; background: white; border: 1px solid #ccc; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.2);";
    zoomResetBtn.onclick = () => {
      svg.style.transform = "scale(1)";
    };

    zoomControls.appendChild(zoomInBtn);
    zoomControls.appendChild(zoomResetBtn);
    zoomControls.appendChild(zoomOutBtn);
    scrollWrapper.insertBefore(zoomControls, scrollWrapper.firstChild);
  }

  if (!pair.dataflow || !Array.isArray(pair.dataflow)) {
    svg.innerHTML =
      '<text x="50%" y="50%" text-anchor="middle" fill="#333">No dataflow to display</text>';
    console.log("No dataflow to display for pair");
    return;
  }

  console.log(
    "Rendering flow graph with",
    pair.dataflow.length,
    "dataflow entries"
  );
  console.log("First dataflow entry:", pair.dataflow[0]);

  // Collect all input and output bits first to calculate size
  const inputBits = new Set();
  const outputBits = new Set();
  const edges = [];

  pair.dataflow.forEach((flow) => {
    const outBit = flow.output_bit;
    const inBits = flow.input_bits || [];
    const condition = flow.condition || "UNCONDITIONAL";

    outputBits.add(JSON.stringify(outBit));
    inBits.forEach((inBit) => {
      inputBits.add(JSON.stringify(inBit));
      edges.push({
        from: JSON.stringify(inBit),
        to: JSON.stringify(outBit),
        condition: condition,
      });
    });
  });

  console.log("Created", edges.length, "edges");
  if (edges.length > 0) {
    console.log("First edge:", edges[0]);
    console.log("First edge condition:", edges[0].condition);
  }

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
      path.setAttribute("data-from", edge.from);
      path.setAttribute("data-to", edge.to);
      path.setAttribute("data-condition", edge.condition || "UNCONDITIONAL");
      path.innerHTML = `<title>${edge.from} → ${edge.to}\nCondition: ${
        edge.condition || "UNCONDITIONAL"
      }</title>`;

      // Add hover handler to show condition
      path.addEventListener("mouseover", function (e) {
        const tooltip =
          document.getElementById("edge-tooltip") || createTooltip();
        const condition = this.getAttribute("data-condition");
        tooltip.textContent = condition;
        tooltip.style.display = "block";
        tooltip.style.left = e.pageX + 10 + "px";
        tooltip.style.top = e.pageY + 10 + "px";
      });

      path.addEventListener("mouseout", function () {
        const tooltip = document.getElementById("edge-tooltip");
        if (tooltip) tooltip.style.display = "none";
      });

      svg.appendChild(path);
    }
  });

  // Helper function to create tooltip
  function createTooltip() {
    const tooltip = document.createElement("div");
    tooltip.id = "edge-tooltip";
    tooltip.style.position = "fixed";
    tooltip.style.background = "rgba(0, 0, 0, 0.8)";
    tooltip.style.color = "white";
    tooltip.style.padding = "8px 12px";
    tooltip.style.borderRadius = "4px";
    tooltip.style.fontSize = "12px";
    tooltip.style.zIndex = "10000";
    tooltip.style.pointerEvents = "none";
    tooltip.style.maxWidth = "400px";
    tooltip.style.wordWrap = "break-word";
    tooltip.style.display = "none";
    document.body.appendChild(tooltip);
    return tooltip;
  }

  // Draw input nodes
  inputArray.forEach((bit, idx) => {
    const key = JSON.stringify(bit);
    const pos = inputPos[key];
    const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
    g.setAttribute("class", "bit-node input");
    g.setAttribute("transform", `translate(${pos.x}, ${pos.y})`);
    g.setAttribute("data-node-id", key);

    const circle = document.createElementNS(
      "http://www.w3.org/2000/svg",
      "circle"
    );
    circle.setAttribute("r", 15);
    g.appendChild(circle);

    const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
    text.setAttribute("class", "circle-label");
    text.textContent = "IN";
    g.appendChild(text);

    // Add click handler for highlighting
    g.addEventListener("click", function (e) {
      e.stopPropagation();
      console.log("Input node clicked:", key);
      highlightConnectedEdges(key, "input");
    });

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
    g.setAttribute("data-node-id", key);

    const circle = document.createElementNS(
      "http://www.w3.org/2000/svg",
      "circle"
    );
    circle.setAttribute("r", 15);
    g.appendChild(circle);

    const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
    text.setAttribute("class", "circle-label");
    text.textContent = "OUT";
    g.appendChild(text);

    // Add click handler for highlighting
    g.addEventListener("click", function (e) {
      e.stopPropagation();
      console.log("Output node clicked:", key);
      highlightConnectedEdges(key, "output");
    });

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

  // Build lookup maps once for O(1) click performance
  console.log("Building lookup maps for fast interaction...");
  graphNodeMap = new Map();
  document.querySelectorAll("[data-node-id]").forEach((node) => {
    graphNodeMap.set(node.getAttribute("data-node-id"), node);
  });

  graphEdgesByFrom = new Map();
  graphEdgesByTo = new Map();
  document.querySelectorAll(".flow-line").forEach((edge) => {
    const from = edge.getAttribute("data-from");
    const to = edge.getAttribute("data-to");
    if (!graphEdgesByFrom.has(from)) graphEdgesByFrom.set(from, []);
    if (!graphEdgesByTo.has(to)) graphEdgesByTo.set(to, []);
    graphEdgesByFrom.get(from).push(edge);
    graphEdgesByTo.get(to).push(edge);
  });
  console.log(
    "Maps built:",
    graphNodeMap.size,
    "nodes,",
    graphEdgesByFrom.size,
    "edge sources"
  );

  // Add click handler to SVG background to unselect
  svg.addEventListener("click", function (e) {
    // Only unselect if clicking directly on SVG (not on child elements)
    if (e.target === svg) {
      const scrollWrapper = svg.closest(".graph-scroll-wrapper");
      if (scrollWrapper && scrollWrapper.classList.contains("has-selection")) {
        graphHighlightedElements.forEach((el) => {
          el.classList.remove("highlighted");
        });
        graphHighlightedElements = [];
        scrollWrapper.classList.remove("has-selection");
        console.log("Unselected via background click");
      }
    }
  });
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
