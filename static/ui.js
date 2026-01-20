// UI functions for TaintInduce Visualizer

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
                          `<div class="flow-item">${f.input} → [${f.outputs}]</div>`,
                      )
                      .join("")}
                </div>
            </div>
        `;
  });

  container.innerHTML = html;
}

function updateAllDisplays(data) {
  // Store data globally
  currentRuleData = data;

  // Check if data has the expected structure
  if (!data || !data.format) {
    console.error("Invalid data structure - missing 'format' field:", data);
    return;
  }

  // Reset graph state to ensure clean state when loading new file
  if (typeof resetGraphState === "function") {
    resetGraphState();
  }

  // Reset simulator state to clear tainted bits and other state
  if (typeof resetSimulatorState === "function") {
    resetSimulatorState();
  }

  // Update overview statistics using the correct element IDs
  document.getElementById("rule-file").textContent =
    data.filename || "Uploaded Rule";
  document.getElementById("arch").textContent = data.format?.arch || "N/A";

  // Add instruction display
  if (data.instruction) {
    const instrEl = document.getElementById("instruction");
    if (instrEl) {
      instrEl.innerHTML = `<strong>${data.instruction.bytestring}</strong><br><span style="color: #667eea; font-family: monospace;">${data.instruction.asm}</span>`;
    }
  }

  document.getElementById("num-regs").textContent =
    data.format?.registers?.length || 0;
  document.getElementById("num-mem").textContent = data.format?.mem_slots || 0;
  document.getElementById("num-pairs").textContent =
    data.num_pairs || data.pairs?.length || 0;

  // Show register format details in the registers-list div
  if (data.format.registers && Array.isArray(data.format.registers)) {
    const regHTML = data.format.registers
      .map((r) => `<li><strong>${r.name}</strong>: ${r.bits} bits</li>`)
      .join("");
    document.getElementById("registers-list").innerHTML = `
      <h3>Register Format</h3>
      <ul>${regHTML}</ul>
    `;
  }

  // Load pairs tab
  if (data.pairs && Array.isArray(data.pairs)) {
    loadPairs(data.pairs);
  }

  // Update graph tab
  populatePairSelector();
  if (data.pairs && data.pairs.length > 0) {
    document.getElementById("pairSelect").value = "ALL";
    renderGraph();
  }

  // Initialize simulator with register inputs
  if (typeof initializeSimulator === "function") {
    initializeSimulator();
  }

  // Clear condition matcher results from previous rule
  const matchingPairsContainer = document.getElementById("matching-pairs");
  if (matchingPairsContainer) {
    matchingPairsContainer.innerHTML = "";
  }

  const simulationResults = document.getElementById("simulation-results");
  if (simulationResults) {
    simulationResults.classList.remove("show");
  }
}
