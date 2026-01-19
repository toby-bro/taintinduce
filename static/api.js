// API functions for TaintInduce Visualizer

async function loadRuleData() {
  const response = await fetch("/api/rule");
  const data = await response.json();

  // Update all displays
  updateAllDisplays(data);

  // Load test cases (only available from backend)
  loadTestCases();
}

async function handleRuleFileUpload(event) {
  const file = event.target.files[0];
  if (!file) return;

  const statusEl = document.getElementById("uploadStatus");
  statusEl.textContent = "Uploading...";
  statusEl.style.color = "#ffc107";

  try {
    // Read the file content as text and parse as JSON
    const fileContent = await file.text();
    const jsonData = JSON.parse(fileContent);

    const response = await fetch("/api/upload-rule", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(jsonData),
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.error || "Upload failed");
    }

    const uploadResult = await response.json();

    // Upload successful, now fetch the formatted rule data from /api/rule
    if (!uploadResult.success) {
      throw new Error(uploadResult.error || "Upload failed");
    }

    const ruleResponse = await fetch("/api/rule");
    if (!ruleResponse.ok) {
      throw new Error("Failed to fetch rule data after upload");
    }

    const data = await ruleResponse.json();

    // Update the global state and UI
    currentRuleData = data;
    updateAllDisplays(data);

    statusEl.textContent = `✓ Loaded: ${file.name}`;
    statusEl.style.color = "#28a745";

    // Auto-select ALL pairs and render graph
    populatePairSelector();
    if (data.pairs && data.pairs.length > 0) {
      document.getElementById("pairSelect").value = "ALL";
      renderGraph();
    }

    setTimeout(() => {
      statusEl.textContent = "";
    }, 3000);
  } catch (error) {
    statusEl.textContent = `✗ Error: ${error.message}`;
    statusEl.style.color = "#dc3545";
    console.error("Upload error:", error);
  }
}

// Track current view mode for condition matcher
let conditionMatcherView = "dnf";

function toggleConditionMatcherView(view) {
  conditionMatcherView = view;
  const dnfBtn = document.getElementById("matcherViewToggleDNF");
  const bitmaskBtn = document.getElementById("matcherViewToggleBitmask");

  if (view === "dnf") {
    dnfBtn.style.background = "#667eea";
    dnfBtn.style.color = "white";
    bitmaskBtn.style.background = "#e0e0e0";
    bitmaskBtn.style.color = "#333";
  } else {
    dnfBtn.style.background = "#e0e0e0";
    dnfBtn.style.color = "#333";
    bitmaskBtn.style.background = "#667eea";
    bitmaskBtn.style.color = "white";
  }

  // Re-run matcher to update display
  findMatchingConditions();
}

async function findMatchingConditions() {
  if (!currentRuleData || !currentRuleData.format) {
    console.log("No rule data loaded yet");
    return;
  }

  // Get current state from input registers
  const format = currentRuleData.format;
  let stateValue = 0n;
  let bitOffset = 0;

  format.registers.forEach((reg) => {
    for (let bitIdx = 0; bitIdx < reg.bits; bitIdx++) {
      const valueEl = document.getElementById(
        `bit-value-${reg.name}-${bitIdx}`,
      );
      if (valueEl) {
        const bitValue = parseInt(valueEl.textContent);
        if (bitValue === 1) {
          stateValue |= 1n << BigInt(bitOffset + bitIdx);
        }
      }
    }
    bitOffset += reg.bits;
  });

  const inputStateHex = "0x" + stateValue.toString(16).toUpperCase();

  const response = await fetch("/api/taint", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ input_state: inputStateHex }),
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
            <h4>Current State: ${results.input_state_hex}</h4>
            <p><strong>${results.matching_pairs.length}</strong> condition(s) matched</p>
        </div>
    `;

  results.matching_pairs.forEach((pair) => {
    const formattedCondition = formatConditionText(pair.condition_text, format);

    // Get the actual pair data from currentRuleData to access all dataflows
    const pairData = currentRuleData.pairs[pair.pair_index];
    const dataflows = pairData.dataflow || [];

    html += `
            <div class="result-card">
                <h4>✅ Pair ${pair.pair_index + 1} Matched ${
                  pair.is_unconditional
                    ? '<span class="badge badge-success">UNCONDITIONAL</span>'
                    : ""
                }</h4>`;

    // Show DNF or Bitmask view based on toggle
    if (conditionMatcherView === "dnf") {
      html += `<div style="padding: 10px; background: white; border-radius: 4px; margin: 10px 0;">
                  <div style="font-weight: bold; color: #667eea; margin-bottom: 4px;">Condition:</div>
                  <div style="word-break: break-word; font-family: monospace; font-size: 13px;">${formattedCondition}</div>
                </div>`;
    } else {
      html += `<div style="margin: 10px 0;">${renderBitmaskView(pair.condition_text, format)}</div>`;
    }

    // Build dataflow display from local data
    html += `<div style="margin-top: 10px;">
                    <strong>Dataflows (${dataflows.length} total):</strong>
                    <div style="max-height: 400px; overflow-y: auto; margin-top: 5px; border: 1px solid #e0e0e0; border-radius: 4px; padding: 8px; background: #fafafa;">`;

    if (dataflows.length > 0) {
      dataflows.forEach((flow) => {
        // Each flow has input_bits (array) and output_bit (single bit object)
        const inputBits = flow.input_bits || [];
        const outputBit = flow.output_bit;

        const inputNames =
          inputBits.map((bit) => formatBitPosition(bit)).join(", ") ||
          '<span style="color: #999;">no inputs</span>';
        const outputName = outputBit
          ? formatBitPosition(outputBit)
          : '<span style="color: #999;">no output</span>';

        html += `<div class="flow-item" style="padding: 4px 0; border-bottom: 1px solid #eee; font-family: monospace; font-size: 12px;">
                   <span style="color: #28a745;">${inputNames}</span> → <span style="color: #dc3545;">${outputName}</span>
                 </div>`;
      });
    } else {
      html += `<div style="color: #999; font-style: italic; padding: 8px;">No dataflows</div>`;
    }

    html += `</div>
                </div>
            </div>
        `;
  });

  if (results.matching_pairs.length === 0) {
    html += `<div class="result-card no-match">❌ No conditions matched this input state</div>`;
  }

  container.innerHTML = html;
}

async function loadTestCases() {
  const response = await fetch("/api/test-cases");
  const data = await response.json();

  const container = document.getElementById("test-cases");
  let html = "";

  data.test_cases.forEach((tc, idx) => {
    html += `
            <div class="result-card">
                <h4>Test Case ${idx + 1}</h4>
                <p><strong>Description:</strong> ${tc.description || "N/A"}</p>
                <p><strong>Input:</strong> ${tc.input_state_hex || "0x0"}</p>
                <p><strong>Pair Index:</strong> ${tc.pair_index !== undefined ? tc.pair_index + 1 : "N/A"}</p>
                ${tc.bitmask ? `<p><strong>Bitmask:</strong> ${tc.bitmask}</p>` : ""}
                ${tc.expected_value ? `<p><strong>Expected Value:</strong> ${tc.expected_value}</p>` : ""}
                <button onclick="if (window.updateBitsFromHex) { document.getElementById('input-state-hex').value='${tc.input_state_hex || "0x0"}'; window.updateBitsFromHex(); }">
                    Run This Test
                </button>
            </div>
        `;
  });

  container.innerHTML = html;
}

function populatePairSelector() {
  if (!currentRuleData) {
    console.error("populatePairSelector: currentRuleData is null/undefined");
    return;
  }

  if (!currentRuleData.pairs || !Array.isArray(currentRuleData.pairs)) {
    console.error(
      "populatePairSelector: currentRuleData.pairs is missing or not an array",
      currentRuleData,
    );
    return;
  }

  const selector = document.getElementById("pairSelect");
  selector.innerHTML = '<option value="ALL">All Pairs (Combined)</option>';

  currentRuleData.pairs.forEach((pair, idx) => {
    const label = pair.is_unconditional ? " (UNCONDITIONAL)" : "";
    selector.innerHTML += `<option value="${idx}">Pair ${idx + 1}${label}</option>`;
  });
}
