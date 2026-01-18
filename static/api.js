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
                <p>Condition: ${pair.condition_text}</p>
                <div style="margin-top: 10px;">
                    <strong>Dataflows (${pair.dataflows.length}):</strong>
                    <div style="max-height: 200px; overflow-y: auto; margin-top: 5px;">
                        ${pair.dataflows
                          .map(
                            (f) =>
                              `<div class="flow-item">Bit ${f.input} → [${f.outputs}]</div>`,
                          )
                          .join("")}
                    </div>
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
                <button onclick="document.getElementById('input-state').value='${tc.input_state_hex || "0x0"}'; runSimulation();">
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
