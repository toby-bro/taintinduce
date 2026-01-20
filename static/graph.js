// Graph rendering functions for TaintInduce Visualizer

// Global state for graph interaction
let graphNodeMap = new Map();
let graphEdgesByFrom = new Map();
let graphEdgesByTo = new Map();
let graphHighlightedElements = [];

function resetGraphState() {
  // Clear all graph-related state when loading a new rule
  graphNodeMap.clear();
  graphEdgesByFrom.clear();
  graphEdgesByTo.clear();
  graphHighlightedElements = [];

  // Remove any selection state from the UI
  const scrollWrapper = document.querySelector(".graph-scroll-wrapper");
  if (scrollWrapper) {
    scrollWrapper.classList.remove("has-selection");
  }

  console.log("Graph state reset");
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

    currentRuleData.pairs.forEach((pair, pairIdx) => {
      if (pair.dataflow && Array.isArray(pair.dataflow)) {
        if (pairIdx < 3) {
          console.log(
            `Pair ${pairIdx + 1} has ${pair.dataflow.length} flows, sample:`,
            pair.dataflow[0],
          );
        }
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
      "total dataflows",
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
    if (reg.name === "EFLAGS" || reg.name === "RFLAGS" || reg.name === "NZCV") {
      html += decodeFlags(reg.name, reg.bits);
    }

    html += "</div>";
  });

  container.innerHTML = html;
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

  const mapKey = type + ":" + nodeId;
  const clickedNode = graphNodeMap.get(mapKey);

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
      console.log("Adding clicked node to highlight list (key:", mapKey, ")");
    } else {
      console.error("Clicked node not found in graphNodeMap for key:", mapKey);
    }

    // Find and collect all elements to highlight
    if (type === "input") {
      const edges = graphEdgesByFrom.get(nodeId) || [];
      console.log("Found", edges.length, "edges from this input node");
      console.log(
        "Sample edge data-condition:",
        edges[0]?.getAttribute("data-condition"),
      );
      edges.forEach((edge) => {
        toHighlight.push(edge);
        const toId = edge.getAttribute("data-to");
        const toNode = graphNodeMap.get("output:" + toId);
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
        const fromNode = graphNodeMap.get("input:" + fromId);
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
      "ms",
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
        svg.style.transform?.match(/scale\(([\d.]+)\)/)?.[1] || 1,
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
        svg.style.transform?.match(/scale\(([\d.]+)\)/)?.[1] || 1,
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
    "dataflow entries",
  );
  console.log("First dataflow entry:", pair.dataflow[0]);

  // Collect all input and output bits first to calculate size
  const inputBits = new Set();
  const outputBits = new Set();
  const edgeMap = new Map(); // Use Map to merge edges with same from->to

  pair.dataflow.forEach((flow) => {
    const outBit = flow.output_bit;
    const inBits = flow.input_bits || [];
    const condition = flow.condition || "UNCONDITIONAL";
    const pairIndex = flow.pair_index;

    outputBits.add(JSON.stringify(outBit));
    inBits.forEach((inBit) => {
      inputBits.add(JSON.stringify(inBit));

      const from = JSON.stringify(inBit);
      const to = JSON.stringify(outBit);
      const key = from + "→" + to;

      if (edgeMap.has(key)) {
        // Merge conditions for same input->output pair
        const existing = edgeMap.get(key);
        if (existing.condition !== condition) {
          // Different conditions - combine them
          if (!existing.conditions) {
            existing.conditions = [existing.condition];
            existing.pairIndices = [existing.pairIndex];
          }
          existing.conditions.push(condition);
          existing.pairIndices.push(pairIndex);
          existing.condition = `${existing.conditions.length} different conditions`;
        }
      } else {
        edgeMap.set(key, {
          from: from,
          to: to,
          condition: condition,
          pairIndex: pairIndex,
        });
      }
    });
  });

  const edges = Array.from(edgeMap.values());
  const mergedEdges = edges.filter((e) => e.conditions).length;

  console.log(
    "Created",
    edges.length,
    "edges (merged",
    mergedEdges,
    "edges with multiple conditions)",
  );
  if (edges.length > 0) {
    console.log("First edge:", edges[0]);
    console.log("First edge condition:", edges[0].condition);
    // Log 10 random edges to see condition distribution
    const sampleIndices = [
      0, 50, 100, 150, 200, 250, 300, 350, 400, 450,
    ].filter((i) => i < edges.length);
    console.log("Sample edges:");
    sampleIndices.forEach((i) => {
      console.log(`  Edge ${i}: condition ="${edges[i].condition}"`);
    });
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
        "path",
      );
      const midX = (from.x + to.x) / 2;
      const d = `M ${from.x} ${from.y} C ${midX} ${from.y}, ${midX} ${to.y}, ${to.x} ${to.y}`;
      path.setAttribute("d", d);
      path.setAttribute("class", "flow-line");
      path.setAttribute("data-from", edge.from);
      path.setAttribute("data-to", edge.to);
      path.setAttribute("data-condition", edge.condition || "UNCONDITIONAL");

      // Store multiple conditions if they exist
      if (edge.conditions) {
        path.setAttribute("data-conditions", JSON.stringify(edge.conditions));
        path.setAttribute(
          "data-pair-indices",
          JSON.stringify(edge.pairIndices),
        );
      } else if (edge.pairIndex !== undefined) {
        path.setAttribute("data-pair-index", edge.pairIndex);
      }

      // Debug: log first 5 edges to verify data-condition is set
      if (svg.querySelectorAll(".flow-line").length < 5) {
        console.log(
          `Setting edge ${
            svg.querySelectorAll(".flow-line").length
          }: data-condition="${edge.condition || "UNCONDITIONAL"}"${
            edge.conditions ? ` (${edge.conditions.length} total)` : ""
          }`,
        );
        if (edge.conditions) {
          console.log("  conditions array:", edge.conditions);
        }
      }

      path.innerHTML = `<title>${edge.from} → ${edge.to}\nCondition: ${
        edge.condition || "UNCONDITIONAL"
      }</title>`;

      // Add hover handler to show condition
      path.addEventListener("mouseenter", function (e) {
        const tooltip =
          document.getElementById("edge-tooltip") || createTooltip();
        const multiConditions = this.getAttribute("data-conditions");

        console.log("Hover on edge:", {
          "data-condition": this.getAttribute("data-condition"),
          "data-conditions exists": !!multiConditions,
          "data-conditions length": multiConditions?.length,
        });

        if (multiConditions) {
          // Show all conditions
          const conditions = JSON.parse(multiConditions);
          console.log("Parsed conditions:", conditions.length, "items");
          const header = `<div style="font-weight: bold; margin-bottom: 8px; border-bottom: 1px solid rgba(255,255,255,0.3); padding-bottom: 4px;">${conditions.length} Conditions for this edge:</div>`;
          const conditionList = conditions
            .map(
              (c, i) =>
                `<div style="margin: 6px 0; padding-left: 8px; border-left: 2px solid rgba(255,255,255,0.4);"><strong style="color: #4fc3f7;">${
                  i + 1
                }.</strong> ${formatConditionText(c, currentRuleData.format)}</div>`,
            )
            .join("");
          tooltip.innerHTML = header + conditionList;
          console.log(
            "Tooltip HTML length:",
            tooltip.innerHTML.length,
            "first 200 chars:",
            tooltip.innerHTML.substring(0, 200),
          );
        } else {
          const condition =
            this.getAttribute("data-condition") || "UNCONDITIONAL";
          tooltip.textContent = formatConditionText(
            condition,
            currentRuleData.format,
          );
        }

        tooltip.style.display = "block";
        tooltip.style.left = e.pageX + 10 + "px";
        tooltip.style.top = e.pageY + 10 + "px";
      });

      path.addEventListener("mouseleave", function () {
        const tooltip = document.getElementById("edge-tooltip");
        if (tooltip) tooltip.style.display = "none";
      });

      // Add click handler to show full conditions in side panel
      path.addEventListener("click", function (e) {
        e.stopPropagation();
        const panel = document.getElementById("edgeDetailsPanel");
        const content = document.getElementById("edgeDetailsContent");
        const multiConditions = this.getAttribute("data-conditions");
        const fromBit = JSON.parse(this.getAttribute("data-from"));
        const toBit = JSON.parse(this.getAttribute("data-to"));

        let html = `<div style="margin-bottom: 15px; padding: 10px; background: white; border-radius: 4px;">
          <strong style="color: #667eea;">From:</strong> ${formatBitPosition(fromBit)}<br>
          <strong style="color: #764ba2;">To:</strong> ${formatBitPosition(toBit)}
        </div>`;

        // Add view toggle buttons
        html += `<div style="display: flex; gap: 8px; margin-bottom: 15px;">
          <button onclick="toggleConditionView('dnf')" id="viewToggleDNF" style="
            padding: 8px 16px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
          ">📝 DNF Text</button>
          <button onclick="toggleConditionView('bitmask')" id="viewToggleBitmask" style="
            padding: 8px 16px;
            background: #e0e0e0;
            color: #333;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
          ">🎨 Visual Bitmask</button>
        </div>`;

        if (multiConditions) {
          const conditions = JSON.parse(multiConditions);
          const pairIndices = this.getAttribute("data-pair-indices");
          const indices = pairIndices ? JSON.parse(pairIndices) : [];

          // DNF view
          html += `<div id="dnfView" style="display: block;">`;
          html += `<div style="font-weight: bold; margin-bottom: 10px; color: #333;">${conditions.length} Conditions:</div>`;
          conditions.forEach((condition, i) => {
            const formatted = formatConditionText(
              condition,
              currentRuleData.format,
            );
            const pairIdx = indices[i] !== undefined ? indices[i] + 1 : i + 1;
            html += `<div style="margin-bottom: 12px; padding: 10px; background: white; border-radius: 4px; border-left: 3px solid #667eea;">
              <div style="font-weight: bold; color: #667eea; margin-bottom: 4px;">Condition ${pairIdx}:</div>
              <div style="word-break: break-word;">${formatted}</div>
            </div>`;
          });
          html += `</div>`;

          // Bitmask view
          html += `<div id="bitmaskView" style="display: none;">`;
          conditions.forEach((condition, i) => {
            const pairIdx = indices[i] !== undefined ? indices[i] + 1 : i + 1;
            html += `<div style="margin-bottom: 20px;">`;
            html += `<div style="font-weight: bold; color: #667eea; margin-bottom: 8px; font-size: 14px;">Condition ${pairIdx}:</div>`;
            html += renderBitmaskView(condition, currentRuleData.format);
            html += `</div>`;
          });
          html += `</div>`;
        } else {
          const condition =
            this.getAttribute("data-condition") || "UNCONDITIONAL";
          const pairIndex = this.getAttribute("data-pair-index");
          const formatted = formatConditionText(
            condition,
            currentRuleData.format,
          );
          const label =
            pairIndex !== null
              ? `Condition ${parseInt(pairIndex) + 1}:`
              : "Condition:";

          // DNF view
          html += `<div id="dnfView" style="display: block;">`;
          html += `<div style="padding: 10px; background: white; border-radius: 4px;">
            <div style="font-weight: bold; color: #667eea; margin-bottom: 4px;">${label}</div>
            <div style="word-break: break-word;">${formatted}</div>
          </div>`;
          html += `</div>`;

          // Bitmask view
          html += `<div id="bitmaskView" style="display: none;">`;
          html += `<div style="font-weight: bold; color: #667eea; margin-bottom: 8px;">${label}</div>`;
          html += renderBitmaskView(condition, currentRuleData.format);
          html += `</div>`;
        }

        content.innerHTML = html;
        panel.style.display = "block";
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
    tooltip.style.maxWidth = "600px";
    tooltip.style.maxHeight = "400px";
    tooltip.style.overflow = "auto";
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
      "circle",
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
      "title",
    );
    title.textContent = formatBitPosition(bit);
    g.appendChild(title);

    // Label (adjust x position to avoid overlap with circles)
    const label = document.createElementNS(
      "http://www.w3.org/2000/svg",
      "text",
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
      "circle",
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
      "title",
    );
    title.textContent = formatBitPosition(bit);
    g.appendChild(title);

    // Label (adjust x position to not overlap)
    const label = document.createElementNS(
      "http://www.w3.org/2000/svg",
      "text",
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
    "circle",
  );
  inputCircle.setAttribute("cx", 0);
  inputCircle.setAttribute("cy", 0);
  inputCircle.setAttribute("r", 8);
  inputCircle.setAttribute("fill", "#28a745");
  legend.appendChild(inputCircle);

  const inputText = document.createElementNS(
    "http://www.w3.org/2000/svg",
    "text",
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
    "circle",
  );
  outputCircle.setAttribute("cx", 100);
  outputCircle.setAttribute("cy", 0);
  outputCircle.setAttribute("r", 8);
  outputCircle.setAttribute("fill", "#ff6b6b");
  legend.appendChild(outputCircle);

  const outputText = document.createElementNS(
    "http://www.w3.org/2000/svg",
    "text",
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
  // Clear previous maps to avoid stale data from previous renders
  graphNodeMap.clear();
  graphEdgesByFrom.clear();
  graphEdgesByTo.clear();

  document.querySelectorAll(".bit-node.input").forEach((node) => {
    const nodeId = node.getAttribute("data-node-id");
    graphNodeMap.set("input:" + nodeId, node);
  });
  document.querySelectorAll(".bit-node.output").forEach((node) => {
    const nodeId = node.getAttribute("data-node-id");
    graphNodeMap.set("output:" + nodeId, node);
  });

  // Maps already cleared above, now populate them
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
    "edge sources",
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
