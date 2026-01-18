// Condition parsing and rendering for DNF and bitmask views

function formatConditionText(conditionText, format) {
  // Replace bit[N] references with register names
  if (!conditionText || !format) return conditionText;

  // Match patterns like "bit[39] = 0" or "bit[7]==1"
  return conditionText.replace(/bit\[(\d+)\]/g, (match, bitPos) => {
    const regName = globalBitToRegister(parseInt(bitPos), format);
    return regName || match;
  });
}

function parseDNFCondition(conditionText, format) {
  // Parse DNF condition into structured data for visual rendering
  // Returns: [{ registerName, bits: {bitNum: value (0/1/null for don't care)} }, ...]

  if (!conditionText || conditionText.includes("UNCONDITIONAL")) {
    return null;
  }

  // Extract OR clauses from "DNF: (clause1) OR (clause2) OR ..."
  const dnfMatch = conditionText.match(/DNF:\s*(.+)/);
  if (!dnfMatch) return null;

  const clausesText = dnfMatch[1];

  // Split by ') OR (' to get individual clauses
  const clauses = [];
  let depth = 0;
  let currentClause = "";

  for (let i = 0; i < clausesText.length; i++) {
    const char = clausesText[i];
    if (char === "(") depth++;
    if (char === ")") depth--;

    if (depth === 0 && clausesText.substring(i, i + 5) === ") OR ") {
      clauses.push(currentClause + ")");
      currentClause = "";
      i += 4; // Skip ' OR '
      continue;
    }
    currentClause += char;
  }
  if (currentClause) clauses.push(currentClause);

  // Parse each clause
  return clauses.map((clause) => {
    // Remove outer parentheses
    clause = clause.replace(/^\(/, "").replace(/\)$/, "");

    // Extract all conditions - can be either "EFLAGS[4:AF]=1" format or "bit[39]=1" format
    const registerBits = {};

    // Try register[bit:name]=value format first
    const regConditionRegex = /(\w+)\[(\d+)(?::[^\]]+)?\]\s*=\s*([01])/g;
    let match;
    while ((match = regConditionRegex.exec(clause)) !== null) {
      const [, regName, bitNum, value] = match;
      if (!registerBits[regName]) {
        registerBits[regName] = {};
      }
      registerBits[regName][parseInt(bitNum)] = parseInt(value);
    }

    // Also try bit[N]=value format and convert to register format
    const bitConditionRegex = /bit\[(\d+)\]\s*=\s*([01])/g;
    while ((match = bitConditionRegex.exec(clause)) !== null) {
      const [, globalBitPos, value] = match;
      const bitPos = parseInt(globalBitPos);

      // Convert global bit position to register + bit
      let currentPos = 0;
      for (const reg of format.registers) {
        if (bitPos < currentPos + reg.bits) {
          const bitInReg = bitPos - currentPos;
          if (!registerBits[reg.name]) {
            registerBits[reg.name] = {};
          }
          registerBits[reg.name][bitInReg] = parseInt(value);
          break;
        }
        currentPos += reg.bits;
      }
    }

    return registerBits;
  });
}

function renderBitmaskView(conditionText, format) {
  // Render visual bitmask representation of DNF condition
  const clauses = parseDNFCondition(conditionText, format);

  if (!clauses) {
    return '<div style="padding: 10px; color: #666;">No condition constraints (UNCONDITIONAL)</div>';
  }

  // Get all registers from format to show consistently
  const allRegisters = format.registers.map((r) => ({
    name: r.name,
    bits: r.bits,
  }));

  let html = '<div class="bitmask-view">';

  clauses.forEach((clause, clauseIdx) => {
    html += `<div class="bitmask-clause" style="margin-bottom: 15px; padding: 12px; background: white; border-radius: 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">`;
    html += `<div style="font-weight: bold; margin-bottom: 10px; color: #667eea; font-size: 13px;">OR Clause ${clauseIdx + 1}</div>`;

    // Show each register on its own line in a scrollable container
    html += `<div style="max-height: 400px; overflow-y: auto; overflow-x: auto;">`;

    allRegisters.forEach((reg, regIdx) => {
      const regName = reg.name;
      const regBits = reg.bits;
      const bits = clause[regName] || {};

      // Check if this register has any constraints
      const hasConstraints = Object.keys(bits).length > 0;
      const constraintCount = Object.keys(bits).length;

      html += `<div style="
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 8px;
        padding: 6px;
        background: ${hasConstraints ? "#f8f9ff" : "#fafafa"};
        border-radius: 4px;
      ">`;

      // Register label on the left
      html += `<div style="
        min-width: 80px;
        font-size: 11px;
        font-weight: 600;
        color: ${hasConstraints ? "#333" : "#999"};
        white-space: nowrap;
      ">${regName}${hasConstraints ? ` (${constraintCount})` : ""}</div>`;

      // Bit row
      html += `<div style="display: flex; gap: 1px; flex-wrap: nowrap;">`;

      // Render bits from MSB to LSB
      for (let bitNum = regBits - 1; bitNum >= 0; bitNum--) {
        const value = bits[bitNum];
        let color, text, title, textColor;

        if (value === 1) {
          color = "#4caf50"; // Green for must be 1
          text = "1";
          textColor = "white";
          title = `${regName}[${bitNum}]: must be 1`;
        } else if (value === 0) {
          color = "#f44336"; // Red for must be 0
          text = "0";
          textColor = "white";
          title = `${regName}[${bitNum}]: must be 0`;
        } else {
          color = "#f5f5f5"; // Light gray for don't care
          text = "·";
          textColor = "#ccc";
          title = `${regName}[${bitNum}]: don't care`;
        }

        const flagName = getFlagName(regName, bitNum);
        if (flagName) {
          title += ` (${flagName})`;
        }

        html += `<div style="
          width: 12px;
          height: 24px;
          background: ${color};
          color: ${textColor};
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 9px;
          font-weight: bold;
          border-radius: 2px;
          font-family: monospace;
          cursor: help;
          border: 1px solid ${value === 1 || value === 0 ? color : "#e0e0e0"};
        " title="${title}">${text}</div>`;
      }

      html += `</div></div>`;
    });

    html += `</div>`;

    // Show constraint count
    const totalConstraints = Object.values(clause).reduce(
      (sum, bits) => sum + Object.keys(bits).length,
      0,
    );
    html += `<div style="margin-top: 8px; font-size: 11px; color: #666; font-weight: 600;">Total: ${totalConstraints} bit constraints</div>`;
    html += `</div>`;
  });

  html += "</div>";
  return html;
}

function toggleConditionView(view) {
  const dnfView = document.getElementById("dnfView");
  const bitmaskView = document.getElementById("bitmaskView");
  const dnfBtn = document.getElementById("viewToggleDNF");
  const bitmaskBtn = document.getElementById("viewToggleBitmask");

  if (view === "dnf") {
    dnfView.style.display = "block";
    bitmaskView.style.display = "none";
    dnfBtn.style.background = "#667eea";
    dnfBtn.style.color = "white";
    bitmaskBtn.style.background = "#e0e0e0";
    bitmaskBtn.style.color = "#333";
  } else {
    dnfView.style.display = "none";
    bitmaskView.style.display = "block";
    dnfBtn.style.background = "#e0e0e0";
    dnfBtn.style.color = "#333";
    bitmaskBtn.style.background = "#667eea";
    bitmaskBtn.style.color = "white";
  }
}
