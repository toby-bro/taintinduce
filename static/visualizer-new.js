// TaintInduce Visualizer - Main Entry Point
// Functions are now split across multiple files:
// - utils.js: Utility functions (flag names, bit formatting, register sorting)
// - conditions.js: Condition parsing and rendering (DNF, bitmask views)
// - ui.js: UI interactions (tab switching, display updates)
// - api.js: API calls and data loading
// - graph.js: Graph rendering and visualization

// Global state
let currentRuleData = null;

// Initialize on page load
document.addEventListener("DOMContentLoaded", () => {
  loadRuleData();
  populatePairSelector();
});
