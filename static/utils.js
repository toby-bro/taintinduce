// Utility functions for TaintInduce Visualizer

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
      12: "IOPL",
      13: "IOPL",
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
      12: "IOPL",
      13: "IOPL",
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

function globalBitToRegister(bitPos, format) {
  // Convert a global bit position to register name and bit within that register
  if (!format || !format.registers) return null;

  let currentPos = 0;
  for (const reg of format.registers) {
    if (bitPos < currentPos + reg.bits) {
      const bitInReg = bitPos - currentPos;
      const flagName = getFlagName(reg.name, bitInReg);
      if (flagName) {
        return `${reg.name}[${bitInReg}:${flagName}]`;
      }
      return `${reg.name}[${bitInReg}]`;
    }
    currentPos += reg.bits;
  }

  // Check memory slots
  if (format.mem_slots) {
    for (let i = 0; i < format.mem_slots.length; i++) {
      const memSlot = format.mem_slots[i];
      if (bitPos < currentPos + memSlot.bits) {
        const bitInMem = bitPos - currentPos;
        return `MEM${i}[${bitInMem}]`;
      }
      currentPos += memSlot.bits;
    }
  }

  return `bit[${bitPos}]`; // Fallback
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

function decodeFlags(regName, bits, value = null) {
  // EFLAGS/RFLAGS flag decoding for x86/AMD64
  const flagDefs = {
    EFLAGS: [
      { bit: 0, name: "CF", desc: "Carry flag" },
      { bit: 2, name: "PF", desc: "Parity flag" },
      { bit: 4, name: "AF", desc: "Auxiliary Carry flag" },
      { bit: 6, name: "ZF", desc: "Zero flag" },
      { bit: 7, name: "SF", desc: "Sign flag" },
      { bit: 8, name: "TF", desc: "Trap flag (single step)" },
      { bit: 9, name: "IF", desc: "Interrupt enable flag" },
      { bit: 10, name: "DF", desc: "Direction flag" },
      { bit: 11, name: "OF", desc: "Overflow flag" },
      { bit: 12, name: "IOPL", desc: "I/O privilege level (bit 0)" },
      { bit: 13, name: "IOPL", desc: "I/O privilege level (bit 1)" },
      { bit: 14, name: "NT", desc: "Nested task flag" },
      { bit: 16, name: "RF", desc: "Resume flag" },
      { bit: 17, name: "VM", desc: "Virtual 8086 mode flag" },
      { bit: 18, name: "AC", desc: "Alignment Check / SMAP Access Check" },
      { bit: 19, name: "VIF", desc: "Virtual interrupt flag" },
      { bit: 20, name: "VIP", desc: "Virtual interrupt pending" },
      { bit: 21, name: "ID", desc: "Able to use CPUID instruction" },
    ],
    RFLAGS: [
      // 64-bit extension of EFLAGS
      { bit: 0, name: "CF", desc: "Carry flag" },
      { bit: 2, name: "PF", desc: "Parity flag" },
      { bit: 4, name: "AF", desc: "Auxiliary Carry flag" },
      { bit: 6, name: "ZF", desc: "Zero flag" },
      { bit: 7, name: "SF", desc: "Sign flag" },
      { bit: 8, name: "TF", desc: "Trap flag (single step)" },
      { bit: 9, name: "IF", desc: "Interrupt enable flag" },
      { bit: 10, name: "DF", desc: "Direction flag" },
      { bit: 11, name: "OF", desc: "Overflow flag" },
      { bit: 12, name: "IOPL", desc: "I/O privilege level (bit 0)" },
      { bit: 13, name: "IOPL", desc: "I/O privilege level (bit 1)" },
      { bit: 14, name: "NT", desc: "Nested task flag" },
      { bit: 16, name: "RF", desc: "Resume flag" },
      { bit: 17, name: "VM", desc: "Virtual 8086 mode flag" },
      { bit: 18, name: "AC", desc: "Alignment Check / SMAP Access Check" },
      { bit: 19, name: "VIF", desc: "Virtual interrupt flag" },
      { bit: 20, name: "VIP", desc: "Virtual interrupt pending" },
      { bit: 21, name: "ID", desc: "Able to use CPUID instruction" },
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
