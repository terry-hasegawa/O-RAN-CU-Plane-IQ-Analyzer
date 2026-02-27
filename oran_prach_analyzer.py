"""
O-RAN PRACH Analyzer
====================
Specialized tool for analyzing PRACH (Physical Random Access Channel) in
O-RAN fronthaul pcap captures.

Features:
  - C-Plane Section Type 3 (PRACH) parsing
  - U-Plane PRACH IQ data extraction (filterIndex-based detection)
  - PRACH timing validation against NR configuration tables
  - Per-occasion power (dBFS) analysis
  - Constellation diagram
  - PRACH periodicity and occasion mapping
  - Missing / unexpected occasion detection

Requirements:
    pip install scapy numpy matplotlib

Author: O-RAN PRACH Analyzer
"""

# ============================================================
# IMPORTS
# ============================================================
import os
import sys
import struct
import threading
import csv
import traceback
from collections import defaultdict, OrderedDict

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import numpy as np

try:
    import matplotlib
    matplotlib.use("TkAgg")
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
    from matplotlib.backends.backend_pdf import PdfPages
except ImportError:
    messagebox.showerror("Import Error",
                         "matplotlib not found.\nRun: pip install matplotlib")
    sys.exit(1)

try:
    from scapy.all import PcapReader
except ImportError:
    messagebox.showerror("Import Error",
                         "scapy not found.\nRun: pip install scapy")
    sys.exit(1)


# ============================================================
# CONSTANTS
# ============================================================
ECPRI_ETHERTYPE    = 0xAEFE
ECPRI_MSG_IQ_DATA  = 0x00   # U-Plane
ECPRI_MSG_RT_CTRL  = 0x02   # C-Plane

IQ_WIDTH           = 9
NUM_SUBC_PER_PRB   = 12
IQ_MAX_EXPONENT    = 15
REF_POWER_BASE     = 2.0 ** 46

# Filter indices (O-RAN WG4 CUS Section 7.5.2.13)
FILTER_INDEX_STANDARD = 0   # standard channel filter
FILTER_INDEX_PRACH    = 1   # PRACH
FILTER_INDEX_MIXED_NUM = 2  # mixed numerology

# Section types
SECTION_TYPE_0 = 0  # Unused RB / Idle
SECTION_TYPE_1 = 1  # Most DL/UL IQ data
SECTION_TYPE_3 = 3  # PRACH / Mixed-numerology
SECTION_TYPE_5 = 5  # UE scheduling info
SECTION_TYPE_6 = 6  # CH info
SECTION_TYPE_7 = 7  # LAA

# PRACH preamble formats
PRACH_FORMATS_LONG  = ["0", "1", "2", "3"]
PRACH_FORMATS_SHORT = ["A1", "A2", "A3", "B1", "B2", "B3", "B4", "C0", "C2"]

DEBUG_MAX_PACKETS = 100


# ============================================================
# NR PRACH CONFIGURATION TABLES
# ============================================================
# Source: 3GPP TS 38.211, Tables 6.3.3.2-2 and 6.3.3.2-3
#
# Key: config_index
# Value: (format, x, y, subframe_list, starting_symbol,
#         N_slot_RA, N_t_RA, N_dur_RA)
#
#   x, y  : SFN condition: SFN mod x == y
#   subframe_list: subframes where PRACH can occur
#   starting_symbol: starting OFDM symbol
#   N_slot_RA: num PRACH slots within a subframe (for mu_RA)
#   N_t_RA:   num time-domain PRACH occasions per slot
#   N_dur_RA: duration in OFDM symbols
#
# Table 6.3.3.2-2: Preamble formats 0, 1, 2, 3 (Long sequences, FR1)
# (Partial — most commonly used configs)
PRACH_CONFIG_TABLE_LONG = {
    0:  ("0",  16, 1,  [1],              0, 0, 0, 0),
    1:  ("0",  16, 1,  [4],              0, 0, 0, 0),
    2:  ("0",  16, 1,  [7],              0, 0, 0, 0),
    3:  ("0",  16, 1,  [1, 6],           0, 0, 0, 0),
    4:  ("0",  16, 1,  [2, 7],           0, 0, 0, 0),
    5:  ("0",  16, 1,  [3, 8],           0, 0, 0, 0),
    6:  ("0",  16, 1,  [1, 4, 7],        0, 0, 0, 0),
    7:  ("0",  16, 1,  [2, 5, 8],        0, 0, 0, 0),
    8:  ("0",  16, 1,  [3, 6, 9],        0, 0, 0, 0),
    9:  ("0",   8, 1,  [1],              0, 0, 0, 0),
    10: ("0",   8, 1,  [4],              0, 0, 0, 0),
    11: ("0",   8, 1,  [7],              0, 0, 0, 0),
    12: ("0",   8, 1,  [1, 6],           0, 0, 0, 0),
    13: ("0",   8, 1,  [2, 7],           0, 0, 0, 0),
    14: ("0",   8, 1,  [3, 8],           0, 0, 0, 0),
    15: ("0",   8, 1,  [1, 4, 7],        0, 0, 0, 0),
    16: ("0",   4, 1,  [1],              0, 0, 0, 0),
    17: ("0",   4, 1,  [4],              0, 0, 0, 0),
    18: ("0",   4, 1,  [7],              0, 0, 0, 0),
    19: ("0",   4, 1,  [1, 6],           0, 0, 0, 0),
    20: ("0",   4, 1,  [2, 7],           0, 0, 0, 0),
    21: ("0",   4, 1,  [3, 8],           0, 0, 0, 0),
    22: ("0",   4, 1,  [1, 4, 7],        0, 0, 0, 0),
    23: ("0",   4, 1,  [2, 5, 8],        0, 0, 0, 0),
    24: ("0",   4, 1,  [3, 6, 9],        0, 0, 0, 0),
    25: ("0",   2, 1,  [1],              0, 0, 0, 0),
    26: ("0",   2, 1,  [4],              0, 0, 0, 0),
    27: ("0",   2, 1,  [7],              0, 0, 0, 0),
    28: ("0",   2, 1,  [1, 6],           0, 0, 0, 0),
    29: ("0",   2, 1,  [2, 7],           0, 0, 0, 0),
    30: ("0",   2, 1,  [3, 8],           0, 0, 0, 0),
    31: ("0",   2, 1,  [1, 4, 7],        0, 0, 0, 0),
    32: ("0",   2, 1,  [2, 5, 8],        0, 0, 0, 0),
    33: ("0",   2, 1,  [3, 6, 9],        0, 0, 0, 0),
    34: ("0",   2, 1,  [0, 2, 4, 6, 8],  0, 0, 0, 0),
    35: ("0",   2, 1,  [1, 3, 5, 7, 9],  0, 0, 0, 0),
    36: ("0",   1, 0,  [1],              0, 0, 0, 0),
    37: ("0",   1, 0,  [4],              0, 0, 0, 0),
    38: ("0",   1, 0,  [7],              0, 0, 0, 0),
    39: ("0",   1, 0,  [1, 6],           0, 0, 0, 0),
    40: ("0",   1, 0,  [2, 7],           0, 0, 0, 0),
    41: ("0",   1, 0,  [3, 8],           0, 0, 0, 0),
    42: ("0",   1, 0,  [1, 4, 7],        0, 0, 0, 0),
    43: ("0",   1, 0,  [2, 5, 8],        0, 0, 0, 0),
    44: ("0",   1, 0,  [3, 6, 9],        0, 0, 0, 0),
    45: ("0",   1, 0,  [0, 2, 4, 6, 8],  0, 0, 0, 0),
    46: ("0",   1, 0,  [1, 3, 5, 7, 9],  0, 0, 0, 0),
    47: ("0",   1, 0,  list(range(10)),   0, 0, 0, 0),
    48: ("1",  16, 1,  [1],              0, 0, 0, 0),
    49: ("1",   8, 1,  [1],              0, 0, 0, 0),
    50: ("1",   4, 1,  [1],              0, 0, 0, 0),
    51: ("1",   2, 1,  [1],              0, 0, 0, 0),
    52: ("1",   2, 1,  [4],              0, 0, 0, 0),
    53: ("1",   2, 1,  [7],              0, 0, 0, 0),
    54: ("1",   1, 0,  [1],              0, 0, 0, 0),
    55: ("1",   1, 0,  [4],              0, 0, 0, 0),
    56: ("1",   1, 0,  [7],              0, 0, 0, 0),
    57: ("2",  16, 1,  [1],              0, 0, 0, 0),
    58: ("2",   8, 1,  [1],              0, 0, 0, 0),
    59: ("2",   4, 1,  [1],              0, 0, 0, 0),
    60: ("2",   2, 1,  [1],              0, 0, 0, 0),
    61: ("2",   1, 0,  [1],              0, 0, 0, 0),
    62: ("3",  16, 1,  [1],              0, 0, 0, 0),
    63: ("3",   8, 1,  [1],              0, 0, 0, 0),
    64: ("3",   4, 1,  [1],              0, 0, 0, 0),
    65: ("3",   2, 1,  [1],              0, 0, 0, 0),
    66: ("3",   1, 0,  [1],              0, 0, 0, 0),
}

# Table 6.3.3.2-3: Short preamble formats (FR1, paired spectrum / SUL)
# (Partial — commonly used configs for SCS 15 kHz / 30 kHz)
# format, x, y, subframe_list, starting_symbol, N_slot_RA, N_t_RA, N_dur_RA
PRACH_CONFIG_TABLE_SHORT_FR1_PAIRED = {
    # --- A1 ---
    0:   ("A1", 16, 1,  [4],               0,  1, 1, 6),
    1:   ("A1", 16, 1,  [9],               0,  1, 1, 6),
    2:   ("A1",  8, 1,  [4],               0,  1, 1, 6),
    3:   ("A1",  8, 1,  [9],               0,  1, 1, 6),
    4:   ("A1",  4, 1,  [4],               0,  1, 1, 6),
    5:   ("A1",  4, 1,  [9],               0,  1, 1, 6),
    6:   ("A1",  2, 1,  [4],               0,  1, 1, 6),
    7:   ("A1",  2, 1,  [9],               0,  1, 1, 6),
    8:   ("A1",  2, 1,  [4, 9],            0,  1, 1, 6),
    9:   ("A1",  1, 0,  [4],               0,  1, 1, 6),
    10:  ("A1",  1, 0,  [9],               0,  1, 1, 6),
    11:  ("A1",  1, 0,  [4, 9],            0,  1, 1, 6),
    12:  ("A1",  1, 0,  [1, 4, 7],         0,  1, 1, 6),
    13:  ("A1",  1, 0,  [1, 4, 7, 9],      0,  1, 1, 6),
    14:  ("A1",  1, 0,  list(range(0,10,2)),0,  1, 1, 6),
    15:  ("A1",  1, 0,  list(range(1,10,2)),0,  1, 1, 6),
    16:  ("A1",  1, 0,  list(range(10)),    0,  1, 1, 6),
    17:  ("A1",  1, 0,  [4],               7,  1, 1, 6),
    18:  ("A1",  1, 0,  [9],               7,  1, 1, 6),
    19:  ("A1",  1, 0,  [4, 9],            7,  1, 1, 6),
    # --- A2 ---
    20:  ("A2", 16, 1,  [9],               0,  1, 1, 4),
    21:  ("A2",  8, 1,  [9],               0,  1, 1, 4),
    22:  ("A2",  4, 1,  [9],               0,  1, 1, 4),
    23:  ("A2",  2, 1,  [9],               0,  1, 1, 4),
    24:  ("A2",  1, 0,  [9],               0,  1, 1, 4),
    25:  ("A2",  1, 0,  [4, 9],            0,  1, 1, 4),
    26:  ("A2",  1, 0,  [1, 4, 7, 9],      0,  1, 1, 4),
    27:  ("A2",  1, 0,  list(range(10)),    0,  1, 1, 4),
    # --- A3 ---
    28:  ("A3", 16, 1,  [9],               0,  1, 1, 6),
    29:  ("A3",  8, 1,  [9],               0,  1, 1, 6),
    30:  ("A3",  4, 1,  [9],               0,  1, 1, 6),
    31:  ("A3",  2, 1,  [9],               0,  1, 1, 6),
    32:  ("A3",  1, 0,  [9],               0,  1, 1, 6),
    33:  ("A3",  1, 0,  [4, 9],            0,  1, 1, 6),
    34:  ("A3",  1, 0,  [1, 4, 7, 9],      0,  1, 1, 6),
    35:  ("A3",  1, 0,  list(range(10)),    0,  1, 1, 6),
    # --- B1 ---
    36:  ("B1", 16, 1,  [4],               0,  1, 1, 4),
    37:  ("B1",  8, 1,  [4],               0,  1, 1, 4),
    38:  ("B1",  4, 1,  [4],               0,  1, 1, 4),
    39:  ("B1",  2, 1,  [4],               0,  1, 1, 4),
    40:  ("B1",  2, 1,  [4, 9],            0,  1, 1, 4),
    41:  ("B1",  1, 0,  [4],               0,  1, 1, 4),
    42:  ("B1",  1, 0,  [4, 9],            0,  1, 1, 4),
    43:  ("B1",  1, 0,  [1, 4, 7],         0,  1, 1, 4),
    44:  ("B1",  1, 0,  [1, 4, 7, 9],      0,  1, 1, 4),
    45:  ("B1",  1, 0,  list(range(10)),    0,  1, 1, 4),
    # --- B4 ---
    46:  ("B4", 16, 1,  [4],               0,  1, 1, 12),
    47:  ("B4",  8, 1,  [4],               0,  1, 1, 12),
    48:  ("B4",  4, 1,  [4],               0,  1, 1, 12),
    49:  ("B4",  2, 1,  [4],               0,  1, 1, 12),
    50:  ("B4",  1, 0,  [4],               0,  1, 1, 12),
    51:  ("B4",  1, 0,  [4, 9],            0,  1, 1, 12),
    52:  ("B4",  1, 0,  list(range(10)),    0,  1, 1, 12),
    # --- C0 ---
    53:  ("C0", 16, 1,  [9],               0,  1, 1, 4),
    54:  ("C0",  8, 1,  [9],               0,  1, 1, 4),
    55:  ("C0",  4, 1,  [9],               0,  1, 1, 4),
    56:  ("C0",  2, 1,  [9],               0,  1, 1, 4),
    57:  ("C0",  1, 0,  [9],               0,  1, 1, 4),
    58:  ("C0",  1, 0,  [4, 9],            0,  1, 1, 4),
    59:  ("C0",  1, 0,  list(range(10)),    0,  1, 1, 4),
    # --- C2 ---
    60:  ("C2", 16, 1,  [9],               0,  1, 1, 6),
    61:  ("C2",  8, 1,  [9],               0,  1, 1, 6),
    62:  ("C2",  4, 1,  [9],               0,  1, 1, 6),
    63:  ("C2",  2, 1,  [9],               0,  1, 1, 6),
    64:  ("C2",  1, 0,  [9],               0,  1, 1, 6),
    65:  ("C2",  1, 0,  [4, 9],            0,  1, 1, 6),
    66:  ("C2",  1, 0,  list(range(10)),    0,  1, 1, 6),
}


# ============================================================
# eAxC ID PARSER
# ============================================================
class EAxCID:
    def __init__(self, raw_value: int, mode: str = "standard",
                 custom_bits: tuple = (4, 4, 4, 4)):
        self.raw = raw_value
        bits = (4, 4, 4, 4) if mode == "standard" else custom_bits
        du_bits, bs_bits, cc_bits, ru_bits = bits
        total = du_bits + bs_bits + cc_bits + ru_bits
        shift = total - du_bits
        self.du_port_id     = (raw_value >> shift) & ((1 << du_bits) - 1)
        shift -= bs_bits
        self.band_sector_id = (raw_value >> shift) & ((1 << bs_bits) - 1)
        shift -= cc_bits
        self.cc_id          = (raw_value >> shift) & ((1 << cc_bits) - 1)
        shift -= ru_bits
        self.ru_port_id     = (raw_value >> shift) & ((1 << ru_bits) - 1)

    def __repr__(self):
        return (f"eAxC(0x{self.raw:04X} "
                f"DU={self.du_port_id} BS={self.band_sector_id} "
                f"CC={self.cc_id} RU={self.ru_port_id})")


# ============================================================
# BFP DECODER
# ============================================================
class BFPDecoder:
    IQ_BYTES_PER_PRB_WITH    = 1 + (NUM_SUBC_PER_PRB * 2 * IQ_WIDTH + 7) // 8  # 28
    IQ_BYTES_PER_PRB_WITHOUT =     (NUM_SUBC_PER_PRB * 2 * IQ_WIDTH + 7) // 8  # 27

    @staticmethod
    def prb_size(udcomp_present: bool) -> int:
        return (BFPDecoder.IQ_BYTES_PER_PRB_WITH if udcomp_present
                else BFPDecoder.IQ_BYTES_PER_PRB_WITHOUT)

    @staticmethod
    def decode_prb(prb_bytes: bytes, udcomp_present: bool = True):
        prb_sz = BFPDecoder.prb_size(udcomp_present)
        if len(prb_bytes) < prb_sz:
            raise ValueError(f"PRB data too short: {len(prb_bytes)} < {prb_sz}")
        if udcomp_present:
            exponent = prb_bytes[0] & 0x0F
            iq_bytes = prb_bytes[1:28]
        else:
            exponent = 0
            iq_bytes = prb_bytes[0:27]
        n_samples  = NUM_SUBC_PER_PRB * 2
        total_bits = n_samples * IQ_WIDTH
        bits     = int.from_bytes(iq_bytes, byteorder='big')
        mask     = (1 << IQ_WIDTH) - 1
        sign_bit = 1 << (IQ_WIDTH - 1)
        raw_i = np.empty(NUM_SUBC_PER_PRB, dtype=np.int32)
        raw_q = np.empty(NUM_SUBC_PER_PRB, dtype=np.int32)
        for k in range(NUM_SUBC_PER_PRB):
            i_val = (bits >> (total_bits - IQ_WIDTH * (2 * k + 1))) & mask
            q_val = (bits >> (total_bits - IQ_WIDTH * (2 * k + 2))) & mask
            if i_val & sign_bit: i_val -= (1 << IQ_WIDTH)
            if q_val & sign_bit: q_val -= (1 << IQ_WIDTH)
            raw_i[k] = i_val
            raw_q[k] = q_val
        scale      = float(1 << exponent)
        iq_complex = (raw_i * scale + 1j * raw_q * scale).astype(np.complex64)
        return iq_complex, raw_i, raw_q, exponent

    @staticmethod
    def calc_power_dbfs(iq_complex: np.ndarray, fs_offset: int = 0) -> float:
        iq = iq_complex.astype(np.complex128)
        power_per_sc = iq.real ** 2 + iq.imag ** 2
        active = power_per_sc[power_per_sc > 0]
        if len(active) == 0:
            return -np.inf
        power = np.mean(active)
        ref   = REF_POWER_BASE * (2.0 ** (-fs_offset))
        return 10.0 * np.log10(power / ref)


# ============================================================
# PARSED PACKET STRUCTURES
# ============================================================
class PrachCplaneInfo:
    """C-Plane Section Type 3 information."""
    def __init__(self):
        self.frame_num       = 0    # pcap frame number
        self.data_direction  = -1
        self.filter_index    = 0
        self.frame_id        = 0
        self.subframe_id     = 0
        self.slot_id         = 0
        self.start_symbol_id = 0
        self.eaxc_id         = None
        self.seq_id          = 0
        # Section Type 3 specific
        self.section_id      = 0
        self.start_prbc      = 0
        self.num_prbc        = 0
        self.re_mask         = 0xFFF
        self.num_symbol      = 0
        self.beam_id         = 0
        self.time_offset     = 0
        self.frame_structure = 0    # fftSize[7:4] | scs[3:0]
        self.cp_length       = 0
        self.fft_size        = 0
        self.scs_index       = 0
        self.ud_iq_width     = 0
        self.ud_comp_meth    = 0
        self.freq_offset     = 0    # 24-bit frequency offset


class PrachUplaneData:
    """U-Plane PRACH IQ data."""
    def __init__(self):
        self.frame_num       = 0
        self.data_direction  = -1
        self.filter_index    = 0
        self.frame_id        = 0
        self.subframe_id     = 0
        self.slot_id         = 0
        self.start_symbol_id = 0
        self.eaxc_id         = None
        self.seq_id          = 0
        self.start_prbc      = 0
        self.num_prbc        = 0
        self.iq_complex      = None   # np.ndarray complex64
        self.power_dbfs      = -np.inf
        self.exponents       = []     # list of exponents per PRB


# ============================================================
# PACKET PARSER
# ============================================================
class PrachParser:
    """
    Parse O-RAN packets for PRACH analysis.
    Handles both C-Plane (Section Type 3) and U-Plane (filterIndex=1).
    """
    def __init__(self, eaxc_mode="standard", eaxc_custom_bits=(4, 4, 4, 4),
                 udcomp_present=True, prach_filter_index=1):
        self.eaxc_mode        = eaxc_mode
        self.eaxc_custom_bits = eaxc_custom_bits
        self.udcomp_present   = udcomp_present
        self.prach_filter_idx = prach_filter_index

    def parse_cplane(self, payload: bytes, frame_num: int):
        """
        Parse C-Plane (eCPRI msgType=0x02) for Section Type 3.
        Returns PrachCplaneInfo or None.

        C-Plane O-RAN payload layout (after eCPRI header):
          [0:1]  eAxC ID (16 bit)
          [2]    seqId
          [3]    E(1) | subSeqId(7)
          --- Radio application header ---
          [4]    dataDirection(1) | payloadVersion(3) | filterIndex(4)
          [5]    frameId
          [6]    subframeId(4) | slotId[5:2](4)
          [7]    slotId[1:0](2) | startSymbolId(6)
          --- C-Plane specific ---
          [8]    numberOfSections (not always present in all implementations)
                 OR sectionType directly
          ...depends on implementation...

        Many vendor implementations have:
          [8]    sectionType
          [9..N] type-specific header + sections
        """
        if len(payload) < 12:
            return None

        info = PrachCplaneInfo()
        info.frame_num = frame_num

        eaxc_raw    = struct.unpack_from(">H", payload, 0)[0]
        info.eaxc_id = EAxCID(eaxc_raw, self.eaxc_mode, self.eaxc_custom_bits)
        info.seq_id  = payload[2]

        # Radio application header
        app0                  = payload[4]
        info.data_direction   = (app0 >> 7) & 0x1
        pv                    = (app0 >> 4) & 0x7
        info.filter_index     = app0 & 0x0F
        info.frame_id         = payload[5]
        info.subframe_id      = (payload[6] >> 4) & 0x0F
        info.slot_id          = ((payload[6] & 0x0F) << 2) | ((payload[7] >> 6) & 0x03)
        info.start_symbol_id  = payload[7] & 0x3F

        # --- Try two common C-Plane layouts ---
        # Layout A: [8]=numberOfSections, [9]=sectionType, [10..]=type-specific
        # Layout B: [8]=sectionType, [9..]=type-specific (no numberOfSections byte)
        # We try Layout A first; if sectionType != 3, try Layout B

        section_type = -1
        sec_hdr_start = 0

        if len(payload) > 9:
            # Layout A
            candidate_a = payload[9]
            candidate_b = payload[8]

            if candidate_a == SECTION_TYPE_3:
                section_type = SECTION_TYPE_3
                sec_hdr_start = 10
            elif candidate_b == SECTION_TYPE_3:
                section_type = SECTION_TYPE_3
                sec_hdr_start = 9
            else:
                # Not a Section Type 3 packet
                return None

        if section_type != SECTION_TYPE_3:
            return None

        # --- Parse Section Type 3 specific header ---
        # After sectionType byte, Section Type 3 has:
        #   udCompHdr (1 byte): udIqWidth[7:4] | udCompMeth[3:0]
        #   timeOffset (2 bytes)
        #   frameStructure (1 byte): fftSize[7:4] | scs[3:0]
        #   cpLength (2 bytes)
        #   reserved (1 byte)
        # Total: 7 bytes
        offset = sec_hdr_start
        if len(payload) < offset + 7:
            return None

        ud_comp_hdr          = payload[offset]
        info.ud_iq_width     = (ud_comp_hdr >> 4) & 0x0F
        info.ud_comp_meth    = ud_comp_hdr & 0x0F
        offset += 1

        info.time_offset     = struct.unpack_from(">H", payload, offset)[0]
        offset += 2

        info.frame_structure = payload[offset]
        info.fft_size        = (payload[offset] >> 4) & 0x0F
        info.scs_index       = payload[offset] & 0x0F
        offset += 1

        info.cp_length       = struct.unpack_from(">H", payload, offset)[0]
        offset += 2

        # reserved
        offset += 1

        # --- Parse section body ---
        if len(payload) >= offset + 8:
            word24          = (payload[offset] << 16) | (payload[offset+1] << 8) | payload[offset+2]
            info.section_id = (word24 >> 12) & 0xFFF
            rb              = (word24 >> 11) & 0x1
            sym_inc         = (word24 >> 10) & 0x1
            info.start_prbc = word24 & 0x3FF
            info.num_prbc   = payload[offset+3] or 256
            offset += 4

            if len(payload) >= offset + 4:
                b4 = payload[offset]
                b5 = payload[offset+1]
                info.re_mask    = ((b4 << 4) | (b5 >> 4)) & 0xFFF
                info.num_symbol = b5 & 0x0F
                b6 = payload[offset+2]
                b7 = payload[offset+3]
                ef = (b6 >> 7) & 0x1
                info.beam_id    = ((b6 & 0x7F) << 8) | b7
                offset += 4

            # frequencyOffset (24 bits) — Section Type 3 specific field in section
            if len(payload) >= offset + 3:
                info.freq_offset = ((payload[offset] << 16) |
                                    (payload[offset+1] << 8) |
                                    payload[offset+2])
                # signed 24-bit
                if info.freq_offset & 0x800000:
                    info.freq_offset -= 0x1000000

        return info

    def parse_uplane_prach(self, payload: bytes, frame_num: int,
                           fs_offset: int = 0):
        """
        Parse U-Plane packet and extract PRACH IQ data.
        Detection: filterIndex == prach_filter_idx
        Returns PrachUplaneData or None.
        """
        if len(payload) < 8:
            return None

        data = PrachUplaneData()
        data.frame_num = frame_num

        eaxc_raw    = struct.unpack_from(">H", payload, 0)[0]
        data.eaxc_id = EAxCID(eaxc_raw, self.eaxc_mode, self.eaxc_custom_bits)
        data.seq_id  = payload[2]

        app0                 = payload[4]
        data.data_direction  = (app0 >> 7) & 0x1
        data.filter_index    = app0 & 0x0F
        data.frame_id        = payload[5]
        data.subframe_id     = (payload[6] >> 4) & 0x0F
        data.slot_id         = ((payload[6] & 0x0F) << 2) | ((payload[7] >> 6) & 0x03)
        data.start_symbol_id = payload[7] & 0x3F

        # Only process PRACH filter index
        if data.filter_index != self.prach_filter_idx:
            return None

        # Parse section header (4 bytes minimum)
        prb_sz = BFPDecoder.prb_size(self.udcomp_present)
        offset = 8
        if offset + 4 > len(payload):
            return None

        word24          = (payload[offset] << 16) | (payload[offset+1] << 8) | payload[offset+2]
        data.section_id = (word24 >> 12) & 0xFFF
        data.start_prbc = word24 & 0x3FF
        data.num_prbc   = payload[offset+3] or 256
        offset += 4

        # Check for 8-byte section header
        # Heuristic: if remaining bytes suggest 8-byte header, skip 4 more
        remaining = len(payload) - offset
        expected_iq_4 = data.num_prbc * prb_sz
        expected_iq_8 = data.num_prbc * prb_sz
        if remaining >= expected_iq_8 + 4 and remaining != expected_iq_4:
            offset += 4  # skip reMask, numSymbol, ef, beamId

        # Decode PRBs
        all_iq   = []
        exp_list = []
        for _ in range(data.num_prbc):
            if offset + prb_sz > len(payload):
                break
            try:
                iq, ri, rq, exp = BFPDecoder.decode_prb(
                    payload[offset:offset + prb_sz],
                    udcomp_present=self.udcomp_present)
                all_iq.append(iq)
                exp_list.append(exp)
            except Exception:
                pass
            offset += prb_sz

        if all_iq:
            data.iq_complex = np.concatenate(all_iq)
            data.power_dbfs = BFPDecoder.calc_power_dbfs(data.iq_complex,
                                                          fs_offset=fs_offset)
            data.exponents = exp_list

        return data


# ============================================================
# ETHERNET FRAME HELPERS
# ============================================================
def _find_ecpri_payload(raw: bytes):
    """Walk raw Ethernet frame to find eCPRI payload (handles VLAN)."""
    if len(raw) < 14:
        return None, -1
    ethertype = struct.unpack_from(">H", raw, 12)[0]
    offset = 14
    while ethertype in (0x8100, 0x88A8, 0x9100):
        if offset + 4 > len(raw):
            return None, -1
        ethertype = struct.unpack_from(">H", raw, offset + 2)[0]
        offset += 4
    if ethertype != ECPRI_ETHERTYPE:
        return None, -1
    if offset + 4 > len(raw):
        return None, -1
    ecpri_msg_type = raw[offset + 1]
    return raw[offset:], ecpri_msg_type


# ============================================================
# ANALYSIS RESULT
# ============================================================
class PrachAnalysisResult:
    def __init__(self):
        self.cplane_list    = []   # list of PrachCplaneInfo
        self.uplane_list    = []   # list of PrachUplaneData
        self.total_ecpri    = 0
        self.cplane_count   = 0
        self.uplane_iq_count = 0
        self.error_count    = 0
        self.debug_lines    = []
        self.all_msg_types  = defaultdict(int)  # msgType -> count
        self.all_filter_indices = defaultdict(int)  # filterIndex -> count


# ============================================================
# PRACH TIMING VALIDATOR
# ============================================================
class PrachTimingValidator:
    """
    Validate observed PRACH occasions against expected NR configuration.
    """
    def __init__(self, config_index: int, table_type: str = "long",
                 scs_khz: int = 30):
        self.config_index = config_index
        self.table_type   = table_type
        self.scs_khz      = scs_khz
        self.slots_per_sf  = 1 if scs_khz == 15 else 2
        self.config_entry = None

        if table_type == "long" and config_index in PRACH_CONFIG_TABLE_LONG:
            self.config_entry = PRACH_CONFIG_TABLE_LONG[config_index]
        elif table_type == "short" and config_index in PRACH_CONFIG_TABLE_SHORT_FR1_PAIRED:
            self.config_entry = PRACH_CONFIG_TABLE_SHORT_FR1_PAIRED[config_index]

    def get_config_description(self):
        if self.config_entry is None:
            return f"Config index {self.config_index} not found in {self.table_type} table"
        fmt, x, y, sf_list, sym, n_slot, n_t, n_dur = self.config_entry
        return (f"Format={fmt}  SFN mod {x}={y}  "
                f"SF={sf_list}  startSym={sym}  "
                f"N_slot={n_slot}  N_t={n_t}  N_dur={n_dur}")

    def expected_occasions(self, frame_range: tuple):
        """
        Generate list of expected PRACH occasions (frame, subframe, slot, symbol).
        frame_range: (min_frame, max_frame) observed in pcap.
        """
        if self.config_entry is None:
            return []
        fmt, x, y, sf_list, start_sym, n_slot_ra, n_t_ra, n_dur_ra = self.config_entry

        occasions = []
        f_min, f_max = frame_range
        for frame in range(f_min, f_max + 1):
            if x > 0 and (frame % x) != y:
                continue
            for sf in sf_list:
                for slot_offset in range(self.slots_per_sf):
                    slot = slot_offset
                    occasions.append((frame, sf, slot, start_sym))
                    # Multiple occasions per slot
                    if n_t_ra > 1 and n_dur_ra > 0:
                        for t in range(1, n_t_ra):
                            sym = start_sym + t * n_dur_ra
                            if sym < 14:
                                occasions.append((frame, sf, slot, sym))
        return occasions

    def validate(self, observed_occasions):
        """
        Compare observed occasions against expected.
        observed_occasions: list of (frame, subframe, slot, symbol)
        Returns: (matched, missing, unexpected)
        """
        if self.config_entry is None:
            return [], [], list(observed_occasions)

        obs_set = set(observed_occasions)
        if not obs_set:
            return [], [], []

        frames = [o[0] for o in obs_set]
        frame_range = (min(frames), max(frames))
        expected = self.expected_occasions(frame_range)
        exp_set  = set(expected)

        matched    = sorted(obs_set & exp_set)
        missing    = sorted(exp_set - obs_set)
        unexpected = sorted(obs_set - exp_set)

        return matched, missing, unexpected


# ============================================================
# PCAP PROCESSOR
# ============================================================
def process_prach_pcap(filepath, frame_start, frame_end, parser,
                       progress_cb=None, cancel_flag=None,
                       debug_mode=False, debug_max=DEBUG_MAX_PACKETS,
                       fs_offset=0) -> PrachAnalysisResult:

    result      = PrachAnalysisResult()
    frame_num   = 0
    debug_count = 0

    with PcapReader(filepath) as pcap:
        for raw_pkt in pcap:
            frame_num += 1
            if cancel_flag and cancel_flag[0]:
                break
            if frame_num < frame_start:
                continue
            if frame_end > 0 and frame_num > frame_end:
                break
            if progress_cb and (frame_num % 500 == 0):
                progress_cb(frame_num)

            raw     = bytes(raw_pkt)
            payload, ecpri_msg_type = _find_ecpri_payload(raw)

            if payload is None:
                continue

            if len(payload) < 4:
                continue

            # Track all eCPRI message types
            result.all_msg_types[ecpri_msg_type] += 1
            result.total_ecpri += 1

            # ---- C-Plane (Section Type 3) ----
            if ecpri_msg_type == ECPRI_MSG_RT_CTRL:
                result.cplane_count += 1
                oran_payload = payload[4:]  # skip eCPRI header
                info = parser.parse_cplane(oran_payload, frame_num)
                if info is not None:
                    result.cplane_list.append(info)
                    if debug_mode and debug_count < debug_max:
                        result.debug_lines.append(
                            f"[Frame {frame_num:6d}] C-Plane SecType3  "
                            f"dirBit={info.data_direction}  "
                            f"{info.eaxc_id}  "
                            f"Frm={info.frame_id} SF={info.subframe_id} "
                            f"Slot={info.slot_id} Sym={info.start_symbol_id}  "
                            f"filterIdx={info.filter_index}  "
                            f"startPRBC={info.start_prbc} numPRBC={info.num_prbc}  "
                            f"timeOffset={info.time_offset}  "
                            f"fftSz={info.fft_size} scsIdx={info.scs_index}  "
                            f"cpLen={info.cp_length}  "
                            f"udIqW={info.ud_iq_width} udCompM={info.ud_comp_meth}  "
                            f"freqOffset={info.freq_offset}  "
                            f"beamId={info.beam_id}"
                        )
                        debug_count += 1

            # ---- U-Plane ----
            elif ecpri_msg_type == ECPRI_MSG_IQ_DATA:
                oran_payload = payload[4:]  # skip eCPRI header

                # Track filterIndex from U-Plane
                if len(oran_payload) >= 5:
                    fi = oran_payload[4] & 0x0F
                    result.all_filter_indices[fi] += 1

                data = parser.parse_uplane_prach(oran_payload, frame_num,
                                                  fs_offset=fs_offset)
                if data is not None:
                    result.uplane_iq_count += 1
                    result.uplane_list.append(data)
                    if debug_mode and debug_count < debug_max:
                        exp_str = ""
                        if data.exponents:
                            exp_str = f"exp=[{min(data.exponents)}~{max(data.exponents)}]"
                        result.debug_lines.append(
                            f"[Frame {frame_num:6d}] U-Plane PRACH  "
                            f"dirBit={data.data_direction}  "
                            f"{data.eaxc_id}  "
                            f"Frm={data.frame_id} SF={data.subframe_id} "
                            f"Slot={data.slot_id} Sym={data.start_symbol_id}  "
                            f"filterIdx={data.filter_index}  "
                            f"startPRBC={data.start_prbc} numPRBC={data.num_prbc}  "
                            f"dBFS={data.power_dbfs:+.2f}  {exp_str}  "
                            f"IQ_samples={len(data.iq_complex) if data.iq_complex is not None else 0}"
                        )
                        debug_count += 1

    return result


# ============================================================
# TIMING UTILITY
# ============================================================
def timing_to_slot_index(frame, subframe, slot, scs_khz):
    slots_per_sf    = 1 if scs_khz == 15 else 2
    slots_per_frame = 10 * slots_per_sf
    return frame * slots_per_frame + subframe * slots_per_sf + slot


# ============================================================
# GUI APPLICATION
# ============================================================
class App(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("O-RAN PRACH Analyzer  v1.0")
        self.geometry("1350x900")
        self.minsize(1000, 700)
        self.configure(bg="#2b2b2b")

        # Control variables
        self.filepath         = tk.StringVar()
        self.frame_start      = tk.IntVar(value=1)
        self.frame_end        = tk.IntVar(value=-1)
        self.scs_khz          = tk.IntVar(value=30)
        self.fs_offset        = tk.IntVar(value=0)
        self.prach_filter_idx = tk.IntVar(value=1)

        # PRACH config
        self.prach_table_type   = tk.StringVar(value="long")
        self.prach_config_index = tk.IntVar(value=27)

        # eAxC
        self.eaxc_mode        = tk.StringVar(value="standard")
        self.custom_du_bits   = tk.IntVar(value=4)
        self.custom_bs_bits   = tk.IntVar(value=4)
        self.custom_cc_bits   = tk.IntVar(value=4)
        self.custom_ru_bits   = tk.IntVar(value=4)

        self.udcomp_present   = tk.BooleanVar(value=True)
        self.debug_mode       = tk.BooleanVar(value=True)
        self.debug_max_var    = tk.IntVar(value=100)

        self.result           = None
        self._cancel_flag     = [False]
        self._worker_thread   = None

        self._build_menu()
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # --------------------------------------------------------
    # Menu
    # --------------------------------------------------------
    def _build_menu(self):
        mb = tk.Menu(self)
        fm = tk.Menu(mb, tearoff=0)
        fm.add_command(label="Open pcap...",     command=self._browse_pcap)
        fm.add_separator()
        fm.add_command(label="Save Graph (PNG)", command=lambda: self._save_graph("png"))
        fm.add_command(label="Save Graph (PDF)", command=lambda: self._save_graph("pdf"))
        fm.add_separator()
        fm.add_command(label="Export CSV",       command=self._export_csv)
        fm.add_separator()
        fm.add_command(label="Exit",             command=self._on_close)
        mb.add_cascade(label="File", menu=fm)
        self.configure(menu=mb)

    # --------------------------------------------------------
    # Layout
    # --------------------------------------------------------
    def _build_ui(self):
        self.left = tk.Frame(self, bg="#3c3f41", width=310)
        self.left.pack(side=tk.LEFT, fill=tk.Y)
        self.left.pack_propagate(False)

        self.right = tk.Frame(self, bg="#2b2b2b")
        self.right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._build_controls(self.left)
        self._build_graphs(self.right)

    # --------------------------------------------------------
    # Control panel helpers
    # --------------------------------------------------------
    def _lf(self, parent, title):
        f = tk.LabelFrame(parent, text=title, fg="#a9b7c6",
                          bg="#3c3f41", font=("Consolas", 9, "bold"),
                          padx=6, pady=4)
        f.pack(fill=tk.X, padx=8, pady=3)
        return f

    def _row_label_entry(self, parent, label, var, row, width=9):
        tk.Label(parent, text=label, bg="#3c3f41", fg="#a9b7c6",
                 width=14, anchor="w",
                 font=("Consolas", 8)).grid(row=row, column=0, sticky="w", pady=1)
        tk.Entry(parent, textvariable=var, bg="#4c5052", fg="white",
                 font=("Consolas", 9), width=width,
                 justify="center").grid(row=row, column=1, sticky="w")

    # --------------------------------------------------------
    # Controls
    # --------------------------------------------------------
    def _build_controls(self, parent):
        # --- File ---
        ff = self._lf(parent, "Input File")
        tk.Entry(ff, textvariable=self.filepath, bg="#4c5052",
                 fg="white", width=22,
                 font=("Consolas", 9)).pack(side=tk.LEFT)
        tk.Button(ff, text="...", command=self._browse_pcap,
                  bg="#555", fg="white", width=3).pack(side=tk.LEFT, padx=2)

        # --- Frame Range ---
        rf  = self._lf(parent, "Frame Range")
        row = tk.Frame(rf, bg="#3c3f41")
        row.pack(fill=tk.X)
        for r, lbl, var in [(0, "Start:",        self.frame_start),
                             (1, "End (-1=all):", self.frame_end)]:
            tk.Label(row, text=lbl, bg="#3c3f41", fg="#a9b7c6",
                     width=14, anchor="w").grid(row=r, column=0, sticky="w", pady=1)
            tk.Spinbox(row, from_=-1, to=9999999, textvariable=var,
                       width=9, bg="#4c5052",
                       fg="white").grid(row=r, column=1, sticky="w")

        # --- PRACH Detection ---
        pd = self._lf(parent, "PRACH Detection")
        row2 = tk.Frame(pd, bg="#3c3f41")
        row2.pack(fill=tk.X)
        tk.Label(row2, text="U-Plane filterIdx:", bg="#3c3f41", fg="#a9b7c6",
                 width=14, anchor="w",
                 font=("Consolas", 8)).grid(row=0, column=0, sticky="w")
        tk.Spinbox(row2, from_=0, to=15, textvariable=self.prach_filter_idx,
                   width=4, bg="#4c5052", fg="white").grid(row=0, column=1, sticky="w")
        tk.Label(row2, text="1=PRACH (O-RAN std)",
                 bg="#3c3f41", fg="#6A9955",
                 font=("Consolas", 7)).grid(row=1, column=0, columnspan=2, sticky="w")

        tk.Label(row2, text="SCS (kHz):", bg="#3c3f41", fg="#a9b7c6",
                 width=14, anchor="w",
                 font=("Consolas", 8)).grid(row=2, column=0, sticky="w", pady=(4,0))
        ttk.Combobox(row2, textvariable=self.scs_khz,
                     values=[15, 30], width=5,
                     state="readonly").grid(row=2, column=1, sticky="w", pady=(4,0))

        tk.Label(row2, text="fs-offset:", bg="#3c3f41", fg="#a9b7c6",
                 width=14, anchor="w",
                 font=("Consolas", 8)).grid(row=3, column=0, sticky="w", pady=2)
        tk.Spinbox(row2, from_=0, to=16, textvariable=self.fs_offset,
                   width=4, bg="#4c5052", fg="white").grid(row=3, column=1, sticky="w")

        # --- PRACH Timing Config ---
        tc = self._lf(parent, "PRACH Config (Timing Validation)")
        row3 = tk.Frame(tc, bg="#3c3f41")
        row3.pack(fill=tk.X)
        tk.Label(row3, text="Table:", bg="#3c3f41", fg="#a9b7c6",
                 width=14, anchor="w",
                 font=("Consolas", 8)).grid(row=0, column=0, sticky="w")
        ttk.Combobox(row3, textvariable=self.prach_table_type,
                     values=["long", "short"], width=7,
                     state="readonly").grid(row=0, column=1, sticky="w")
        tk.Label(row3, text="long=Fmt 0/1/2/3  short=A1..C2",
                 bg="#3c3f41", fg="#6A9955",
                 font=("Consolas", 7)).grid(row=1, column=0, columnspan=2, sticky="w")

        tk.Label(row3, text="Config index:", bg="#3c3f41", fg="#a9b7c6",
                 width=14, anchor="w",
                 font=("Consolas", 8)).grid(row=2, column=0, sticky="w", pady=2)
        tk.Spinbox(row3, from_=0, to=255, textvariable=self.prach_config_index,
                   width=5, bg="#4c5052", fg="white").grid(row=2, column=1, sticky="w")
        tk.Label(row3, text="TS38.211 Table 6.3.3.2-2/3",
                 bg="#3c3f41", fg="#6A9955",
                 font=("Consolas", 7)).grid(row=3, column=0, columnspan=2, sticky="w")

        # --- Advanced ---
        adv  = self._lf(parent, "Advanced (Parser)")
        row4 = tk.Frame(adv, bg="#3c3f41")
        row4.pack(fill=tk.X)
        tk.Label(row4, text="eAxC mode:", bg="#3c3f41", fg="#a9b7c6",
                 width=14, anchor="w",
                 font=("Consolas", 8)).grid(row=0, column=0, sticky="w")
        mc = ttk.Combobox(row4, textvariable=self.eaxc_mode,
                          values=["standard", "custom"],
                          width=8, state="readonly")
        mc.grid(row=0, column=1, sticky="w")
        mc.bind("<<ComboboxSelected>>", self._on_eaxc_mode_change)

        self._custom_frame = tk.Frame(adv, bg="#3c3f41")
        self._custom_frame.pack(fill=tk.X)
        for i, (lbl, var) in enumerate([("DU bits", self.custom_du_bits),
                                         ("BS bits", self.custom_bs_bits),
                                         ("CC bits", self.custom_cc_bits),
                                         ("RU bits", self.custom_ru_bits)]):
            tk.Label(self._custom_frame, text=lbl, bg="#3c3f41", fg="#a9b7c6",
                     width=10, anchor="w",
                     font=("Consolas", 8)).grid(row=i, column=0, sticky="w")
            tk.Spinbox(self._custom_frame, from_=1, to=12, textvariable=var,
                       width=4, bg="#4c5052",
                       fg="white").grid(row=i, column=1, sticky="w", pady=1)
        self._custom_frame.pack_forget()

        tk.Checkbutton(adv, text="udCompParam present (BFP 28B/PRB)",
                       variable=self.udcomp_present,
                       bg="#3c3f41", fg="#a9b7c6",
                       activebackground="#3c3f41", selectcolor="#555",
                       font=("Consolas", 8)).pack(anchor="w")

        # --- Debug ---
        dbg     = self._lf(parent, "Debug")
        dbg_row = tk.Frame(dbg, bg="#3c3f41")
        dbg_row.pack(fill=tk.X)
        tk.Checkbutton(dbg_row, text="Enable debug",
                       variable=self.debug_mode,
                       bg="#3c3f41", fg="#a9b7c6",
                       activebackground="#3c3f41", selectcolor="#555",
                       font=("Consolas", 9)).grid(row=0, column=0, columnspan=2, sticky="w")
        tk.Label(dbg_row, text="Max pkts:", bg="#3c3f41", fg="#a9b7c6",
                 width=9, anchor="w",
                 font=("Consolas", 8)).grid(row=1, column=0, sticky="w")
        tk.Spinbox(dbg_row, from_=1, to=1000, textvariable=self.debug_max_var,
                   width=5, bg="#4c5052", fg="white").grid(row=1, column=1, sticky="w")

        # --- Buttons ---
        tk.Button(parent, text="▶  Analyze PRACH",
                  command=self._start_analysis,
                  bg="#4CAF50", fg="white",
                  font=("Consolas", 11, "bold"),
                  relief=tk.FLAT, pady=6).pack(fill=tk.X, padx=8, pady=(6, 2))
        tk.Button(parent, text="■  Stop",
                  command=self._stop_analysis,
                  bg="#f44336", fg="white",
                  font=("Consolas", 10),
                  relief=tk.FLAT, pady=4).pack(fill=tk.X, padx=8)

        # --- Status ---
        self.status_var = tk.StringVar(value="Ready.")
        tk.Label(parent, textvariable=self.status_var,
                 bg="#3c3f41", fg="#6A9955", wraplength=290,
                 justify="left",
                 font=("Consolas", 8)).pack(padx=8, pady=2)

        self.progress = ttk.Progressbar(parent, mode='indeterminate')
        self.progress.pack(fill=tk.X, padx=8, pady=2)

        self.stats_var = tk.StringVar(value="")
        tk.Label(parent, textvariable=self.stats_var,
                 bg="#3c3f41", fg="#a9b7c6", wraplength=290,
                 justify="left",
                 font=("Consolas", 8)).pack(padx=8, pady=2)

    def _on_eaxc_mode_change(self, _=None):
        if self.eaxc_mode.get() == "custom":
            self._custom_frame.pack(fill=tk.X)
        else:
            self._custom_frame.pack_forget()

    # --------------------------------------------------------
    # Graph panel
    # --------------------------------------------------------
    def _build_graphs(self, parent):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook",     background="#2b2b2b")
        style.configure("TNotebook.Tab", background="#3c3f41", foreground="#a9b7c6")

        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # Tab: Timing Summary
        self.tab_timing = tk.Frame(self.notebook, bg="#2b2b2b")
        self.notebook.add(self.tab_timing, text="  Timing Validation  ")
        self._build_timing_tab(self.tab_timing)

        # Tab: Power
        self.tab_power = tk.Frame(self.notebook, bg="#2b2b2b")
        self.notebook.add(self.tab_power, text="  PRACH Power  ")
        self._build_power_tab(self.tab_power)

        # Tab: Constellation
        self.tab_const = tk.Frame(self.notebook, bg="#2b2b2b")
        self.notebook.add(self.tab_const, text="  Constellation  ")
        self._build_const_tab(self.tab_const)

        # Tab: C-Plane Summary
        self.tab_cplane = tk.Frame(self.notebook, bg="#2b2b2b")
        self.notebook.add(self.tab_cplane, text="  C-Plane SecType3  ")
        self._build_cplane_tab(self.tab_cplane)

        # Tab: Debug
        self.tab_debug = tk.Frame(self.notebook, bg="#2b2b2b")
        self.notebook.add(self.tab_debug, text="  Debug  ")
        self._build_debug_tab(self.tab_debug)

    def _build_timing_tab(self, parent):
        top = tk.Frame(parent, bg="#2b2b2b")
        top.pack(fill=tk.X, padx=8, pady=4)

        self.timing_config_label = tk.Label(top, text="PRACH Config: ---",
                                             fg="#61DAFB", bg="#2b2b2b",
                                             font=("Consolas", 10, "bold"))
        self.timing_config_label.pack(anchor="w")

        self.timing_summary_label = tk.Label(top, text="",
                                              fg="#a9b7c6", bg="#2b2b2b",
                                              font=("Consolas", 9))
        self.timing_summary_label.pack(anchor="w")

        # Timing validation text
        frame = tk.Frame(parent, bg="#2b2b2b")
        frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        xsb = tk.Scrollbar(frame, orient=tk.HORIZONTAL)
        ysb = tk.Scrollbar(frame, orient=tk.VERTICAL)
        self.timing_text = tk.Text(
            frame, bg="#1e1e1e", fg="#a9b7c6",
            font=("Consolas", 9), wrap=tk.NONE,
            insertbackground="white",
            xscrollcommand=xsb.set, yscrollcommand=ysb.set,
            state=tk.DISABLED
        )
        xsb.config(command=self.timing_text.xview)
        ysb.config(command=self.timing_text.yview)
        self.timing_text.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")

        # Tag colors
        self.timing_text.tag_configure("ok",      foreground="#98c379")
        self.timing_text.tag_configure("missing",  foreground="#e06c75")
        self.timing_text.tag_configure("unexpected", foreground="#e5c07b")
        self.timing_text.tag_configure("header",   foreground="#61DAFB")
        self.timing_text.tag_configure("section",  foreground="#c678dd")

    def _build_power_tab(self, parent):
        top = tk.Frame(parent, bg="#2b2b2b")
        top.pack(fill=tk.X, padx=8, pady=4)
        tk.Label(top, text="PRACH Average Power:",
                 fg="#a9b7c6", bg="#2b2b2b",
                 font=("Consolas", 11)).pack(side=tk.LEFT)
        self.prach_dbfs_label = tk.Label(top, text="---",
                                          fg="#61DAFB", bg="#2b2b2b",
                                          font=("Consolas", 22, "bold"))
        self.prach_dbfs_label.pack(side=tk.LEFT, padx=12)
        self.prach_count_label = tk.Label(top, text="",
                                           fg="#98c379", bg="#2b2b2b",
                                           font=("Consolas", 10))
        self.prach_count_label.pack(side=tk.LEFT, padx=8)

        self.fig_power = Figure(figsize=(7, 4), dpi=96, facecolor="#1e1e1e")
        self.ax_power  = self.fig_power.add_subplot(111)
        self._style_ax(self.ax_power, "Slot Index", "dBFS",
                       "PRACH Power vs. Time")
        self.fig_power.tight_layout(pad=1.5)

        cp = FigureCanvasTkAgg(self.fig_power, parent)
        cp.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=4)
        NavigationToolbar2Tk(cp, parent).update()
        self.canvas_power = cp

    def _build_const_tab(self, parent):
        self.fig_const = Figure(figsize=(5, 5), dpi=96, facecolor="#1e1e1e")
        self.ax_const  = self.fig_const.add_subplot(111)
        self._style_ax(self.ax_const, "I", "Q", "PRACH Constellation")
        self.fig_const.tight_layout(pad=1.5)

        cc = FigureCanvasTkAgg(self.fig_const, parent)
        cc.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=4)
        NavigationToolbar2Tk(cc, parent).update()
        self.canvas_const = cc

    def _build_cplane_tab(self, parent):
        frame = tk.Frame(parent, bg="#2b2b2b")
        frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        xsb = tk.Scrollbar(frame, orient=tk.HORIZONTAL)
        ysb = tk.Scrollbar(frame, orient=tk.VERTICAL)
        self.cplane_text = tk.Text(
            frame, bg="#1e1e1e", fg="#a9b7c6",
            font=("Consolas", 9), wrap=tk.NONE,
            insertbackground="white",
            xscrollcommand=xsb.set, yscrollcommand=ysb.set,
            state=tk.DISABLED
        )
        xsb.config(command=self.cplane_text.xview)
        ysb.config(command=self.cplane_text.yview)
        self.cplane_text.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")

    def _build_debug_tab(self, parent):
        ctrl = tk.Frame(parent, bg="#2b2b2b")
        ctrl.pack(fill=tk.X, padx=8, pady=4)
        tk.Label(ctrl, text="PRACH packet debug log",
                 fg="#a9b7c6", bg="#2b2b2b",
                 font=("Consolas", 9)).pack(side=tk.LEFT)
        tk.Button(ctrl, text="Clear", command=self._clear_debug,
                  bg="#555", fg="white",
                  font=("Consolas", 8), relief=tk.FLAT).pack(side=tk.RIGHT)

        frame = tk.Frame(parent, bg="#2b2b2b")
        frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        xsb = tk.Scrollbar(frame, orient=tk.HORIZONTAL)
        ysb = tk.Scrollbar(frame, orient=tk.VERTICAL)
        self.debug_text = tk.Text(
            frame, bg="#1e1e1e", fg="#98c379",
            font=("Consolas", 8), wrap=tk.NONE,
            insertbackground="white",
            xscrollcommand=xsb.set, yscrollcommand=ysb.set,
            state=tk.DISABLED
        )
        xsb.config(command=self.debug_text.xview)
        ysb.config(command=self.debug_text.yview)
        self.debug_text.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")

    def _style_ax(self, ax, xlabel, ylabel, title):
        ax.set_facecolor("#1e1e1e")
        ax.tick_params(colors="#a9b7c6", labelsize=8)
        for sp in ax.spines.values():
            sp.set_color("#555555")
        ax.xaxis.label.set_color("#a9b7c6")
        ax.yaxis.label.set_color("#a9b7c6")
        ax.title.set_color("#dcdcdc")
        ax.set_xlabel(xlabel, fontsize=8)
        ax.set_ylabel(ylabel, fontsize=8)
        ax.set_title(title, fontsize=9)

    # --------------------------------------------------------
    # Analysis
    # --------------------------------------------------------
    def _browse_pcap(self):
        path = filedialog.askopenfilename(
            title="Open pcap file",
            filetypes=[("pcap files", "*.pcap *.pcapng"), ("All files", "*.*")]
        )
        if path:
            self.filepath.set(path)

    def _start_analysis(self):
        fp = self.filepath.get().strip()
        if not fp or not os.path.isfile(fp):
            messagebox.showwarning("File not found",
                                   "Please select a valid pcap file.")
            return

        if self._worker_thread and self._worker_thread.is_alive():
            messagebox.showinfo("Busy", "Analysis running. Press Stop first.")
            return

        self._cancel_flag[0] = False
        self.result = None
        self.status_var.set("Analyzing PRACH...")
        self.progress.start(12)
        self.stats_var.set("")
        self.prach_dbfs_label.configure(text="---")
        self.prach_count_label.configure(text="")
        self._clear_debug()
        self._clear_text_widget(self.timing_text)
        self._clear_text_widget(self.cplane_text)

        mode   = self.eaxc_mode.get()
        custom = (self.custom_du_bits.get(), self.custom_bs_bits.get(),
                  self.custom_cc_bits.get(), self.custom_ru_bits.get())

        parser = PrachParser(
            eaxc_mode=mode, eaxc_custom_bits=custom,
            udcomp_present=self.udcomp_present.get(),
            prach_filter_index=self.prach_filter_idx.get()
        )

        fs      = self.frame_start.get()
        fe      = self.frame_end.get()
        debug   = self.debug_mode.get()
        dbg_max = self.debug_max_var.get()
        fso     = self.fs_offset.get()

        def worker():
            try:
                res = process_prach_pcap(
                    fp, fs, fe, parser,
                    progress_cb=self._on_progress,
                    cancel_flag=self._cancel_flag,
                    debug_mode=debug,
                    debug_max=dbg_max,
                    fs_offset=fso,
                )
                self.result = res
                self.after(0, self._on_done)
            except Exception as e:
                tb = traceback.format_exc()
                self.after(0, lambda: self._on_error(str(e), tb))

        self._worker_thread = threading.Thread(target=worker, daemon=True)
        self._worker_thread.start()

    def _stop_analysis(self):
        self._cancel_flag[0] = True
        self.status_var.set("Stopping...")

    def _on_progress(self, frame_num):
        self.after(0, lambda: self.status_var.set(
            f"Processing frame {frame_num:,}..."))

    def _on_done(self):
        self.progress.stop()
        if self.result is None:
            self.status_var.set("No result.")
            return

        res = self.result
        scs = self.scs_khz.get()

        # --- Statistics ---
        msg_types_str = ", ".join(
            f"0x{mt:02X}:{cnt}" for mt, cnt in sorted(res.all_msg_types.items()))
        fi_str = ", ".join(
            f"{fi}:{cnt}" for fi, cnt in sorted(res.all_filter_indices.items()))

        self.stats_var.set(
            f"Total eCPRI: {res.total_ecpri:,}\n"
            f"  MsgTypes: {msg_types_str}\n"
            f"  C-Plane pkts: {res.cplane_count:,}\n"
            f"  Section Type 3: {len(res.cplane_list):,}\n"
            f"  U-Plane filterIdx: {fi_str}\n"
            f"  PRACH U-Plane IQ: {res.uplane_iq_count:,}"
        )

        # --- Power analysis ---
        if res.uplane_list:
            dbfs_vals = np.array([d.power_dbfs for d in res.uplane_list])
            finite    = dbfs_vals[np.isfinite(dbfs_vals)]
            avg_dbfs  = float(np.mean(finite)) if len(finite) > 0 else -np.inf

            self.prach_dbfs_label.configure(text=f"{avg_dbfs:+.2f} dB")
            color = ("#98c379" if abs(avg_dbfs) < 3.0
                     else "#e5c07b" if abs(avg_dbfs) < 10.0
                     else "#e06c75")
            self.prach_dbfs_label.configure(fg=color)
            self.prach_count_label.configure(
                text=f"{len(res.uplane_list)} PRACH occasions found")

            # Plot power
            self.notebook.select(self.tab_power)
            self.update_idletasks()
            self._plot_power(res.uplane_list, scs, avg_dbfs)

            # Plot constellation
            self.notebook.select(self.tab_const)
            self.update_idletasks()
            self._plot_constellation(res.uplane_list)
        else:
            self.prach_dbfs_label.configure(text="N/A", fg="#e06c75")
            self.prach_count_label.configure(
                text="No PRACH U-Plane IQ data found")

        # --- Timing validation ---
        self._do_timing_validation(res, scs)

        # --- C-Plane summary ---
        self._populate_cplane(res)

        # --- Debug ---
        self._populate_debug(res)

        # Switch to timing tab
        self.notebook.select(self.tab_timing)
        self.status_var.set("Done.")

    def _on_error(self, msg, tb):
        self.progress.stop()
        self.status_var.set(f"Error: {msg}")
        messagebox.showerror("Analysis Error", f"{msg}\n\n{tb[:1000]}")

    # --------------------------------------------------------
    # Timing Validation
    # --------------------------------------------------------
    def _do_timing_validation(self, res, scs):
        table_type   = self.prach_table_type.get()
        config_index = self.prach_config_index.get()

        validator = PrachTimingValidator(config_index, table_type, scs)

        self.timing_config_label.configure(
            text=f"PRACH Config Index {config_index} ({table_type}):  "
                 f"{validator.get_config_description()}")

        # Collect observed occasions from both C-Plane and U-Plane
        observed_cp = set()
        for info in res.cplane_list:
            observed_cp.add((info.frame_id, info.subframe_id,
                             info.slot_id, info.start_symbol_id))

        observed_up = set()
        for data in res.uplane_list:
            observed_up.add((data.frame_id, data.subframe_id,
                             data.slot_id, data.start_symbol_id))

        # Validate U-Plane PRACH
        all_observed = observed_cp | observed_up
        matched, missing, unexpected = validator.validate(all_observed)

        self._clear_text_widget(self.timing_text)
        tw = self.timing_text
        tw.configure(state=tk.NORMAL)

        # --- Summary ---
        tw.insert(tk.END, "═══ PRACH Timing Validation Summary ═══\n", "header")
        tw.insert(tk.END, f"  Config: {validator.get_config_description()}\n\n")

        tw.insert(tk.END, f"  Observed PRACH occasions:\n")
        tw.insert(tk.END, f"    C-Plane (SecType3):  {len(observed_cp)} unique (frame,sf,slot,sym)\n")
        tw.insert(tk.END, f"    U-Plane (filterIdx): {len(observed_up)} unique (frame,sf,slot,sym)\n")
        tw.insert(tk.END, f"    Combined:            {len(all_observed)} unique\n\n")

        if validator.config_entry is not None:
            tw.insert(tk.END, f"  ✓ Matched:    {len(matched)}\n", "ok")
            tw.insert(tk.END, f"  ✗ Missing:    {len(missing)}\n", "missing")
            tw.insert(tk.END, f"  ? Unexpected: {len(unexpected)}\n\n", "unexpected")

            # --- Observed occasion detail (C-Plane) ---
            if observed_cp:
                tw.insert(tk.END,
                          "═══ C-Plane Section Type 3 Occasions ═══\n", "section")
                tw.insert(tk.END,
                          f"  {'Frame':>5s}  {'SF':>2s}  {'Slot':>4s}  "
                          f"{'Sym':>3s}  {'startPRBC':>9s}  {'numPRBC':>7s}  "
                          f"{'timeOffset':>10s}  {'beamId':>6s}  {'eAxC':>12s}\n")
                tw.insert(tk.END, f"  {'─'*80}\n")
                for info in sorted(res.cplane_list,
                                    key=lambda i: (i.frame_id, i.subframe_id,
                                                   i.slot_id, i.start_symbol_id)):
                    occ = (info.frame_id, info.subframe_id,
                           info.slot_id, info.start_symbol_id)
                    tag = "ok" if occ in set(matched) else "unexpected"
                    tw.insert(tk.END,
                              f"  {info.frame_id:5d}  {info.subframe_id:2d}  "
                              f"{info.slot_id:4d}  {info.start_symbol_id:3d}  "
                              f"{info.start_prbc:9d}  {info.num_prbc:7d}  "
                              f"{info.time_offset:10d}  {info.beam_id:6d}  "
                              f"{info.eaxc_id}\n", tag)

            # --- Observed U-Plane detail ---
            if observed_up:
                tw.insert(tk.END,
                          "\n═══ U-Plane PRACH IQ Occasions ═══\n", "section")
                tw.insert(tk.END,
                          f"  {'Frame':>5s}  {'SF':>2s}  {'Slot':>4s}  "
                          f"{'Sym':>3s}  {'PRBs':>4s}  {'dBFS':>8s}  "
                          f"{'Exponents':>12s}  {'eAxC':>12s}\n")
                tw.insert(tk.END, f"  {'─'*80}\n")
                for data in sorted(res.uplane_list,
                                    key=lambda d: (d.frame_id, d.subframe_id,
                                                   d.slot_id, d.start_symbol_id)):
                    occ = (data.frame_id, data.subframe_id,
                           data.slot_id, data.start_symbol_id)
                    tag = "ok" if occ in set(matched) else "unexpected"
                    exp_str = ""
                    if data.exponents:
                        exp_str = f"[{min(data.exponents)}~{max(data.exponents)}]"
                    tw.insert(tk.END,
                              f"  {data.frame_id:5d}  {data.subframe_id:2d}  "
                              f"{data.slot_id:4d}  {data.start_symbol_id:3d}  "
                              f"{data.num_prbc:4d}  {data.power_dbfs:+8.2f}  "
                              f"{exp_str:>12s}  {data.eaxc_id}\n", tag)

            # --- Missing occasions ---
            if missing:
                tw.insert(tk.END,
                          "\n═══ Missing Expected Occasions ═══\n", "missing")
                tw.insert(tk.END,
                          f"  {'Frame':>5s}  {'SF':>2s}  {'Slot':>4s}  {'Sym':>3s}\n")
                tw.insert(tk.END, f"  {'─'*30}\n")
                for (frm, sf, sl, sym) in missing[:200]:
                    tw.insert(tk.END,
                              f"  {frm:5d}  {sf:2d}  {sl:4d}  {sym:3d}\n",
                              "missing")
                if len(missing) > 200:
                    tw.insert(tk.END,
                              f"  ... and {len(missing)-200} more\n", "missing")

            # --- Unexpected occasions ---
            if unexpected:
                tw.insert(tk.END,
                          "\n═══ Unexpected Occasions ═══\n", "unexpected")
                tw.insert(tk.END,
                          f"  {'Frame':>5s}  {'SF':>2s}  {'Slot':>4s}  {'Sym':>3s}\n")
                tw.insert(tk.END, f"  {'─'*30}\n")
                for (frm, sf, sl, sym) in unexpected[:200]:
                    tw.insert(tk.END,
                              f"  {frm:5d}  {sf:2d}  {sl:4d}  {sym:3d}\n",
                              "unexpected")
        else:
            tw.insert(tk.END,
                      "  Config index not found in table.\n"
                      "  Listing observed occasions only.\n\n", "unexpected")

            # List all observed
            tw.insert(tk.END, "═══ All Observed Occasions ═══\n", "section")
            for occ in sorted(all_observed):
                tw.insert(tk.END,
                          f"  Frame={occ[0]:3d}  SF={occ[1]}  "
                          f"Slot={occ[2]}  Sym={occ[3]}\n")

        # --- Periodicity analysis ---
        if len(all_observed) >= 2:
            tw.insert(tk.END, "\n═══ Periodicity Analysis ═══\n", "header")
            sorted_occ = sorted(all_observed)
            slot_indices = [timing_to_slot_index(o[0], o[1], o[2], scs)
                           for o in sorted_occ]
            if len(slot_indices) >= 2:
                diffs = np.diff(slot_indices)
                unique_diffs = np.unique(diffs)
                tw.insert(tk.END,
                          f"  Slot index range: {slot_indices[0]} ~ {slot_indices[-1]}\n"
                          f"  Inter-occasion gaps (slots): {unique_diffs.tolist()}\n")
                if len(unique_diffs) == 1:
                    tw.insert(tk.END,
                              f"  ✓ Consistent periodicity: every {unique_diffs[0]} slots\n",
                              "ok")
                    slots_per_frame = 10 * (1 if scs == 15 else 2)
                    period_frames = unique_diffs[0] / slots_per_frame
                    tw.insert(tk.END,
                              f"    = every {period_frames:.1f} frames "
                              f"({period_frames * 10:.0f} ms)\n", "ok")
                else:
                    tw.insert(tk.END,
                              f"  ⚠ Variable periodicity detected\n"
                              f"    Most common gap: {int(np.median(diffs))} slots\n",
                              "unexpected")

        tw.configure(state=tk.DISABLED)

    # --------------------------------------------------------
    # C-Plane summary
    # --------------------------------------------------------
    def _populate_cplane(self, res):
        tw = self.cplane_text
        tw.configure(state=tk.NORMAL)
        tw.delete("1.0", tk.END)

        if not res.cplane_list:
            tw.insert(tk.END, "No C-Plane Section Type 3 packets found.\n"
                              "  (eCPRI msgType=0x02 with sectionType=3)\n\n"
                              f"  Total C-Plane packets seen: {res.cplane_count}\n"
                              f"  eCPRI msgTypes: {dict(res.all_msg_types)}\n")
        else:
            tw.insert(tk.END,
                      f"═══ C-Plane Section Type 3 Summary ═══\n"
                      f"  Total: {len(res.cplane_list)} packets\n\n")

            # Group by unique configurations
            configs = defaultdict(list)
            for info in res.cplane_list:
                key = (info.data_direction, info.filter_index,
                       info.start_prbc, info.num_prbc,
                       info.fft_size, info.scs_index,
                       info.ud_iq_width, info.ud_comp_meth)
                configs[key].append(info)

            for key, items in configs.items():
                dd, fi, sprbc, nprbc, fft, scs_i, iqw, cm = key
                tw.insert(tk.END,
                          f"  ─── Configuration Group ({len(items)} pkts) ───\n"
                          f"    dirBit={dd}  filterIndex={fi}\n"
                          f"    startPRBC={sprbc}  numPRBC={nprbc}\n"
                          f"    fftSize={fft}  scsIndex={scs_i}\n"
                          f"    udIqWidth={iqw}  udCompMeth={cm}\n"
                          f"    Frames: {items[0].frame_id}..{items[-1].frame_id}\n"
                          f"    timeOffset range: "
                          f"{min(i.time_offset for i in items)}~"
                          f"{max(i.time_offset for i in items)}\n"
                          f"    cpLength range: "
                          f"{min(i.cp_length for i in items)}~"
                          f"{max(i.cp_length for i in items)}\n"
                          f"    beamId values: "
                          f"{sorted(set(i.beam_id for i in items))}\n\n")

        tw.configure(state=tk.DISABLED)

    # --------------------------------------------------------
    # Plots
    # --------------------------------------------------------
    def _plot_power(self, uplane_list, scs, avg_dbfs):
        ax = self.ax_power
        ax.cla()
        self._style_ax(ax, "Slot Index", "dBFS", "PRACH Power vs. Time")

        ax.axhline(0,        color="#e06c75", lw=1.2, ls="--", label="0 dBFS")
        ax.axhline(avg_dbfs, color="#61DAFB", lw=1.0, ls="-.",
                   label=f"avg {avg_dbfs:+.2f} dB")

        slots = np.array([timing_to_slot_index(d.frame_id, d.subframe_id,
                                                d.slot_id, scs)
                          for d in uplane_list])
        dbfs  = np.array([d.power_dbfs for d in uplane_list])

        ax.scatter(slots, dbfs, s=8, color="#61AFEF", alpha=0.8,
                   label=f"PRACH ({len(uplane_list)} occ)")
        ax.legend(facecolor="#2b2b2b", edgecolor="#555",
                  labelcolor="#a9b7c6", fontsize=8)
        try:
            self.fig_power.tight_layout(pad=1.5)
        except Exception:
            pass
        self.canvas_power.draw_idle()

    def _plot_constellation(self, uplane_list):
        ax = self.ax_const
        ax.cla()
        self._style_ax(ax, "I", "Q", "PRACH Constellation")

        all_iq_list = [d.iq_complex for d in uplane_list
                       if d.iq_complex is not None]
        if not all_iq_list:
            self.canvas_const.draw_idle()
            return

        all_iq = np.concatenate(all_iq_list)
        if len(all_iq) > 80000:
            idx    = np.random.choice(len(all_iq), 80000, replace=False)
            all_iq = all_iq[idx]

        if len(all_iq) > 0:
            ax.scatter(all_iq.real, all_iq.imag, s=1, color="#61AFEF", alpha=0.3)
            ax.axhline(0, color="#555", lw=0.5)
            ax.axvline(0, color="#555", lw=0.5)
            ax.set_aspect("equal", adjustable="box")

        try:
            self.fig_const.tight_layout(pad=1.5)
        except Exception:
            pass
        self.canvas_const.draw_idle()

    # --------------------------------------------------------
    # Debug
    # --------------------------------------------------------
    def _populate_debug(self, res):
        if not res.debug_lines:
            return
        tw = self.debug_text
        tw.configure(state=tk.NORMAL)
        tw.insert(tk.END,
                  f"=== PRACH Debug Log ({len(res.debug_lines)} entries) ===\n"
                  f"{'─' * 100}\n")
        for line in res.debug_lines:
            tw.insert(tk.END, line + "\n")
        tw.see(tk.END)
        tw.configure(state=tk.DISABLED)

    def _clear_debug(self):
        self.debug_text.configure(state=tk.NORMAL)
        self.debug_text.delete("1.0", tk.END)
        self.debug_text.configure(state=tk.DISABLED)

    def _clear_text_widget(self, tw):
        tw.configure(state=tk.NORMAL)
        tw.delete("1.0", tk.END)
        tw.configure(state=tk.DISABLED)

    # --------------------------------------------------------
    # Export
    # --------------------------------------------------------
    def _save_graph(self, fmt):
        idx = self.notebook.index(self.notebook.select())
        if idx == 1:
            fig = self.fig_power
        elif idx == 2:
            fig = self.fig_const
        else:
            messagebox.showinfo("Info", "Select Power or Constellation tab first.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=f".{fmt}",
            filetypes=[(f"{fmt.upper()} files", f"*.{fmt}"), ("All files", "*.*")],
            title=f"Save graph as {fmt.upper()}"
        )
        if not path:
            return
        if fmt == "pdf":
            with PdfPages(path) as pp:
                pp.savefig(fig, bbox_inches="tight")
        else:
            fig.savefig(path, dpi=150, bbox_inches="tight",
                        facecolor=fig.get_facecolor())
        messagebox.showinfo("Saved", f"Saved:\n{path}")

    def _export_csv(self):
        if self.result is None:
            messagebox.showwarning("No data", "Run analysis first.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Export PRACH CSV"
        )
        if not path:
            return

        try:
            with open(path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["source", "pcap_frame", "dir_bit", "eAxC_raw",
                             "RU_Port", "Frame", "SF", "Slot", "Symbol",
                             "filterIdx", "startPRBC", "numPRBC",
                             "dBFS", "timeOffset", "cpLength",
                             "fftSize", "scsIndex", "beamId"])

                for info in self.result.cplane_list:
                    w.writerow(["C-Plane", info.frame_num, info.data_direction,
                                f"0x{info.eaxc_id.raw:04X}",
                                info.eaxc_id.ru_port_id,
                                info.frame_id, info.subframe_id,
                                info.slot_id, info.start_symbol_id,
                                info.filter_index, info.start_prbc,
                                info.num_prbc, "",
                                info.time_offset, info.cp_length,
                                info.fft_size, info.scs_index, info.beam_id])

                for data in self.result.uplane_list:
                    w.writerow(["U-Plane", data.frame_num, data.data_direction,
                                f"0x{data.eaxc_id.raw:04X}",
                                data.eaxc_id.ru_port_id,
                                data.frame_id, data.subframe_id,
                                data.slot_id, data.start_symbol_id,
                                data.filter_index, data.start_prbc,
                                data.num_prbc, f"{data.power_dbfs:.4f}",
                                "", "", "", "", ""])

            messagebox.showinfo("Exported", f"Saved:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def _on_close(self):
        self._cancel_flag[0] = True
        self.destroy()


# ============================================================
# ENTRY POINT
# ============================================================
if __name__ == "__main__":
    app = App()
    app.mainloop()
