"""
O-RAN CU-Plane IQ Analyzer
==========================
Analyzes O-RAN fronthaul U-Plane pcap captures.
Supports BFP compressed IQ data (9-bit IQ, 4-bit exponent).
Computes dBFS power, plots time series, and shows constellation diagrams.

Requirements:
    pip install scapy numpy matplotlib

Author: O-RAN IQ Analyzer
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
from collections import defaultdict

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

import numpy as np

try:
    import matplotlib
    matplotlib.use("TkAgg")
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
    from matplotlib.backends.backend_pdf import PdfPages
except ImportError:
    messagebox.showerror("Import Error", "matplotlib not found.\nRun: pip install matplotlib")
    sys.exit(1)

try:
    from scapy.all import PcapReader, Ether
except ImportError:
    messagebox.showerror("Import Error", "scapy not found.\nRun: pip install scapy")
    sys.exit(1)


# ============================================================
# CONSTANTS
# ============================================================
ECPRI_ETHERTYPE   = 0xAEFE
ECPRI_MSG_IQ_DATA = 0x00   # eCPRI message type: IQ Data

# BFP parameters
IQ_WIDTH         = 9    # bits per I or Q sample
NUM_SUBC_PER_PRB = 12   # subcarriers per PRB

# 0dBFS reference base (fs_offset=0):
#   max_value = 2^(IQ_WIDTH-1) * 2^MAX_EXPONENT = 2^8 * 2^15 = 2^23
#   REF_BASE  = max_value^2 = 2^46  (per component; I²+Q² at full scale = 2*2^46)
#   With fs_offset: REF = 2^(46 - 2*fs_offset)
IQ_MAX_EXPONENT = 15
REF_POWER_BASE  = 2.0 ** 46   # = (2^8 * 2^15)^2

# NR RB count table: (bandwidth_MHz, scs_khz) -> num_RBs
# Source: 3GPP TS 38.101-1, Table 5.3.2-1
NR_RB_TABLE = {
    ( 5,  15): 25,
    (10,  15): 52,
    (15,  15): 79,
    (20,  15): 106,
    (25,  15): 133,
    (40,  15): 216,
    (50,  15): 270,
    ( 5,  30): 11,
    (10,  30): 24,
    (15,  30): 38,
    (20,  30): 51,
    (25,  30): 65,
    (40,  30): 106,
    (50,  30): 133,
    (60,  30): 162,
    (80,  30): 217,
    (90,  30): 245,
    (100, 30): 273,
}

SUPPORTED_BW  = sorted(set(k[0] for k in NR_RB_TABLE.keys()))
SUPPORTED_SCS = [15, 30]

DEBUG_MAX_PACKETS = 50   # default max packets shown in debug tab


# ============================================================
# EAXC ID PARSER
# ============================================================
class EAxCID:
    """
    Parse 16-bit O-RAN eAxC ID.
    Standard: DU_Port(4) | BandSector(4) | CC(4) | RU_Port(4)
    Custom:   user-defined bit widths
    """
    def __init__(self, raw_value: int, mode: str = "standard",
                 custom_bits: tuple = (4, 4, 4, 4)):
        self.raw  = raw_value
        self.mode = mode

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
        return (f"eAxC(raw=0x{self.raw:04X} "
                f"DU={self.du_port_id} BS={self.band_sector_id} "
                f"CC={self.cc_id} RU={self.ru_port_id})")


# ============================================================
# BFP DECODER
# ============================================================
class BFPDecoder:
    """
    Block Floating Point decompressor.

    udCompParam PRESENT (udcomp_present=True):
        Byte 0     : udCompParam = reserved[7:4] | exponent[3:0]
        Bytes 1-27 : 12 SC * 2 (I,Q) * 9 bits packed MSB-first = 216 bits = 27 bytes
        Total      : 28 bytes/PRB

    udCompParam ABSENT (udcomp_present=False):
        Bytes 0-26 : 12 SC * 2 (I,Q) * 9 bits packed MSB-first = 216 bits = 27 bytes
        exponent   : 0 (fixed, or carried via C-Plane)
        Total      : 27 bytes/PRB
    """
    IQ_BYTES_PER_PRB_WITH    = 1 + (NUM_SUBC_PER_PRB * 2 * IQ_WIDTH + 7) // 8  # 28
    IQ_BYTES_PER_PRB_WITHOUT =     (NUM_SUBC_PER_PRB * 2 * IQ_WIDTH + 7) // 8  # 27

    @staticmethod
    def prb_size(udcomp_present: bool) -> int:
        return (BFPDecoder.IQ_BYTES_PER_PRB_WITH if udcomp_present
                else BFPDecoder.IQ_BYTES_PER_PRB_WITHOUT)

    @staticmethod
    def decode_prb(prb_bytes: bytes, udcomp_present: bool = True):
        """
        Returns (iq_complex, raw_i, raw_q, exponent)
        udcomp_present: True  = first byte is udCompParam (exponent = byte[0] & 0x0F)
                        False = no udCompParam, exponent = 0
        """
        prb_sz = BFPDecoder.prb_size(udcomp_present)
        if len(prb_bytes) < prb_sz:
            raise ValueError(f"PRB data too short: {len(prb_bytes)} < {prb_sz}")

        if udcomp_present:
            exponent = prb_bytes[0] & 0x0F   # lower nibble [3:0]
            iq_bytes = prb_bytes[1:28]
        else:
            exponent = 0
            iq_bytes = prb_bytes[0:27]
        n_samples  = NUM_SUBC_PER_PRB * 2   # 24
        total_bits = n_samples * IQ_WIDTH    # 216

        bits     = int.from_bytes(iq_bytes, byteorder='big')
        mask     = (1 << IQ_WIDTH) - 1       # 0x1FF
        sign_bit = 1 << (IQ_WIDTH - 1)       # 0x100

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
        """
        Average power per active subcarrier in dBFS.

        Only active subcarriers (|I|>0 or |Q|>0) are counted.
        Zero-valued subcarriers (guard bands, unused RBs) are excluded.

        0dBFS definition (O-RAN spec):
            FS₀ = max(I²) = max(Q²) = max(I²+Q²)
                = (max_mantissa × max_scale)²
                = (2^8 × 2^15)² = 2^46
            REF = FS₀ · 2^(-2·FS_Offset) = 2^(46 - 2·fs_offset)
        """
        iq = iq_complex.astype(np.complex128)
        power_per_sc = iq.real ** 2 + iq.imag ** 2

        # Exclude zero subcarriers (guard bands / unused allocations)
        active = power_per_sc[power_per_sc > 0]
        if len(active) == 0:
            return -np.inf

        power = np.mean(active)
        ref   = REF_POWER_BASE * (2.0 ** (-2 * fs_offset))   # 2^(46 - 2*fs_offset)  per O-RAN spec
        return 10.0 * np.log10(power / ref)


# ============================================================
# O-RAN SECTION TYPE 1
# ============================================================
class SectionType1:
    def __init__(self):
        self.section_id  = 0
        self.rb          = 0
        self.sym_inc     = 0
        self.start_prbc  = 0
        self.num_prbc    = 0
        self.re_mask     = 0xFFF
        self.num_symbol  = 0
        self.ef          = 0
        self.beam_id     = 0
        self.prb_data    = []   # list of (iq_complex, raw_i, raw_q, exponent)


def _parse_section_header(data: bytes, offset: int, header_size: int = 4):
    sec = SectionType1()
    if len(data) < offset + 4:
        return None, 0

    word24          = (data[offset] << 16) | (data[offset+1] << 8) | data[offset+2]
    sec.section_id  = (word24 >> 12) & 0xFFF
    sec.rb          = (word24 >> 11) & 0x1
    sec.sym_inc     = (word24 >> 10) & 0x1
    sec.start_prbc  = word24 & 0x3FF
    sec.num_prbc    = data[offset+3] or 256   # 0 means 256 per spec

    consumed = 4
    if header_size >= 8 and len(data) >= offset + 8:
        b4, b5          = data[offset+4], data[offset+5]
        sec.re_mask     = ((b4 << 4) | (b5 >> 4)) & 0xFFF
        sec.num_symbol  = b5 & 0x0F
        b6, b7          = data[offset+6], data[offset+7]
        sec.ef          = (b6 >> 7) & 0x1
        sec.beam_id     = ((b6 & 0x7F) << 8) | b7
        consumed        = 8

    return sec, consumed


# ============================================================
# O-RAN PACKET
# ============================================================
class ORANPacket:
    def __init__(self):
        self.data_direction  = -1
        self.payload_version = 0
        self.filter_index    = 0
        self.frame_id        = 0
        self.subframe_id     = 0
        self.slot_id         = 0
        self.start_symbol_id = 0
        self.eaxc_id         = None
        self.seq_id          = 0
        self.sections        = []


class ORANParser:
    def __init__(self, eaxc_mode="standard", eaxc_custom_bits=(4, 4, 4, 4),
                 section_header_size=4, udcomp_present=True):
        self.eaxc_mode        = eaxc_mode
        self.eaxc_custom_bits = eaxc_custom_bits
        self.section_hdr_size = section_header_size
        self.udcomp_present   = udcomp_present   # True=28 bytes/PRB, False=27 bytes/PRB

    def parse(self, payload: bytes) -> ORANPacket:
        if len(payload) < 8:
            return None

        pkt = ORANPacket()

        # eAxC ID (2 bytes)
        eaxc_raw    = struct.unpack_from(">H", payload, 0)[0]
        pkt.eaxc_id = EAxCID(eaxc_raw, mode=self.eaxc_mode,
                             custom_bits=self.eaxc_custom_bits)
        pkt.seq_id = payload[2]

        # App common header (4 bytes at offset 4)
        app0                 = payload[4]
        pkt.data_direction   = (app0 >> 7) & 0x1
        pkt.payload_version  = (app0 >> 4) & 0x7
        pkt.filter_index     = app0 & 0x0F
        pkt.frame_id         = payload[5]
        pkt.subframe_id      = (payload[6] >> 4) & 0x0F
        pkt.slot_id          = ((payload[6] & 0x0F) << 2) | ((payload[7] >> 6) & 0x03)
        pkt.start_symbol_id  = payload[7] & 0x3F

        # Parse sections starting at offset 8
        prb_sz = BFPDecoder.prb_size(self.udcomp_present)
        offset = 8
        while offset + self.section_hdr_size <= len(payload):
            sec, hdr_bytes = _parse_section_header(
                payload, offset, self.section_hdr_size)
            if sec is None or hdr_bytes == 0:
                break
            offset += hdr_bytes

            for _ in range(sec.num_prbc):
                if offset + prb_sz > len(payload):
                    break
                try:
                    iq, ri, rq, exp = BFPDecoder.decode_prb(
                        payload[offset: offset + prb_sz],
                        udcomp_present=self.udcomp_present)
                    sec.prb_data.append((iq, ri, rq, exp))
                except Exception:
                    pass
                offset += prb_sz

            pkt.sections.append(sec)

        return pkt


# ============================================================
# ANALYSIS RESULT
# ============================================================
class AnalysisResult:
    """
    Key: (data_direction_bit, ru_port_id)
    data_direction_bit is the RAW bit value (0 or 1) from the packet.
    Note: per O-RAN spec 0=DL, 1=UL, but some vendors invert this.
    """
    def __init__(self):
        self.data = defaultdict(lambda: {
            'power_dbfs': [],   # (frame, subframe, slot, symbol, dbfs)
            'iq_complex': [],   # list of np.ndarray complex64
        })
        self.packet_count = 0
        self.error_count  = 0
        self.debug_lines  = []


# ============================================================
# PCAP PROCESSOR
# ============================================================
def process_pcap(filepath, frame_start, frame_end, parser,
                 progress_cb=None, cancel_flag=None,
                 debug_mode=False, debug_max=DEBUG_MAX_PACKETS,
                 fs_offset=0) -> AnalysisResult:

    result      = AnalysisResult()
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

            raw = bytes(raw_pkt)
            payload = _find_ecpri_payload(raw)

            if payload is None:
                if debug_mode and debug_count < debug_max:
                    result.debug_lines.append(
                        f"[Frame {frame_num:5d}] Skipped: no eCPRI (ethertype!=0xAEFE)")
                    debug_count += 1
                continue

            if len(payload) < 4:
                continue
            ecpri_msg = payload[1]
            if ecpri_msg != ECPRI_MSG_IQ_DATA:
                if debug_mode and debug_count < debug_max:
                    result.debug_lines.append(
                        f"[Frame {frame_num:5d}] Skipped: eCPRI msgType=0x{ecpri_msg:02X} "
                        f"(expected 0x00 IQ Data)")
                    debug_count += 1
                continue

            oran_payload = payload[4:]
            pkt = parser.parse(oran_payload)
            if pkt is None:
                result.error_count += 1
                continue

            result.packet_count += 1

            # --- Debug output ---
            if debug_mode and debug_count < debug_max:
                n_prbs   = sum(len(s.prb_data) for s in pkt.sections)
                exp_list = [exp for s in pkt.sections
                            for (_, _, _, exp) in s.prb_data]
                exp_str  = (f"exp=[{min(exp_list)}~{max(exp_list)}]"
                            if exp_list else "exp=[]")

                # All PRBs: all 12 subcarrier IQ pairs
                iq_sample_str = ""
                for sec_idx, sec in enumerate(pkt.sections):
                    for prb_idx, (_, ri, rq, exp) in enumerate(sec.prb_data):
                        pairs = "  ".join(
                            f"SC{k}:(I={ri[k]:5d},Q={rq[k]:5d})"
                            for k in range(len(ri))
                        )
                        iq_sample_str += (
                            f"\n           Sec{sec_idx} PRB{prb_idx} exp={exp}: {pairs}"
                        )

                result.debug_lines.append(
                    f"[Frame {frame_num:5d}] "
                    f"dirBit={pkt.data_direction}  "
                    f"{pkt.eaxc_id}  "
                    f"Frm={pkt.frame_id} SF={pkt.subframe_id} "
                    f"Slot={pkt.slot_id} Sym={pkt.start_symbol_id}  "
                    f"Sec={len(pkt.sections)}  PRBs={n_prbs}  {exp_str}  "
                    f"SeqId={pkt.seq_id}"
                    + iq_sample_str
                )
                debug_count += 1

            # --- Accumulate IQ data ---
            key    = (pkt.data_direction, pkt.eaxc_id.ru_port_id)
            bucket = result.data[key]

            all_iq = []
            for sec in pkt.sections:
                for (iq, ri, rq, _) in sec.prb_data:
                    all_iq.append(iq)

            if not all_iq:
                continue

            iq_flat = np.concatenate(all_iq)

            dbfs = BFPDecoder.calc_power_dbfs(iq_flat, fs_offset=fs_offset)
            bucket['power_dbfs'].append((
                pkt.frame_id, pkt.subframe_id, pkt.slot_id,
                pkt.start_symbol_id, dbfs))
            bucket['iq_complex'].append(iq_flat)

    return result


def _find_ecpri_payload(raw: bytes) -> bytes:
    """Walk raw Ethernet frame bytes to find eCPRI payload (handles 802.1Q VLAN)."""
    if len(raw) < 14:
        return None

    ethertype = struct.unpack_from(">H", raw, 12)[0]
    offset    = 14

    # Skip 802.1Q / QinQ VLAN tags
    while ethertype in (0x8100, 0x88A8, 0x9100):
        if offset + 4 > len(raw):
            return None
        ethertype = struct.unpack_from(">H", raw, offset + 2)[0]
        offset   += 4

    if ethertype != ECPRI_ETHERTYPE:
        return None

    return raw[offset:]


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
        self.title("O-RAN CU-Plane IQ Analyzer  v1.2")
        self.geometry("1250x860")
        self.minsize(950, 680)
        self.configure(bg="#2b2b2b")

        # Control variables
        self.filepath         = tk.StringVar()
        self.frame_start      = tk.IntVar(value=1)
        self.frame_end        = tk.IntVar(value=-1)
        self.dir_bit          = tk.IntVar(value=0)   # raw bit 0 or 1
        self.ru_port_str      = tk.StringVar(value="0")  # free text
        self.bandwidth_mhz    = tk.IntVar(value=20)
        self.scs_khz          = tk.IntVar(value=30)
        self.fs_offset        = tk.IntVar(value=0)   # O-RAN fs-offset 0-16
        self.eaxc_mode        = tk.StringVar(value="standard")
        self.section_hdr_size = tk.IntVar(value=4)
        self.debug_mode       = tk.BooleanVar(value=False)
        self.debug_max_var    = tk.IntVar(value=50)

        # Custom eAxC bit widths
        self.custom_du_bits = tk.IntVar(value=4)
        self.custom_bs_bits = tk.IntVar(value=4)
        self.custom_cc_bits = tk.IntVar(value=4)
        self.custom_ru_bits = tk.IntVar(value=4)

        self.result         = None
        self._cancel_flag   = [False]
        self._worker_thread = None

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
        self.left = tk.Frame(self, bg="#3c3f41", width=295)
        self.left.pack(side=tk.LEFT, fill=tk.Y)
        self.left.pack_propagate(False)

        self.right = tk.Frame(self, bg="#2b2b2b")
        self.right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._build_controls(self.left)
        self._build_graphs(self.right)

    # --------------------------------------------------------
    # Control panel
    # --------------------------------------------------------
    def _lf(self, parent, title):
        """Labeled frame helper."""
        f = tk.LabelFrame(parent, text=title, fg="#a9b7c6",
                          bg="#3c3f41", font=("Consolas", 9, "bold"),
                          padx=6, pady=4)
        f.pack(fill=tk.X, padx=8, pady=3)
        return f

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
        for r, lbl, var in [(0, "Start:",       self.frame_start),
                             (1, "End (-1=all):", self.frame_end)]:
            tk.Label(row, text=lbl, bg="#3c3f41", fg="#a9b7c6",
                     width=12, anchor="w").grid(row=r, column=0, sticky="w", pady=1)
            tk.Spinbox(row, from_=-1, to=9999999, textvariable=var,
                       width=9, bg="#4c5052",
                       fg="white").grid(row=r, column=1, sticky="w")

        # --- Filter ---
        filt  = self._lf(parent, "Filter")
        row2  = tk.Frame(filt, bg="#3c3f41")
        row2.pack(fill=tk.X)

        # Direction bit (raw value 0 or 1)
        tk.Label(row2, text="Dir bit:", bg="#3c3f41", fg="#a9b7c6",
                 width=10, anchor="w").grid(row=0, column=0, sticky="w")
        dir_fr = tk.Frame(row2, bg="#3c3f41")
        dir_fr.grid(row=0, column=1, sticky="w")
        for v, lbl in [(0, "0"), (1, "1")]:
            tk.Radiobutton(dir_fr, text=lbl, variable=self.dir_bit, value=v,
                           bg="#3c3f41", fg="white",
                           activebackground="#3c3f41",
                           selectcolor="#555",
                           font=("Consolas", 10, "bold")).pack(side=tk.LEFT, padx=4)
        tk.Label(row2, text="0=UL  1=DL  (this vendor)",
                 bg="#3c3f41", fg="#6A9955",
                 font=("Consolas", 7)).grid(row=1, column=0, columnspan=2, sticky="w")

        # RU_Port_ID free text
        tk.Label(row2, text="RU_Port_ID:", bg="#3c3f41", fg="#a9b7c6",
                 width=10, anchor="w").grid(row=2, column=0, sticky="w", pady=(5, 0))
        tk.Entry(row2, textvariable=self.ru_port_str,
                 bg="#4c5052", fg="white",
                 font=("Consolas", 11), width=7,
                 justify="center").grid(row=2, column=1, sticky="w", pady=(5, 0))
        tk.Label(row2, text="any value: 0,1,8,9...",
                 bg="#3c3f41", fg="#6A9955",
                 font=("Consolas", 7)).grid(row=3, column=0, columnspan=2, sticky="w")

        # --- Signal Parameters ---
        sp   = self._lf(parent, "Signal Parameters")
        row3 = tk.Frame(sp, bg="#3c3f41")
        row3.pack(fill=tk.X)
        tk.Label(row3, text="BW (MHz):", bg="#3c3f41", fg="#a9b7c6",
                 width=10, anchor="w").grid(row=0, column=0, sticky="w")
        ttk.Combobox(row3, textvariable=self.bandwidth_mhz,
                     values=SUPPORTED_BW, width=7,
                     state="readonly").grid(row=0, column=1, sticky="w")
        tk.Label(row3, text="SCS (kHz):", bg="#3c3f41", fg="#a9b7c6",
                 width=10, anchor="w").grid(row=1, column=0, sticky="w", pady=2)
        ttk.Combobox(row3, textvariable=self.scs_khz,
                     values=SUPPORTED_SCS, width=7,
                     state="readonly").grid(row=1, column=1, sticky="w")
        tk.Label(row3, text="fs-offset:", bg="#3c3f41", fg="#a9b7c6",
                 width=10, anchor="w").grid(row=2, column=0, sticky="w", pady=2)
        tk.Spinbox(row3, from_=0, to=16, textvariable=self.fs_offset,
                   width=4, bg="#4c5052",
                   fg="white").grid(row=2, column=1, sticky="w")
        tk.Label(row3, text="0dBFS ref = 2^(46-2×fs-offset)",
                 bg="#3c3f41", fg="#6A9955",
                 font=("Consolas", 7)).grid(row=3, column=0, columnspan=2, sticky="w")

        # --- Advanced ---
        adv  = self._lf(parent, "Advanced (Parser)")
        row4 = tk.Frame(adv, bg="#3c3f41")
        row4.pack(fill=tk.X)
        tk.Label(row4, text="eAxC mode:", bg="#3c3f41", fg="#a9b7c6",
                 width=11, anchor="w").grid(row=0, column=0, sticky="w")
        mc = ttk.Combobox(row4, textvariable=self.eaxc_mode,
                          values=["standard", "custom"],
                          width=8, state="readonly")
        mc.grid(row=0, column=1, sticky="w")
        mc.bind("<<ComboboxSelected>>", self._on_eaxc_mode_change)

        self._custom_frame = tk.Frame(adv, bg="#3c3f41")
        self._custom_frame.pack(fill=tk.X)
        self._build_custom_eaxc(self._custom_frame)
        self._custom_frame.pack_forget()

        tk.Label(row4, text="Sec Hdr:", bg="#3c3f41", fg="#a9b7c6",
                 width=8, anchor="w").grid(row=1, column=0, sticky="w", pady=2)
        ttk.Combobox(row4, textvariable=self.section_hdr_size,
                     values=[4, 8], width=4,
                     state="readonly").grid(row=1, column=1, sticky="w")

        # --- Debug ---
        dbg     = self._lf(parent, "Debug")
        dbg_row = tk.Frame(dbg, bg="#3c3f41")
        dbg_row.pack(fill=tk.X)
        tk.Checkbutton(dbg_row, text="Enable debug output",
                       variable=self.debug_mode,
                       bg="#3c3f41", fg="#a9b7c6",
                       activebackground="#3c3f41", selectcolor="#555",
                       font=("Consolas", 9)).grid(row=0, column=0, columnspan=2, sticky="w")
        tk.Label(dbg_row, text="Max pkts:", bg="#3c3f41", fg="#a9b7c6",
                 width=9, anchor="w",
                 font=("Consolas", 8)).grid(row=1, column=0, sticky="w")
        tk.Spinbox(dbg_row, from_=1, to=500, textvariable=self.debug_max_var,
                   width=5, bg="#4c5052",
                   fg="white").grid(row=1, column=1, sticky="w")
        tk.Label(dbg_row, text="→ shown in Debug tab",
                 bg="#3c3f41", fg="#6A9955",
                 font=("Consolas", 7)).grid(row=2, column=0, columnspan=2, sticky="w")

        # --- Buttons ---
        tk.Button(parent, text="▶  Analyze",
                  command=self._start_analysis,
                  bg="#4CAF50", fg="white",
                  font=("Consolas", 11, "bold"),
                  relief=tk.FLAT, pady=6).pack(fill=tk.X, padx=8, pady=(6, 2))
        tk.Button(parent, text="■  Stop",
                  command=self._stop_analysis,
                  bg="#f44336", fg="white",
                  font=("Consolas", 10),
                  relief=tk.FLAT, pady=4).pack(fill=tk.X, padx=8)

        # --- Status / Stats ---
        self.status_var = tk.StringVar(value="Ready.")
        tk.Label(parent, textvariable=self.status_var,
                 bg="#3c3f41", fg="#6A9955", wraplength=270,
                 justify="left",
                 font=("Consolas", 8)).pack(padx=8, pady=2)

        self.progress = ttk.Progressbar(parent, mode='indeterminate')
        self.progress.pack(fill=tk.X, padx=8, pady=2)

        self.stats_var = tk.StringVar(value="")
        tk.Label(parent, textvariable=self.stats_var,
                 bg="#3c3f41", fg="#a9b7c6", wraplength=270,
                 justify="left",
                 font=("Consolas", 8)).pack(padx=8, pady=2)

    def _build_custom_eaxc(self, parent):
        for i, (lbl, var) in enumerate([("DU bits", self.custom_du_bits),
                                         ("BS bits", self.custom_bs_bits),
                                         ("CC bits", self.custom_cc_bits),
                                         ("RU bits", self.custom_ru_bits)]):
            tk.Label(parent, text=lbl, bg="#3c3f41", fg="#a9b7c6",
                     width=8, anchor="w",
                     font=("Consolas", 8)).grid(row=i, column=0, sticky="w")
            tk.Spinbox(parent, from_=1, to=12, textvariable=var,
                       width=4, bg="#4c5052",
                       fg="white").grid(row=i, column=1, sticky="w", pady=1)

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

        self.tab_power = tk.Frame(self.notebook, bg="#2b2b2b")
        self.notebook.add(self.tab_power, text="  Power / dBFS  ")
        self._build_power_tab(self.tab_power)

        self.tab_const = tk.Frame(self.notebook, bg="#2b2b2b")
        self.notebook.add(self.tab_const, text="  Constellation  ")
        self._build_const_tab(self.tab_const)

        self.tab_debug = tk.Frame(self.notebook, bg="#2b2b2b")
        self.notebook.add(self.tab_debug, text="  Debug  ")
        self._build_debug_tab(self.tab_debug)

    def _build_power_tab(self, parent):
        top = tk.Frame(parent, bg="#2b2b2b")
        top.pack(fill=tk.X, padx=8, pady=4)
        tk.Label(top, text="Average dBFS:",
                 fg="#a9b7c6", bg="#2b2b2b",
                 font=("Consolas", 11)).pack(side=tk.LEFT)
        self.dbfs_label = tk.Label(top, text="---",
                                   fg="#61DAFB", bg="#2b2b2b",
                                   font=("Consolas", 22, "bold"))
        self.dbfs_label.pack(side=tk.LEFT, padx=12)
        self.fullscale_label = tk.Label(top, text="",
                                        fg="#98c379", bg="#2b2b2b",
                                        font=("Consolas", 10))
        self.fullscale_label.pack(side=tk.LEFT, padx=8)

        self.fig_power = Figure(figsize=(7, 4), dpi=96, facecolor="#1e1e1e")
        self.ax_power  = self.fig_power.add_subplot(111)
        self._style_ax(self.ax_power, "Slot Index", "dBFS", "Packet Power vs. Time")
        self.fig_power.tight_layout(pad=1.5)

        cp = FigureCanvasTkAgg(self.fig_power, parent)
        cp.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=4)
        NavigationToolbar2Tk(cp, parent).update()
        self.canvas_power = cp

    def _build_const_tab(self, parent):
        self.fig_const = Figure(figsize=(5, 5), dpi=96, facecolor="#1e1e1e")
        self.ax_const  = self.fig_const.add_subplot(111)
        self._style_ax(self.ax_const, "I", "Q", "Constellation")
        self.fig_const.tight_layout(pad=1.5)

        cc = FigureCanvasTkAgg(self.fig_const, parent)
        cc.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=4)
        NavigationToolbar2Tk(cc, parent).update()
        self.canvas_const = cc

    def _build_debug_tab(self, parent):
        ctrl = tk.Frame(parent, bg="#2b2b2b")
        ctrl.pack(fill=tk.X, padx=8, pady=4)
        tk.Label(ctrl,
                 text="Parsed packet log  (first N eCPRI IQ Data packets)",
                 fg="#a9b7c6", bg="#2b2b2b",
                 font=("Consolas", 9)).pack(side=tk.LEFT)
        tk.Button(ctrl, text="Clear", command=self._clear_debug,
                  bg="#555", fg="white",
                  font=("Consolas", 8), relief=tk.FLAT).pack(side=tk.RIGHT)

        # Use grid layout for reliable horizontal + vertical scrollbar
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
            xscrollcommand=xsb.set,
            yscrollcommand=ysb.set,
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
            filetypes=[("pcap files", "*.pcap"), ("All files", "*.*")]
        )
        if path:
            self.filepath.set(path)

    def _start_analysis(self):
        fp = self.filepath.get().strip()
        if not fp or not os.path.isfile(fp):
            messagebox.showwarning("File not found", "Please select a valid pcap file.")
            return

        bw  = self.bandwidth_mhz.get()
        scs = self.scs_khz.get()
        if (bw, scs) not in NR_RB_TABLE:
            messagebox.showwarning(
                "Unsupported",
                f"BW={bw} MHz / SCS={scs} kHz not in RB table.\n"
                f"Supported: {sorted(NR_RB_TABLE.keys())}")
            return

        try:
            ru_port = int(self.ru_port_str.get().strip())
        except ValueError:
            messagebox.showwarning("Input Error",
                "RU_Port_ID must be an integer (e.g. 0, 1, 8, 9).")
            return

        if self._worker_thread and self._worker_thread.is_alive():
            messagebox.showinfo("Busy", "Analysis running. Press Stop first.")
            return

        self._cancel_flag[0] = False
        self.result = None
        self.status_var.set("Analyzing...")
        self.progress.start(12)
        self.dbfs_label.configure(text="---")
        self.fullscale_label.configure(text="")
        self.stats_var.set("")
        self._clear_debug()

        mode   = self.eaxc_mode.get()
        custom = (self.custom_du_bits.get(), self.custom_bs_bits.get(),
                  self.custom_cc_bits.get(), self.custom_ru_bits.get())
        parser = ORANParser(eaxc_mode=mode, eaxc_custom_bits=custom,
                            section_header_size=self.section_hdr_size.get(),
                            udcomp_present=True)

        fs      = self.frame_start.get()
        fe      = self.frame_end.get()
        dir_bit = self.dir_bit.get()
        debug   = self.debug_mode.get()
        dbg_max = self.debug_max_var.get()
        fso     = self.fs_offset.get()

        def worker():
            try:
                res = process_pcap(
                    fp, fs, fe, parser,
                    progress_cb=self._on_progress,
                    cancel_flag=self._cancel_flag,
                    debug_mode=debug,
                    debug_max=dbg_max,
                    fs_offset=fso,
                )
                self.result = res
                self.after(0, lambda: self._on_done(dir_bit, ru_port, bw, scs))
            except Exception as e:
                tb = traceback.format_exc()
                self.after(0, lambda: self._on_error(str(e), tb))

        self._worker_thread = threading.Thread(target=worker, daemon=True)
        self._worker_thread.start()

    def _stop_analysis(self):
        self._cancel_flag[0] = True
        self.status_var.set("Stopping...")

    def _on_progress(self, frame_num):
        self.after(0, lambda: self.status_var.set(f"Processing frame {frame_num:,}..."))

    def _on_done(self, dir_bit, ru_port, bw, scs):
        self.progress.stop()
        if self.result is None:
            self.status_var.set("No result.")
            return

        num_rb = NR_RB_TABLE[(bw, scs)]
        key    = (dir_bit, ru_port)

        if key not in self.result.data:
            available = sorted(self.result.data.keys())
            self.status_var.set(
                f"No data for dirBit={dir_bit}, RU_Port={ru_port}.\n"
                f"Available: {available}"
            )
            self.stats_var.set(
                f"eCPRI pkts: {self.result.packet_count:,}\n"
                f"Errors: {self.result.error_count}\n"
                f"Keys found: {available}"
            )
            # Still populate debug if available
            self._populate_debug()
            return

        bucket     = self.result.data[key]
        power_list = bucket['power_dbfs']
        iq_list    = bucket['iq_complex']

        if not power_list:
            self.status_var.set(f"dirBit={dir_bit}/RU{ru_port}: matched but no IQ data.")
            self._populate_debug()
            return

        dbfs_values  = np.array([p[4] for p in power_list])
        finite_dbfs  = dbfs_values[np.isfinite(dbfs_values)]
        avg_dbfs     = float(np.mean(finite_dbfs)) if len(finite_dbfs) > 0 else -np.inf
        zero_pkt_cnt = int(np.sum(~np.isfinite(dbfs_values)))

        total_prbs  = (sum(len(iq) for iq in iq_list[-1:]) // NUM_SUBC_PER_PRB
                       if iq_list else 0)
        full_rb_ok  = total_prbs >= num_rb

        self.dbfs_label.configure(text=f"{avg_dbfs:+.2f} dB")
        color = ("#98c379" if abs(avg_dbfs) < 1.0
                 else "#e5c07b" if abs(avg_dbfs) < 3.0
                 else "#e06c75")
        self.dbfs_label.configure(fg=color)
        self.fullscale_label.configure(
            text=(f"Full-RB: {total_prbs} / {num_rb} RBs  "
                  f"({'✓ OK' if full_rb_ok else '✗ Mismatch'})"))

        self.stats_var.set(
            f"dirBit={dir_bit} | RU_Port={ru_port}\n"
            f"BW={bw} MHz | SCS={scs} kHz | RBs={num_rb}\n"
            f"Matched pkts: {len(power_list):,}  (zero-SC: {zero_pkt_cnt})\n"
            f"Total eCPRI: {self.result.packet_count:,} | Err: {self.result.error_count}"
        )
        self.status_var.set("Done.")

        # ---- Plot on Power tab first (must be visible for correct layout) ----
        self.notebook.select(self.tab_power)
        self.update_idletasks()
        self._plot_power(power_list, scs, avg_dbfs, dir_bit, ru_port)

        # ---- Plot constellation ----
        self.notebook.select(self.tab_const)
        self.update_idletasks()
        self._plot_constellation(iq_list, dir_bit, ru_port)

        # ---- Populate debug log and switch tab if needed ----
        self._populate_debug()

        # Return to Power tab as default view
        self.notebook.select(self.tab_power)

    def _populate_debug(self):
        """Fill debug tab with log lines. Called after plotting."""
        if not (self.result and self.result.debug_lines):
            return
        keys_found = sorted(self.result.data.keys())
        self._append_debug(
            f"=== Debug log: {len(self.result.debug_lines)} entries "
            f"(total eCPRI IQ pkts: {self.result.packet_count:,}) ===\n"
            f"Keys in pcap  (dir_bit, ru_port_id): {keys_found}\n"
            f"{'─' * 80}\n"
        )
        for line in self.result.debug_lines:
            self._append_debug(line + "\n")

    def _on_error(self, msg, tb):
        self.progress.stop()
        self.status_var.set(f"Error: {msg}")
        messagebox.showerror("Analysis Error", f"{msg}\n\n{tb[:1000]}")

    # --------------------------------------------------------
    # Plots
    # --------------------------------------------------------
    def _plot_power(self, power_list, scs, avg_dbfs, dir_bit, ru_port):
        ax = self.ax_power
        ax.cla()
        self._style_ax(ax, "Slot Index", "dBFS",
                       f"Power vs. Time  [dirBit={dir_bit} | RU_Port={ru_port}]")
        ax.axhline(0,        color="#e06c75", lw=1.2, ls="--", label="0 dBFS ref")
        ax.axhline(avg_dbfs, color="#61DAFB", lw=1.0, ls="-.",
                   label=f"avg {avg_dbfs:+.2f} dB")

        slots    = np.array([timing_to_slot_index(p[0], p[1], p[2], scs)
                             for p in power_list])
        dbfs_arr = np.array([p[4] for p in power_list])
        ax.scatter(slots, dbfs_arr, s=2, color="#61AFEF", alpha=0.7, label="per-pkt")
        ax.legend(facecolor="#2b2b2b", edgecolor="#555",
                  labelcolor="#a9b7c6", fontsize=8)
        try:
            self.fig_power.tight_layout(pad=1.5)
        except Exception:
            pass
        self.canvas_power.draw_idle()

    def _plot_constellation(self, iq_list, dir_bit, ru_port):
        ax = self.ax_const
        ax.cla()
        self._style_ax(ax, "I", "Q",
                       f"Constellation  [dirBit={dir_bit} | RU_Port={ru_port}]")

        all_iq = np.concatenate(iq_list) if iq_list else np.array([], dtype=np.complex64)
        if len(all_iq) > 50000:
            idx    = np.random.choice(len(all_iq), 50000, replace=False)
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
    # Debug helpers
    # --------------------------------------------------------
    def _append_debug(self, text: str):
        self.debug_text.configure(state=tk.NORMAL)
        self.debug_text.insert(tk.END, text)
        self.debug_text.see(tk.END)
        self.debug_text.configure(state=tk.DISABLED)

    def _clear_debug(self):
        self.debug_text.configure(state=tk.NORMAL)
        self.debug_text.delete("1.0", tk.END)
        self.debug_text.configure(state=tk.DISABLED)

    # --------------------------------------------------------
    # Export
    # --------------------------------------------------------
    def _save_graph(self, fmt):
        idx = self.notebook.index(self.notebook.select())
        fig = self.fig_power if idx == 0 else self.fig_const

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
            title="Export CSV"
        )
        if not path:
            return

        try:
            with open(path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["dir_bit", "RU_Port_ID",
                             "Frame", "Subframe", "Slot", "Symbol", "dBFS"])
                for (dir_bit, ru_port), bucket in self.result.data.items():
                    for (frame, sf, slot, sym, dbfs) in bucket['power_dbfs']:
                        w.writerow([dir_bit, ru_port,
                                    frame, sf, slot, sym, f"{dbfs:.4f}"])
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
