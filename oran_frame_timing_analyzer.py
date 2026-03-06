#!/usr/bin/env python3
"""
O-RAN Fronthaul Frame Timing Analyzer
O-RAN CUS 9.7.2 / Table B.1 based frameId verification.

Requirements:
    pip install scapy matplotlib numpy
"""

import sys, struct, math

# ── dependency check ───────────────────────────────────────────
missing = []
try:
    import numpy as np
except ImportError:
    missing.append("numpy  →  pip install numpy")
try:
    import matplotlib
    import matplotlib.pyplot as plt
    import matplotlib.gridspec as gridspec
    from matplotlib.lines import Line2D
    from matplotlib.widgets import Slider, TextBox, Button
except ImportError:
    missing.append("matplotlib  →  pip install matplotlib")
try:
    from scapy.all import rdpcap
    from scapy.layers.l2 import Ether
except ImportError:
    missing.append("scapy  →  pip install scapy")
if missing:
    print("Missing packages:"); [print("  " + m) for m in missing]; sys.exit(1)

import tkinter as tk
from tkinter import filedialog

# ──────────────────────────────────────────────────────────────
#  Constants
# ──────────────────────────────────────────────────────────────
ETHERTYPE_PTP   = 0x88F7
ETHERTYPE_ECPRI = 0xAEFE
ETHERTYPE_VLAN  = 0x8100
ETHERTYPE_VLAN2 = 0x88A8
PTP_TO_GPS      = 315_964_819   # Table B.1: GPS_sec = PTP_sec - this
FRAME_PERIOD    = 0.01
MAX_FRAME       = 1023
CHIP_HZ         = 1.2288e9
PTP_SYNC        = 0x0
PTP_FOLLOWUP    = 0x8
ECPRI_CPLANE    = 0x02

# ──────────────────────────────────────────────────────────────
#  Parsing
# ──────────────────────────────────────────────────────────────
def strip_vlan(raw):
    if len(raw) < 14: return None, None
    off = 12
    et  = struct.unpack_from('>H', raw, off)[0]; off += 2
    while et in (ETHERTYPE_VLAN, ETHERTYPE_VLAN2):
        if len(raw) < off + 4: return None, None
        et = struct.unpack_from('>H', raw, off+2)[0]; off += 4
    return et, raw[off:]

def parse_ptp(p):
    if len(p) < 44: return None
    mt = p[0] & 0x0F
    if mt not in (PTP_SYNC, PTP_FOLLOWUP): return None
    seq = struct.unpack_from('>H', p, 30)[0]
    ts  = bool(p[6] & 0x02)
    sh  = struct.unpack_from('>H', p, 34)[0]
    sl  = struct.unpack_from('>I', p, 36)[0]
    ns  = struct.unpack_from('>I', p, 40)[0]
    return mt, ((sh << 32)|sl)*1_000_000_000 + ns, seq, ts

def parse_ecpri(p):
    if len(p) < 12: return None
    mt = p[1]; o = 8
    plane = 'C-Plane' if mt == ECPRI_CPLANE else 'U-Plane'
    return {'frameId': p[o+1],
            'subframeId': (p[o+2]>>4)&0xF,
            'slotId': ((p[o+2]&0xF)<<2)|((p[o+3]>>6)&0x3),
            'symbolId': p[o+3]&0x3F, 'plane': plane}

# ──────────────────────────────────────────────────────────────
#  frameId calculation
# ──────────────────────────────────────────────────────────────
def calc_expected(ptp_ns, alpha, beta):
    gps = ptp_ns/1e9 - PTP_TO_GPS
    t   = gps - beta*FRAME_PERIOD - alpha/CHIP_HZ
    return int(math.floor(t/FRAME_PERIOD)) % (MAX_FRAME+1)

def delta(actual, exp):
    d = (actual - exp) % (MAX_FRAME+1)
    return d - (MAX_FRAME+1) if d > (MAX_FRAME+1)//2 else d

# ──────────────────────────────────────────────────────────────
#  pcap loader
# ──────────────────────────────────────────────────────────────
def load_pcap(path):
    recs = []; pending = {}
    nv = np_ = ne = 0
    for pkt in rdpcap(path):
        ts = int(float(pkt.time)*1_000_000_000)
        if not pkt.haslayer(Ether): continue
        raw = bytes(pkt[Ether])
        if struct.unpack_from('>H', raw, 12)[0] in (ETHERTYPE_VLAN, ETHERTYPE_VLAN2): nv+=1
        et, pay = strip_vlan(raw)
        if et is None: continue
        if et == ETHERTYPE_PTP:
            r = parse_ptp(pay)
            if not r: continue
            np_ += 1
            mt, ptp_ns, seq, two = r
            if mt == PTP_SYNC:
                if two: pending[seq] = ts
                else: recs.append({'type':'ptp','ts':ts,'ptp_ns':ptp_ns,'label':'Sync(1-step)'})
            elif mt == PTP_FOLLOWUP:
                recs.append({'type':'ptp','ts':pending.pop(seq,ts),'ptp_ns':ptp_ns,'label':'FollowUp'})
        elif et == ETHERTYPE_ECPRI:
            r = parse_ecpri(pay)
            if not r: continue
            ne += 1; r.update({'type':'ecpri','ts':ts}); recs.append(r)
    recs.sort(key=lambda x: x['ts'])
    print(f"  VLAN:{nv}  PTP:{np_}  eCPRI:{ne}")
    return recs

# ──────────────────────────────────────────────────────────────
#  Analysis
# ──────────────────────────────────────────────────────────────
def analyze(recs, alpha, beta):
    results=[]; ptp_evts=[]; dbg=[]
    ref_ptp=ref_ts=None; idx=0
    for rec in recs:
        idx+=1
        if rec['type']=='ptp':
            ref_ptp=rec['ptp_ns']; ref_ts=rec['ts']
            ptp_evts.append(rec['ts'])
            ps=ref_ptp/1e9; gs=ps-PTP_TO_GPS
            t=gs-beta*FRAME_PERIOD-alpha/CHIP_HZ
            exp=int(math.floor(t/FRAME_PERIOD))%(MAX_FRAME+1)
            dbg.append({'idx':idx,'kind':'PTP','plane':rec['label'],'ts':rec['ts'],
                'ptp_sec':ps,'gps_sec':gs,'elapsed_ns':0,'curr_ptp':ps,
                'alpha_ns':alpha/CHIP_HZ*1e9,'beta_ms':beta*FRAME_PERIOD*1e3,
                't':t,'expected':exp,'actual':None,'delta':None})
        elif rec['type']=='ecpri':
            if ref_ptp is None:
                dbg.append({'idx':idx,'kind':'eCPRI','plane':rec['plane'],'ts':rec['ts'],
                    'ptp_sec':None,'gps_sec':None,'elapsed_ns':None,'curr_ptp':None,
                    'alpha_ns':None,'beta_ms':None,'t':None,'expected':None,
                    'actual':rec['frameId'],'delta':None}); continue
            el=rec['ts']-ref_ts; cp=ref_ptp+el; ps=cp/1e9; gs=ps-PTP_TO_GPS
            t=gs-beta*FRAME_PERIOD-alpha/CHIP_HZ
            exp=int(math.floor(t/FRAME_PERIOD))%(MAX_FRAME+1)
            dlt=delta(rec['frameId'],exp)
            results.append({'ts':rec['ts'],'actual':rec['frameId'],'expected':exp,
                            'delta':dlt,'plane':rec['plane']})
            dbg.append({'idx':idx,'kind':'eCPRI','plane':rec['plane'],'ts':rec['ts'],
                'ptp_sec':None,'gps_sec':None,'elapsed_ns':el,'curr_ptp':ps,
                'alpha_ns':alpha/CHIP_HZ*1e9,'beta_ms':beta*FRAME_PERIOD*1e3,
                't':t,'expected':exp,'actual':rec['frameId'],'delta':dlt})
    return results, ptp_evts, dbg

# ──────────────────────────────────────────────────────────────
#  Main: single matplotlib window
# ──────────────────────────────────────────────────────────────
def main():
    print("O-RAN Fronthaul Frame Timing Analyzer")
    print("="*40)

    # File dialog via tkinter (minimal, destroyed immediately)
    root = tk.Tk(); root.withdraw(); root.attributes('-topmost', True)
    path = filedialog.askopenfilename(
        title='Select pcap file',
        filetypes=[('pcap','*.pcap *.pcapng *.cap'),('All','*.*')])
    root.destroy()
    if not path:
        print("No file selected."); sys.exit(0)

    print(f"Loading: {path}")
    recs = load_pcap(path)

    # ── Colors ────────────────────────────────────────────────
    BG='#1e1e2e'; PAN='#313244'; GRD='#45475a'; TXT='#cdd6f4'
    TTL='#cba6f7'; CU='#89b4fa'; CC='#f38ba8'
    CPTP='#6c7086'; CH='#89dceb'; CZ='#f9e2af'

    # ── Figure layout ─────────────────────────────────────────
    fig = plt.figure(figsize=(14,10), facecolor=BG)
    fig.canvas.manager.set_window_title('O-RAN Frame Timing Analyzer')

    gs = gridspec.GridSpec(3, 2, figure=fig,
                           height_ratios=[4,4,0.8],
                           hspace=0.55, wspace=0.32,
                           left=0.07, right=0.97, top=0.93, bottom=0.05)
    ax_d = fig.add_subplot(gs[0,:])
    ax_h = fig.add_subplot(gs[1,0])
    ax_s = fig.add_subplot(gs[1,1]); ax_s.axis('off'); ax_s.set_facecolor(BG)
    stats_t = ax_s.text(0.03,0.97,'',transform=ax_s.transAxes,
                        fontsize=9.5,va='top',fontfamily='monospace',color=TXT,
                        bbox=dict(boxstyle='round,pad=0.6',facecolor=PAN,alpha=0.9))

    # Slider axes
    ax_sa = fig.add_subplot(gs[2,0])
    ax_sb = fig.add_subplot(gs[2,1])
    for ax in (ax_sa, ax_sb): ax.set_facecolor(PAN)

    fig.text(0.5,0.97,'O-RAN Fronthaul Frame Timing Analyzer',
             ha='center',va='top',fontsize=13,color=TTL,fontweight='bold')

    sl_a = Slider(ax_sa,'α (chips)',-50000,50000,valinit=0,valstep=1,
                  color=CU, track_color=PAN)
    sl_b = Slider(ax_sb,'β (frames)',-100,100,valinit=0,valstep=1,
                  color='#a6e3a1', track_color=PAN)
    for sl in (sl_a, sl_b):
        sl.label.set_color(TXT); sl.valtext.set_color(TXT)

    def style(ax, title, xl, yl):
        ax.set_facecolor(BG); ax.tick_params(colors=TXT,labelsize=8)
        ax.xaxis.label.set_color(TXT); ax.yaxis.label.set_color(TXT)
        ax.set_title(title,fontsize=10,pad=6,color=TXT)
        ax.set_xlabel(xl,fontsize=8); ax.set_ylabel(yl,fontsize=8)
        for sp in ax.spines.values(): sp.set_edgecolor(GRD)

    def redraw(val=None):
        alpha = int(sl_a.val); beta = int(sl_b.val)
        results, ptp_evts, dbg = analyze(recs, alpha, beta)
        ax_d.cla(); ax_h.cla()
        style(ax_d,
              f'frameId Delta (actual − expected)   α={alpha} chips   β={beta} frames',
              'Capture Time (relative ms)','Δ frameId')
        style(ax_h,'Δ frameId Histogram','Δ frameId','Count')

        if not results:
            ax_d.text(0.5,0.5,'No eCPRI after PTP ref.',
                      ha='center',va='center',color=TXT,transform=ax_d.transAxes)
            fig.canvas.draw_idle(); return

        t0  = recs[0]['ts']
        ts  = [(r['ts']-t0)/1e6 for r in results]
        d   = [r['delta'] for r in results]
        pl  = [r['plane'] for r in results]
        u_t = [ts[i] for i,p in enumerate(pl) if p=='U-Plane']
        u_d = [d[i]  for i,p in enumerate(pl) if p=='U-Plane']
        c_t = [ts[i] for i,p in enumerate(pl) if p=='C-Plane']
        c_d = [d[i]  for i,p in enumerate(pl) if p=='C-Plane']

        ax_d.grid(True,color=GRD,lw=0.4,zorder=0)
        ax_d.axhline(0,color=CZ,lw=0.9,linestyle='--',zorder=1)
        if u_t: ax_d.scatter(u_t,u_d,s=7,color=CU,alpha=0.75,zorder=3)
        if c_t: ax_d.scatter(c_t,c_d,s=7,color=CC,alpha=0.75,zorder=3)
        for ev in ptp_evts:
            ax_d.axvline((ev-t0)/1e6,color=CPTP,lw=1.0,alpha=0.7,zorder=2)

        leg=[]
        if u_t: leg.append(Line2D([0],[0],marker='o',color='w',markerfacecolor=CU,ms=6,label='U-Plane'))
        if c_t: leg.append(Line2D([0],[0],marker='o',color='w',markerfacecolor=CC,ms=6,label='C-Plane'))
        if ptp_evts: leg.append(Line2D([0],[0],color=CPTP,lw=1.5,label='PTP ref'))
        if leg: ax_d.legend(handles=leg,fontsize=8,facecolor=PAN,labelcolor=TXT,
                            framealpha=0.85,loc='upper right')

        arr=np.array(d)
        br=max(abs(arr.min()),abs(arr.max()))+1
        ax_h.grid(True,color=GRD,lw=0.4,axis='y',zorder=0)
        ax_h.hist(arr,bins=np.arange(-br-0.5,br+1.5,1),
                  color=CH,edgecolor=BG,lw=0.4,zorder=3)
        ax_h.axvline(0,color=CZ,lw=1.2,linestyle='--',zorder=4)

        zp=100.0*np.sum(arr==0)/len(arr)
        stats_t.set_text(
            f"  Packets  : {len(d)}\n"
            f"  PTP refs : {len(ptp_evts)}\n"
            f"  ─────────────\n"
            f"  Δ=0 OK   : {int(np.sum(arr==0))} ({zp:.1f}%)\n"
            f"  Δ≠0 NG   : {int(np.sum(arr!=0))}\n"
            f"  ─────────────\n"
            f"  Min Δ  : {int(arr.min())}\n"
            f"  Max Δ  : {int(arr.max())}\n"
            f"  Mean Δ : {arr.mean():.3f}\n"
            f"  Std  Δ : {arr.std():.3f}\n"
        )
        fig.canvas.draw_idle()

        # ── Print debug to terminal ────────────────────────────
        print(f"\n--- Debug (α={alpha}, β={beta}) first 20 eCPRI packets ---")
        print(f"{'#':>4} {'Plane':<8} {'PTP_sec':>18} {'GPS_sec':>18} "
              f"{'elapsed_ns':>12} {'t_input':>18} {'exp':>5} {'act':>5} {'Δ':>5}")
        shown = 0
        for r in dbg:
            if r['kind']!='eCPRI' or r['expected'] is None: continue
            ps = f"{r['curr_ptp']:.6f}" if r['curr_ptp'] else '—'
            gs = f"{r['curr_ptp']-PTP_TO_GPS:.6f}" if r['curr_ptp'] else '—'
            print(f"{r['idx']:>4} {r['plane']:<8} {ps:>18} {gs:>18} "
                  f"{str(r['elapsed_ns']):>12} {r['t']:.6f} "
                  f"{r['expected']:>5} {r['actual']:>5} {r['delta']:>+5}")
            shown+=1
            if shown>=20: break

    sl_a.on_changed(redraw)
    sl_b.on_changed(redraw)
    redraw()
    plt.show()

if __name__ == '__main__':
    main()
