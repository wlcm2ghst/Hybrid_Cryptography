# ============================================================
# visualise_enhanced.py
# Generates publication-quality coloured graphs
# matching the style shown in the reference image
#
# UPDATED to match the current summary.csv schema (peak-RSS /
# isolated-process memory columns, mean_cpu_percent instead of
# mean_cpu_usage) and to use 95% confidence-interval error bars
# (ci95_*) instead of raw standard deviation. CI is the more
# appropriate choice for a chart error bar: it answers "how
# precisely do we know the mean?" whereas SD answers "how spread
# out are individual runs?". If an older summary.csv without the
# ci95_* columns is loaded, this script automatically falls back
# to std_* so it doesn't break.
# ============================================================

import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
import matplotlib.ticker as mticker
import os
import numpy as np

matplotlib.use('Agg')

RESULTS_FOLDER = 'results'
GRAPHS_FOLDER  = 'graphs_'
SCHEMES        = ['RSA+AES-256', 'ECC+AES-256', 'ECC+ChaCha20']
VOLUMES        = [100, 500, 1000, 5000]

# ── Style matching reference image ──────────────────────────
COLORS     = ['#1f77b4', '#d62728', '#2ca02c']   # blue, red, green
MARKERS    = ['o', 's', '^']
LINESTYLES = ['-', '--', ':']
LINEWIDTHS = [2.0, 2.0, 2.0]
MARKERSIZE = 9

LABEL_FONTSIZE  = 9
AXIS_FONTSIZE   = 11
TITLE_FONTSIZE  = 12
LEGEND_FONTSIZE = 9

plt.rcParams.update({
    'font.family'      : 'DejaVu Sans',
    'axes.spines.top'  : False,
    'axes.spines.right': False,
    'axes.grid'        : True,
    'grid.color'       : '#e0e0e0',
    'grid.linestyle'   : '--',
    'grid.linewidth'   : 0.7,
    'axes.facecolor'   : 'white',
    'figure.facecolor' : 'white',
})

# ============================================================
# SETUP
# ============================================================
def setup():
    if not os.path.exists(GRAPHS_FOLDER):
        os.makedirs(GRAPHS_FOLDER)
    df = pd.read_csv(f'{RESULTS_FOLDER}/summary.csv')
    print(f"Loaded {len(df)} records from summary.csv")
    return df


def error_col(df, metric_col):
    """
    Picks the standard-deviation column for a given metric
    (std_<metric-without-mean_prefix>), so chart error bars show the
    spread of individual runs. Falls back to the 95% CI column if,
    for some reason, the std_ column isn't present in this
    summary.csv.
    """
    base = metric_col.replace('mean_', '', 1)
    std_col = f'std_{base}'
    ci_col = f'ci95_{base}'
    if std_col in df.columns:
        return std_col, 'SD'
    return ci_col, '95% CI'


# ============================================================
# HELPER — save figure
# ============================================================
def save_fig(filename):
    path = f'{GRAPHS_FOLDER}/{filename}'
    plt.savefig(path, dpi=300, bbox_inches='tight',
                facecolor='white')
    plt.close()
    print(f"  Saved: {path}")


# ============================================================
# GENERIC LINE GRAPH
# ============================================================
def plot_line(df, metric_col, ylabel, title,
              filename, label_offset=60, fmt=',.2f',
              integer_y=False):

    err_col, err_label = error_col(df, metric_col)

    fig, ax = plt.subplots(figsize=(10, 6))

    for i, scheme in enumerate(SCHEMES):
        data = df[df['scheme'] == scheme].sort_values('volume')
        x    = data['volume'].tolist()
        y    = data[metric_col].tolist()
        yerr = data[err_col].tolist()

        ax.plot(x, y,
                color=COLORS[i],
                marker=MARKERS[i],
                linestyle=LINESTYLES[i],
                linewidth=LINEWIDTHS[i],
                markersize=MARKERSIZE,
                label=scheme,
                zorder=3)

        ax.errorbar(x, y, yerr=yerr,
                    fmt='none',
                    color=COLORS[i],
                    capsize=5,
                    capthick=1.2,
                    elinewidth=1,
                    alpha=0.4,
                    zorder=2)

        # Data labels
        for xi, yi in zip(x, y):
            ax.annotate(
                f'{yi:{fmt}}',
                xy=(xi, yi),
                xytext=(0, label_offset),
                textcoords='offset points',
                ha='center', va='bottom',
                fontsize=LABEL_FONTSIZE,
                color=COLORS[i],
                fontweight='bold'
            )

    ax.set_title(title, fontsize=TITLE_FONTSIZE,
                 fontweight='bold', pad=14)
    ax.set_xlabel('Transaction Volume', fontsize=AXIS_FONTSIZE)
    ax.set_ylabel(ylabel, fontsize=AXIS_FONTSIZE)
    ax.set_xticks(VOLUMES)
    ax.set_xticklabels([str(v) for v in VOLUMES])
    ax.legend(fontsize=LEGEND_FONTSIZE,
              frameon=True, fancybox=False,
              edgecolor='#cccccc',
              loc='best')
    if integer_y:
        ax.yaxis.set_major_formatter(
            mticker.FuncFormatter(lambda x, _: f'{int(x):,}'))
    # Note error bar meaning (CI vs SD) in a small caption so the
    # figure is self-explanatory if it's copied out on its own.
    ax.annotate(f'Error bars: {err_label}', xy=(0, 0),
                xycoords='axes fraction', xytext=(0, -34),
                textcoords='offset points', fontsize=7.5,
                color='#888888', ha='left')
    plt.tight_layout()
    save_fig(filename)


# ============================================================
# CHART 1 — KEY GENERATION TIME
# ============================================================
def plot_key_gen_time(df):
    print("\nKey Generation Time...")
    plot_line(
        df,
        metric_col  = 'mean_key_gen_time',
        ylabel      = 'Mean Key Generation Time (ms)',
        title       = 'Key Generation Time vs Transaction Volume',
        filename    = 'key_gen_time.png',
        label_offset= 8,
        fmt         = ',.2f'
    )


# ============================================================
# CHART 2 — ENCRYPTION TIME
# ============================================================
def plot_encryption_time(df):
    print("\nEncryption Time...")
    plot_line(
        df,
        metric_col  = 'mean_encryption_time',
        ylabel      = 'Mean Encryption Time (ms)',
        title       = 'Encryption Time vs Transaction Volume',
        filename    = 'encryption_time.png',
        label_offset= 6,
        fmt         = ',.4f'
    )


# ============================================================
# CHART 3 — DECRYPTION TIME
# ============================================================
def plot_decryption_time(df):
    print("\nDecryption Time...")
    plot_line(
        df,
        metric_col  = 'mean_decryption_time',
        ylabel      = 'Mean Decryption Time (ms)',
        title       = 'Decryption Time vs Transaction Volume',
        filename    = 'decryption_time.png',
        label_offset= 6,
        fmt         = ',.4f'
    )


# ============================================================
# CHART 4 — THROUGHPUT (matches reference image exactly)
# ============================================================
def plot_throughput(df):
    print("\nThroughput...")

    err_col, err_label = error_col(df, 'mean_throughput')
    fig, ax = plt.subplots(figsize=(10, 6))

    for i, scheme in enumerate(SCHEMES):
        data = df[df['scheme'] == scheme].sort_values('volume')
        x    = data['volume'].tolist()
        y    = data['mean_throughput'].tolist()
        yerr = data[err_col].tolist()

        ax.plot(x, y,
                color=COLORS[i],
                marker=MARKERS[i],
                linestyle=LINESTYLES[i],
                linewidth=LINEWIDTHS[i],
                markersize=MARKERSIZE,
                label=scheme,
                zorder=3)

        ax.errorbar(x, y, yerr=yerr,
                    fmt='none',
                    color=COLORS[i],
                    capsize=5,
                    capthick=1.2,
                    elinewidth=1,
                    alpha=0.4,
                    zorder=2)

        # Adaptive label offset
        for j, (xi, yi) in enumerate(zip(x, y)):
            # RSA values go below, ECC values go above
            offset = -18 if i == 0 else 10
            va     = 'top' if i == 0 else 'bottom'
            ax.annotate(
                f'{yi:,.2f}',
                xy=(xi, yi),
                xytext=(0, offset),
                textcoords='offset points',
                ha='center', va=va,
                fontsize=LABEL_FONTSIZE,
                color=COLORS[i],
                fontweight='bold'
            )

    ax.set_title(
        'Mean Throughput vs Transaction Volume',
        fontsize=TITLE_FONTSIZE, fontweight='bold', pad=14)
    ax.set_xlabel('Transaction Volume', fontsize=AXIS_FONTSIZE)
    ax.set_ylabel('Mean Throughput (transactions/second)',
                  fontsize=AXIS_FONTSIZE)
    ax.set_xticks(VOLUMES)
    ax.set_xticklabels([str(v) for v in VOLUMES])
    ax.yaxis.set_major_formatter(
        mticker.FuncFormatter(lambda x, _: f'{int(x):,}'))
    ax.legend(fontsize=LEGEND_FONTSIZE,
              frameon=True, fancybox=False,
              edgecolor='#cccccc',
              loc='center right')
    ax.annotate(f'Error bars: {err_label}', xy=(0, 0),
                xycoords='axes fraction', xytext=(0, -34),
                textcoords='offset points', fontsize=7.5,
                color='#888888', ha='left')
    plt.tight_layout()
    save_fig('throughput.png')


# ============================================================
# CHART 5 — MEMORY CONSUMPTION (peak RSS minus baseline)
# ============================================================
def plot_memory(df):
    print("\nMemory Consumption...")
    plot_line(
        df,
        metric_col  = 'mean_memory_used_mb',
        ylabel      = 'Mean Memory Used (MB, peak RSS − baseline)',
        title       = 'Memory Consumption vs Transaction Volume',
        filename    = 'memory.png',
        label_offset= 6,
        fmt         = ',.4f'
    )


# ============================================================
# CHART 6 — CPU USAGE
# ============================================================
def plot_cpu(df):
    print("\nCPU Usage...")
    plot_line(
        df,
        metric_col  = 'mean_cpu_percent',
        ylabel      = 'Mean CPU Usage (%)',
        title       = 'Figure 4.6: CPU Usage vs Transaction Volume',
        filename    = 'fig4_6_cpu.png',
        label_offset= 6,
        fmt         = ',.2f'
    )


# ============================================================
# CHART 7 — GROUPED BAR CHART AT 1000 TRANSACTIONS
# ============================================================
def plot_grouped_bar(df):
    print("\nGrouped Bar Chart at 1,000 Tx...")

    subset = df[df['volume'] == 1000].copy()

    metrics = [
        ('mean_encryption_time', 'Enc Time (ms)'),
        ('mean_decryption_time', 'Dec Time (ms)'),
        ('mean_throughput',      'Throughput\n(tx/s)'),
        ('mean_cpu_percent',     'CPU Usage (%)'),
    ]

    x      = np.arange(len(metrics))
    width  = 0.25
    fig, ax = plt.subplots(figsize=(11, 6))

    for i, scheme in enumerate(SCHEMES):
        row    = subset[subset['scheme'] == scheme]
        values = [row[m].values[0] for m, _ in metrics]
        bars   = ax.bar(x + i * width, values,
                        width,
                        label=scheme,
                        color=COLORS[i],
                        edgecolor='white',
                        linewidth=0.8,
                        zorder=3)
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2,
                    h * 1.02,
                    f'{h:.2f}',
                    ha='center', va='bottom',
                    fontsize=7.5,
                    color=COLORS[i],
                    fontweight='bold')

    ax.set_title(
        'Performance Comparison at 1,000 Transactions',
        fontsize=TITLE_FONTSIZE, fontweight='bold', pad=14)
    ax.set_xlabel('Performance Metric', fontsize=AXIS_FONTSIZE)
    ax.set_ylabel('Value', fontsize=AXIS_FONTSIZE)
    ax.set_xticks(x + width)
    ax.set_xticklabels([label for _, label in metrics],
                       fontsize=10)
    ax.legend(fontsize=LEGEND_FONTSIZE,
              frameon=True, fancybox=False,
              edgecolor='#cccccc')
    plt.tight_layout()
    save_fig('grouped_bar_1000.png')


# ============================================================
# CHART 8 — KEY GENERATION BAR CHART COMPARISON
# ============================================================
def plot_key_gen_bar(df):
    print("\nGenerating Key Generation Bar Chart...")

    subset = df[df['volume'] == 1000].copy()
    fig, ax = plt.subplots(figsize=(9, 5))

    bars = ax.bar(
        subset['scheme'],
        subset['mean_key_gen_time'],
        color=COLORS,
        edgecolor='white',
        linewidth=0.8,
        width=0.5,
        zorder=3
    )

    for bar, color in zip(bars, COLORS):
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2,
                h * 1.02,
                f'{h:.2f} ms',
                ha='center', va='bottom',
                fontsize=10,
                fontweight='bold',
                color=color)

    ax.set_title(
        'Key Generation Time Comparison (1,000 Transactions)',
        fontsize=TITLE_FONTSIZE, fontweight='bold', pad=14)
    ax.set_xlabel('Hybrid Scheme', fontsize=AXIS_FONTSIZE)
    ax.set_ylabel('Mean Key Generation Time (ms)',
                  fontsize=AXIS_FONTSIZE)
    plt.tight_layout()
    save_fig('key_gen_bar.png')


# ============================================================
# PRINT SUMMARY TABLE
# ============================================================
def print_summary_table(df):
    print("\n" + "="*72)
    print("SUMMARY STATISTICS")
    print("="*72)
    for volume in VOLUMES:
        print(f"\nVolume: {volume} transactions")
        print(f"{'Scheme':<18} {'KeyGen(ms)':>12} "
              f"{'Enc(ms)':>10} {'Dec(ms)':>10} "
              f"{'Tput(tx/s)':>12} {'Mem(MB)':>10} "
              f"{'CPU(%)':>8}")
        print("-"*72)
        for scheme in SCHEMES:
            row = df[(df['scheme']==scheme) &
                     (df['volume']==volume)]
            if len(row) > 0:
                print(
                    f"{scheme:<18} "
                    f"{row['mean_key_gen_time'].values[0]:>12.2f} "
                    f"{row['mean_encryption_time'].values[0]:>10.4f} "
                    f"{row['mean_decryption_time'].values[0]:>10.4f} "
                    f"{row['mean_throughput'].values[0]:>12.2f} "
                    f"{row['mean_memory_used_mb'].values[0]:>10.4f} "
                    f"{row['mean_cpu_percent'].values[0]:>8.2f}"
                )


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("ENHANCED COLOURED VISUALISATION")
    print("=" * 60)

    df = setup()

    if df['volume'].nunique() < len(VOLUMES) or not set(VOLUMES).issubset(set(df['volume'].unique())):
        print("\n  NOTE: summary.csv doesn't contain all of the "
              f"expected volumes {VOLUMES} — charts will only show "
              "whatever volumes are actually present.")

    plot_key_gen_time(df)
    plot_encryption_time(df)
    plot_decryption_time(df)
    plot_throughput(df)
    plot_memory(df)
    plot_cpu(df)
    plot_grouped_bar(df)
    plot_key_gen_bar(df)
    print_summary_table(df)

    print(f"\n{'='*60}")
    print("ALL GRAPHS GENERATED")
    print(f"{'='*60}")
    print(f"Saved in: ./{GRAPHS_FOLDER}/")
    print("\nFigures generated:")
    print("  Key Generation Time vs Volume")
    print("  Encryption Time vs Volume")
    print("  Decryption Time vs Volume")
    print("  Throughput vs Volume")
    print("  Memory Consumption vs Volume")
    print("  CPU Usage vs Volume")
    print("  Grouped Bar at 1,000 Transactions")
    print("  Key Generation Bar Chart")