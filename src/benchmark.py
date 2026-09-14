# ============================================================
# benchmark.py
# Runs all experiments across all schemes and volumes
# Saves results to CSV files for analysis
#
# METHODOLOGY NOTES (read before changing constants below)
# ------------------------------------------------------------
# Memory:
#   Each repetition is executed in its own isolated OS process
#   (see resource_monitor.py). We report PEAK Resident Set Size
#   (RSS) for that process, minus a BASELINE RSS captured for the
#   same process immediately after it starts and before it does
#   any crypto work. This isolates the measurement to the scheme
#   under test and avoids cross-repetition contamination (cached
#   keys, warmed allocators, GC state) that a shared long-lived
#   process would introduce. It also captures native (non-Python)
#   memory used by the underlying crypto libraries, which
#   tracemalloc alone would miss.
#
# CPU:
#   Sampled at a fixed, explicit interval (CPU_SAMPLE_INTERVAL_SEC,
#   currently 50ms) using psutil's per-process cpu_percent(), which
#   is normalised so 100% == one fully-loaded logical core. We
#   report both the mean and peak sampled value per repetition,
#   plus the interval and sample count used, so results are
#   auditable and reproducible. A one-off, informational
#   whole-machine idle CPU baseline is also recorded at the start
#   of the run for context (see SYSTEM_CPU_BASELINE below).
#
# Aggregation / repetitions:
#   Timing (key-gen/encryption/decryption/throughput) is recorded
#   per transaction, per repetition, as before.
#   Memory and CPU are recorded ONCE PER REPETITION (not once per
#   transaction) because they describe the isolated process running
#   the whole batch, not any single transaction. To avoid inflating
#   or (more importantly) silently DEFLATING the reported variance,
#   summary statistics for memory/CPU are computed over the
#   REPETITIONS independent per-repetition values (see
#   results/resource_usage.csv and generate_summary below) rather
#   than over the broadcasted, duplicated per-transaction columns.
#   REPETITIONS (currently 5) is the sample size behind every
#   mean +/- std reported in summary.csv.
# ============================================================

import time
import os
import importlib
import pandas as pd
from transaction_generator import generate_transaction_batch, transaction_to_bytes
from resource_monitor import ResourceMonitor, CPU_SAMPLE_INTERVAL_SEC, get_system_cpu_baseline

# ============================================================
# 95% CONFIDENCE INTERVAL HELPERS
# ------------------------------------------------------------
# Uses a standard two-tailed 95% t-distribution lookup table
# rather than requiring scipy as a dependency. The t-distribution
# (not a normal/Z approximation) matters here specifically because
# REPETITIONS defaults to 5 — at that sample size the t-critical
# value (2.571) is meaningfully wider than the Z approximation
# (1.96), and using Z would understate the true interval.
# ============================================================

_T_TABLE_95 = {
    1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571,
    6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
    11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131,
    16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086,
    21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060,
    26: 2.056, 27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042,
}


def _t_critical_95(df):
    """Two-tailed 95% critical t-value for `df` degrees of freedom.
    Falls back to the normal approximation (1.96) once df > 30, where
    the t- and Z-distributions have converged closely enough that the
    difference no longer matters in practice."""
    if df is None or df <= 0:
        return float('nan')
    if df in _T_TABLE_95:
        return _T_TABLE_95[df]
    if df > 30:
        return 1.960
    # df between table entries shouldn't happen (table is contiguous
    # 1-30), but fall back to the nearest entry defensively.
    return _T_TABLE_95[min(_T_TABLE_95.keys(), key=lambda k: abs(k - df))]


def ci95_margin(std, n):
    """
    95% confidence interval half-width: t_(0.975, n-1) * std / sqrt(n).
    Add/subtract this margin from the mean to get the CI bounds.
    Returns NaN when n <= 1 (a CI is undefined with a single sample).
    """
    if n is None or n <= 1 or pd.isna(std):
        return float('nan')
    return _t_critical_95(n - 1) * std / (n ** 0.5)

# ============================================================
# EXPERIMENT CONFIGURATION
# ============================================================

# Map scheme name -> importable module name (NOT the function object).
# We re-import the module fresh inside each isolated child process so
# that no module-level state (cached keys, warmed-up contexts, etc.)
# survives between repetitions.
SCHEMES = {
    'RSA+AES-256': 'rsa_aes',
    'ECC+AES-256': 'ecc_aes',
    'ECC+ChaCha20': 'ecc_chacha20',
}

VOLUMES = [100, 500, 1000, 5000]
REPETITIONS = 5
RESULTS_FOLDER = 'results'


# ============================================================
# SETUP RESULTS FOLDER
# ============================================================

def setup_results_folder():
    """Create results folder if it doesn't exist"""
    if not os.path.exists(RESULTS_FOLDER):
        os.makedirs(RESULTS_FOLDER)
        print(f"Created results folder: {RESULTS_FOLDER}")


# ============================================================
# ISOLATED CHILD-PROCESS WORKER
# (must be a module-level function so it can be pickled by
#  multiprocessing's 'spawn' start method)
# ============================================================

def _isolated_worker(scheme_module_name, volume, ready_event, go_event, result_queue):
    """
    Runs entirely inside a fresh, isolated child process.

    Order matters: we signal readiness BEFORE importing the crypto
    module or generating any data, so the parent can capture a clean,
    work-free baseline RSS. We only start real work after the parent
    releases us via `go_event`.
    """
    # Signal readiness immediately — no imports, no allocations yet.
    ready_event.set()
    go_event.wait(timeout=30)

    # Re-import fresh inside this process (deliberately not imported
    # at module load time / from the parent) so this repetition starts
    # with no leftover state from any previous repetition.
    from transaction_generator import generate_transaction_batch, transaction_to_bytes
    scheme_module = importlib.import_module(scheme_module_name)
    process_fn = scheme_module.process_transaction

    transactions = generate_transaction_batch(volume)

    tx_results = []
    for i, transaction in enumerate(transactions):
        transaction_bytes = transaction_to_bytes(transaction)
        r = process_fn(transaction_bytes)
        tx_results.append({
            'transaction_id': i + 1,
            'key_gen_time': r['key_gen_time'],
            'encryption_time': r['encryption_time'],
            'decryption_time': r['decryption_time'],
            'integrity_verified': r['integrity_verified'],
        })
        # Note: any 'memory_used' / 'cpu_usage' keys a scheme module
        # returns are intentionally ignored here — those are now
        # measured externally, uniformly, by resource_monitor.py for
        # every scheme, rather than self-reported per scheme.

    result_queue.put(tx_results)


# ============================================================
# RUN SINGLE EXPERIMENT (one isolated repetition)
# ============================================================

def run_single_experiment(scheme_name, scheme_module_name, volume, repetition):
    """
    Run a single, isolated repetition for one scheme at one volume.

    Returns:
        tx_rows        -> list of per-transaction result dicts
        resource_row   -> single dict with this repetition's
                           memory/CPU measurement
    """
    print(f"    Running {scheme_name} | "
          f"Volume: {volume} | "
          f"Repetition: {repetition}/{REPETITIONS}...")

    monitor = ResourceMonitor(sample_interval=CPU_SAMPLE_INTERVAL_SEC)
    run_data = monitor.run(_isolated_worker, args=(scheme_module_name, volume))

    tx_results = run_data['result'] or []
    if not tx_results:
        print(f"    WARNING: no transaction results returned for "
              f"{scheme_name} | Volume: {volume} | Rep: {repetition}. "
              f"Skipping this repetition's rows.")

    total_encryption_time = sum(r['encryption_time'] for r in tx_results)
    total_decryption_time = sum(r['decryption_time'] for r in tx_results)
    total_time_seconds = (total_encryption_time + total_decryption_time) / 1000
    throughput = volume / total_time_seconds if total_time_seconds > 0 else 0

    tx_rows = []
    for r in tx_results:
        tx_rows.append({
            'scheme': scheme_name,
            'volume': volume,
            'repetition': repetition,
            'transaction_id': r['transaction_id'],
            'key_gen_time': r['key_gen_time'],
            'encryption_time': r['encryption_time'],
            'decryption_time': r['decryption_time'],
            'integrity_verified': r['integrity_verified'],
            'throughput': throughput,
        })

    resource_row = {
        'scheme': scheme_name,
        'volume': volume,
        'repetition': repetition,
        'baseline_memory_mb': run_data['baseline_rss_mb'],
        'peak_memory_mb': run_data['peak_rss_mb'],
        'memory_used_mb': run_data['memory_used_mb'],
        'mean_cpu_percent': run_data['mean_cpu_percent'],
        'peak_cpu_percent': run_data['peak_cpu_percent'],
        'cpu_sample_interval_sec': run_data['sample_interval_sec'],
        'num_cpu_samples': run_data['num_cpu_samples'],
        'wall_time_sec': run_data['wall_time_sec'],
        'throughput': throughput,
    }

    return tx_rows, resource_row


# ============================================================
# RUN ALL EXPERIMENTS
# ============================================================

def run_all_experiments():
    """
    Run complete benchmarking experiment for all schemes,
    volumes and repetitions.
    """
    setup_results_folder()

    print("\n" + "=" * 60)
    print("HYBRID CRYPTOGRAPHY BENCHMARKING EXPERIMENT")
    print("=" * 60)
    print(f"Schemes            : {list(SCHEMES.keys())}")
    print(f"Volumes            : {VOLUMES}")
    print(f"Repetitions        : {REPETITIONS}")
    print(f"CPU sample interval: {CPU_SAMPLE_INTERVAL_SEC * 1000:.0f} ms")
    print(f"Memory metric      : peak RSS of an isolated child process, "
          f"minus pre-workload baseline RSS")
    print(f"Process isolation  : each repetition runs in its own "
          f"spawned OS process")
    print(f"Results            : ./{RESULTS_FOLDER}/")
    print("=" * 60)

    system_cpu_baseline = get_system_cpu_baseline(interval=1.0)
    print(f"System-wide idle CPU baseline (informational only, not "
          f"subtracted): {system_cpu_baseline:.2f}%\n")

    all_tx_results = []
    all_resource_rows = []
    experiment_count = 0
    total_experiments = len(SCHEMES) * len(VOLUMES) * REPETITIONS

    start_total = time.time()

    for scheme_name, scheme_module_name in SCHEMES.items():
        print(f"\n{'='*60}")
        print(f"SCHEME: {scheme_name}")
        print(f"{'='*60}")

        for volume in VOLUMES:
            print(f"\n  Volume: {volume} transactions")

            volume_tx_results = []
            volume_resource_rows = []

            for rep in range(1, REPETITIONS + 1):
                tx_rows, resource_row = run_single_experiment(
                    scheme_name, scheme_module_name, volume, rep
                )
                volume_tx_results.extend(tx_rows)
                volume_resource_rows.append(resource_row)
                experiment_count += 1

                progress = (experiment_count / total_experiments) * 100
                print(f"     Complete "
                      f"({progress:.1f}% overall) — "
                      f"peak memory: {resource_row['peak_memory_mb']:.2f} MB "
                      f"(baseline {resource_row['baseline_memory_mb']:.2f} MB), "
                      f"mean CPU: {resource_row['mean_cpu_percent']:.1f}%")

            all_tx_results.extend(volume_tx_results)
            all_resource_rows.extend(volume_resource_rows)

            # Save intermediate results per scheme per volume
            safe_name = scheme_name.replace('+', '_')
            df_volume = pd.DataFrame(volume_tx_results)
            filename = f"{RESULTS_FOLDER}/{safe_name}_{volume}.csv"
            df_volume.to_csv(filename, index=False)
            print(f"   Saved: {filename}")

            df_volume_resources = pd.DataFrame(volume_resource_rows)
            resource_filename = f"{RESULTS_FOLDER}/{safe_name}_{volume}_resources.csv"
            df_volume_resources.to_csv(resource_filename, index=False)
            print(f"   Saved: {resource_filename}")

    # Save complete results to single CSVs
    df_all = pd.DataFrame(all_tx_results)
    df_all.to_csv(f'{RESULTS_FOLDER}/all_results.csv', index=False)

    df_resources = pd.DataFrame(all_resource_rows)
    df_resources.to_csv(f'{RESULTS_FOLDER}/resource_usage.csv', index=False)

    end_total = time.time()
    total_time = end_total - start_total

    print(f"\n{'='*60}")
    print(f"ALL EXPERIMENTS COMPLETE")
    print(f"{'='*60}")
    print(f"Total time     : {total_time:.2f} seconds "
          f"({total_time/60:.2f} minutes)")
    print(f"Timing results : {RESULTS_FOLDER}/all_results.csv")
    print(f"Resource usage : {RESULTS_FOLDER}/resource_usage.csv "
          f"(one row per repetition)")
    print(f"Total tx rows  : {len(all_tx_results)}")
    print(f"Total reps     : {len(all_resource_rows)}")

    return df_all, df_resources


# ============================================================
# GENERATE SUMMARY STATISTICS
# ============================================================

def generate_summary(df_tx, df_resources):
    """
    Generate summary statistics from experimental results.

    Timing stats are aggregated across all transactions (per scheme,
    per volume) — their 95% CI uses n = number of transactions.
    Throughput/memory/CPU stats are aggregated across the REPETITIONS
    independent per-repetition measurements in df_resources, NOT
    across the per-transaction rows in df_tx — computing std() on a
    value that is identical across every transaction within a
    repetition would silently understate the true run-to-run
    variance, and their 95% CI uses n = REPETITIONS accordingly.
    """
    print(f"\n{'='*60}")
    print("SUMMARY STATISTICS")
    print(f"{'='*60}")

    summary_data = []

    schemes = df_tx['scheme'].unique()
    volumes = sorted(df_tx['volume'].unique())

    for scheme in schemes:
        for volume in volumes:
            tx_subset = df_tx[
                (df_tx['scheme'] == scheme) & (df_tx['volume'] == volume)
            ]
            res_subset = df_resources[
                (df_resources['scheme'] == scheme) & (df_resources['volume'] == volume)
            ]

            n_tx = len(tx_subset)
            n_reps = len(res_subset)

            summary = {
                'scheme': scheme,
                'volume': volume,
                'n_repetitions': n_reps,
                'n_transactions': n_tx,

                'mean_key_gen_time': tx_subset['key_gen_time'].mean(),
                'std_key_gen_time': tx_subset['key_gen_time'].std(),
                'mean_encryption_time': tx_subset['encryption_time'].mean(),
                'std_encryption_time': tx_subset['encryption_time'].std(),
                'mean_decryption_time': tx_subset['decryption_time'].mean(),
                'std_decryption_time': tx_subset['decryption_time'].std(),
                'mean_throughput': res_subset['throughput'].mean(),
                'std_throughput': res_subset['throughput'].std(),

                # Memory/CPU: aggregated over the REPETITIONS
                # per-repetition measurements (n = n_repetitions),
                # not over per-transaction rows.
                'mean_peak_memory_mb': res_subset['peak_memory_mb'].mean(),
                'std_peak_memory_mb': res_subset['peak_memory_mb'].std(),
                'mean_baseline_memory_mb': res_subset['baseline_memory_mb'].mean(),
                'mean_memory_used_mb': res_subset['memory_used_mb'].mean(),
                'std_memory_used_mb': res_subset['memory_used_mb'].std(),
                'mean_cpu_percent': res_subset['mean_cpu_percent'].mean(),
                'std_cpu_percent': res_subset['mean_cpu_percent'].std(),
                'mean_peak_cpu_percent': res_subset['peak_cpu_percent'].mean(),
                'cpu_sample_interval_sec': (
                    res_subset['cpu_sample_interval_sec'].iloc[0]
                    if n_reps else CPU_SAMPLE_INTERVAL_SEC
                ),
            }

            # 95% confidence interval half-widths. Timing metrics use
            # n_tx (per-transaction sample); throughput/memory/CPU use
            # n_reps (per-repetition sample) — see docstring above.
            summary['ci95_key_gen_time'] = ci95_margin(summary['std_key_gen_time'], n_tx)
            summary['ci95_encryption_time'] = ci95_margin(summary['std_encryption_time'], n_tx)
            summary['ci95_decryption_time'] = ci95_margin(summary['std_decryption_time'], n_tx)
            summary['ci95_throughput'] = ci95_margin(summary['std_throughput'], n_reps)
            summary['ci95_peak_memory_mb'] = ci95_margin(summary['std_peak_memory_mb'], n_reps)
            summary['ci95_memory_used_mb'] = ci95_margin(summary['std_memory_used_mb'], n_reps)
            summary['ci95_cpu_percent'] = ci95_margin(summary['std_cpu_percent'], n_reps)

            summary_data.append(summary)

            print(f"\n{scheme} | Volume: {volume} "
                  f"(n_reps={summary['n_repetitions']}, n_tx={summary['n_transactions']})")
            print(f"  Key Gen Time    : "
                  f"{summary['mean_key_gen_time']:.4f} ms "
                  f"(SD ±{summary['std_key_gen_time']:.4f}, "
                  f"95% CI ±{summary['ci95_key_gen_time']:.4f})")
            print(f"  Encryption Time : "
                  f"{summary['mean_encryption_time']:.4f} ms "
                  f"(SD ±{summary['std_encryption_time']:.4f}, "
                  f"95% CI ±{summary['ci95_encryption_time']:.4f})")
            print(f"  Decryption Time : "
                  f"{summary['mean_decryption_time']:.4f} ms "
                  f"(SD ±{summary['std_decryption_time']:.4f}, "
                  f"95% CI ±{summary['ci95_decryption_time']:.4f})")
            print(f"  Throughput      : "
                  f"{summary['mean_throughput']:.4f} tx/sec "
                  f"(SD ±{summary['std_throughput']:.4f}, "
                  f"95% CI ±{summary['ci95_throughput']:.4f})")
            print(f"  Peak Memory     : "
                  f"{summary['mean_peak_memory_mb']:.4f} MB "
                  f"(SD ±{summary['std_peak_memory_mb']:.4f}, "
                  f"95% CI ±{summary['ci95_peak_memory_mb']:.4f}), "
                  f"baseline {summary['mean_baseline_memory_mb']:.4f} MB")
            print(f"  Memory Used     : "
                  f"{summary['mean_memory_used_mb']:.4f} MB "
                  f"(SD ±{summary['std_memory_used_mb']:.4f}, "
                  f"95% CI ±{summary['ci95_memory_used_mb']:.4f}) "
                  f"[peak - baseline]")
            print(f"  CPU Usage (mean): "
                  f"{summary['mean_cpu_percent']:.4f} % "
                  f"(SD ±{summary['std_cpu_percent']:.4f}, "
                  f"95% CI ±{summary['ci95_cpu_percent']:.4f}), "
                  f"peak {summary['mean_peak_cpu_percent']:.4f} %, "
                  f"sampled every {summary['cpu_sample_interval_sec']*1000:.0f} ms")

    # Save summary to CSV
    df_summary = pd.DataFrame(summary_data)
    df_summary.to_csv(f'{RESULTS_FOLDER}/summary.csv', index=False)
    print(f"\n Summary saved: {RESULTS_FOLDER}/summary.csv")

    return df_summary


# ============================================================
# MAIN — Run everything
# ============================================================
if __name__ == "__main__":
    print("\n  WARNING: This experiment will take several")
    print("minutes to complete especially at 5000 transactions.")
    print("Each repetition now runs in its own isolated process,")
    print("which adds a small amount of process-startup overhead")
    print("per repetition in exchange for clean, uncontaminated")
    print("memory/CPU measurements.")
    print("Please do not close VS Code while it is running.\n")

    input("Press ENTER to start the experiment...")

    # Run all experiments
    df_tx_results, df_resource_results = run_all_experiments()

    # Generate summary statistics
    df_summary = generate_summary(df_tx_results, df_resource_results)

    print(f"\n{'='*60}")
    print(" ALL DONE!")
    print(f"{'='*60}")
    print("Your results are saved in the 'results' folder:")
    print("  - all_results.csv      (per-transaction timing/integrity)")
    print("  - resource_usage.csv   (per-repetition memory/CPU)")
    print("  - summary.csv          (aggregated mean ± std)")
    print("Next step: Run visualise.py to generate your graphs.")