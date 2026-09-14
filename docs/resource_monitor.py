# ============================================================
# resource_monitor.py
#
# Provides methodologically sound measurement of memory and CPU
# usage for a single benchmark repetition, addressing three
# reviewer concerns:
#
#   1. MEMORY  — measured as PEAK Resident Set Size (RSS) of a
#      dedicated, isolated child process, with a pre-workload
#      BASELINE RSS subtracted off. Peak RSS (rather than
#      tracemalloc) is used because tracemalloc only tracks
#      Python-object allocations and misses native memory used by
#      the underlying crypto libraries (OpenSSL bindings etc. via
#      the `cryptography` package), which is exactly where RSA/ECC
#      key material and cipher buffers actually live.
#
#   2. PROCESS ISOLATION — every repetition runs in its own fresh
#      OS process (multiprocessing, 'spawn' start method), so one
#      repetition's memory allocator state, cached keys, or GC
#      history cannot leak into the next. This is what makes the
#      "baseline subtraction" meaningful: the baseline is captured
#      from the *same* process, right after it starts and before it
#      imports/uses any crypto code.
#
#   3. CPU — sampled at an explicit, fixed, documented interval
#      (CPU_SAMPLE_INTERVAL_SEC) using psutil's process-level
#      cpu_percent(), which is normalised so 100% == one full core.
#      Both the mean and the peak sampled value are reported, along
#      with the interval and sample count, so the measurement is
#      reproducible and auditable rather than a single opaque number.
# ============================================================

import multiprocessing as mp
import threading
import time
import psutil

# Fixed CPU/RSS sampling interval, in seconds. Documented explicitly
# so results are reproducible and comparable across machines/runs.
# 50ms balances measurement resolution against sampling overhead.
CPU_SAMPLE_INTERVAL_SEC = 0.05

# How long to wait for the child process to signal readiness / finish
# putting its result on the queue, before giving up.
READY_TIMEOUT_SEC = 30
RESULT_TIMEOUT_SEC = 30


class ResourceMonitor:
    """
    Runs a workload in an isolated child process and measures its
    peak RSS (baseline-subtracted) and CPU utilisation at a fixed
    sampling interval.
    """

    def __init__(self, sample_interval=CPU_SAMPLE_INTERVAL_SEC):
        self.sample_interval = sample_interval

    def run(self, target, args=()):
        """
        Spawns `target(*args, ready_event, go_event, result_queue)`
        in an isolated child process and monitors it end-to-end.

        The target function MUST:
          - call `ready_event.set()` as its very first action (before
            importing/using any crypto code), so a clean baseline can
            be captured;
          - then call `go_event.wait()` and only start real work once
            it returns;
          - finally put its result object onto `result_queue`.

        Returns a dict with:
            result               -> whatever the child put on the queue
            baseline_rss_mb      -> RSS right after spawn, pre-workload
            peak_rss_mb          -> highest RSS observed during the run
            memory_used_mb       -> peak_rss_mb - baseline_rss_mb (>= 0)
            mean_cpu_percent     -> mean of sampled process cpu_percent()
            peak_cpu_percent     -> max of sampled process cpu_percent()
            num_cpu_samples      -> number of CPU/RSS samples taken
            sample_interval_sec  -> the sampling interval used
            wall_time_sec        -> total wall-clock time of the child run
        """
        ctx = mp.get_context('spawn')
        ready_event = ctx.Event()
        go_event = ctx.Event()
        result_queue = ctx.Queue()

        proc = ctx.Process(
            target=target,
            args=(*args, ready_event, go_event, result_queue)
        )

        start_wall = time.time()
        proc.start()

        # Wait until the child is alive and has signalled readiness,
        # BEFORE it does any real (crypto) work. This is what lets us
        # take a clean, work-free baseline measurement.
        signalled = ready_event.wait(timeout=READY_TIMEOUT_SEC)
        if not signalled:
            proc.terminate()
            proc.join()
            raise TimeoutError(
                "Child process did not signal readiness in time; "
                "aborting this repetition."
            )

        ps_proc = psutil.Process(proc.pid)

        # First call to cpu_percent() always returns a meaningless
        # value (it has no prior interval to compare against) — this
        # call exists purely to "prime" the internal counter.
        ps_proc.cpu_percent(interval=None)

        try:
            baseline_rss = ps_proc.memory_info().rss
        except psutil.NoSuchProcess:
            baseline_rss = 0

        # Release the child to begin the actual workload now that the
        # baseline has been captured.
        go_event.set()

        # Drain the result queue on a background thread CONCURRENTLY
        # with waiting for the child, rather than after. This matters
        # because multiprocessing.Queue pickles data through an OS
        # pipe with a limited buffer (commonly 64KB on Linux): if the
        # child's result is bigger than that buffer, it cannot finish
        # writing until something reads from the pipe. Calling
        # proc.join() before result_queue.get() means nothing is
        # reading yet, so on a large-enough payload (e.g. thousands of
        # per-transaction result dicts) the child hangs forever
        # writing to a full pipe, and join() hangs forever waiting for
        # a child that can never exit — a real, reproducible deadlock,
        # not just slow hardware. Reading with no timeout here is
        # intentional: the workload itself may legitimately take a
        # long time, and we must not stop listening before it's done.
        result_holder = {'value': None}

        def _drain():
            try:
                result_holder['value'] = result_queue.get()
            except Exception:
                result_holder['value'] = None

        drain_thread = threading.Thread(target=_drain, daemon=True)
        drain_thread.start()

        rss_samples = [baseline_rss]
        cpu_samples = []

        while proc.is_alive():
            time.sleep(self.sample_interval)
            try:
                cpu_samples.append(ps_proc.cpu_percent(interval=None))
                rss_samples.append(ps_proc.memory_info().rss)
            except psutil.NoSuchProcess:
                # Child exited between the is_alive() check and the
                # sample call — nothing more to measure.
                break

        proc.join()
        wall_time = time.time() - start_wall

        # By the time the child has exited, its result should already
        # be sitting in result_holder (or arrive within an instant) —
        # this join is just to reclaim the thread, not to wait on the
        # actual computation.
        drain_thread.join(timeout=RESULT_TIMEOUT_SEC)
        if drain_thread.is_alive():
            print(f"    [resource_monitor] WARNING: child process "
                  f"exited but no result was ever received (it may "
                  f"have crashed before calling result_queue.put()). "
                  f"Treating this repetition as having no data.")
        child_result = result_holder['value']

        if proc.exitcode not in (0, None) and child_result is None:
            print(f"    [resource_monitor] WARNING: child process "
                  f"exited with code {proc.exitcode} and returned no "
                  f"result.")

        peak_rss = max(rss_samples) if rss_samples else baseline_rss
        memory_used_mb = max(0.0, (peak_rss - baseline_rss) / (1024 * 1024))
        mean_cpu = (sum(cpu_samples) / len(cpu_samples)) if cpu_samples else 0.0
        peak_cpu = max(cpu_samples) if cpu_samples else 0.0

        return {
            'result': child_result,
            'baseline_rss_mb': baseline_rss / (1024 * 1024),
            'peak_rss_mb': peak_rss / (1024 * 1024),
            'memory_used_mb': memory_used_mb,
            'mean_cpu_percent': mean_cpu,
            'peak_cpu_percent': peak_cpu,
            'num_cpu_samples': len(cpu_samples),
            'sample_interval_sec': self.sample_interval,
            'wall_time_sec': wall_time,
        }


def get_system_cpu_baseline(interval=1.0):
    """
    Measures system-wide (whole-machine) CPU utilisation over a short
    idle window, BEFORE the experiment starts. This is reported
    alongside results purely as context (e.g. "the machine already had
    12% background load before we started") — it is NOT subtracted
    from per-process measurements, since psutil's per-process
    cpu_percent() is already isolated to that process and unaffected
    by other processes' usage.
    """
    return psutil.cpu_percent(interval=interval)
