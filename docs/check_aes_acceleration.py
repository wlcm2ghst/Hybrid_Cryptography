# ============================================================
# check_aes_acceleration.py
#
# Checks whether AES hardware acceleration (AES-NI on x86, or the
# ARMv8 Cryptography Extensions on ARM) is active on this machine,
# using TWO independent methods, because either one alone can
# mislead:
#
#   1. CPU FLAG CHECK — reads the CPU's advertised instruction set
#      (via `py-cpuinfo`, cross-platform). This tells you whether the
#      *hardware* supports AES acceleration at all. It does NOT tell
#      you whether the specific crypto library you're using actually
#      exercises that support — a library can be compiled without
#      AES-NI codepaths even on hardware that has it.
#
#   2. EMPIRICAL THROUGHPUT TEST — actually encrypts data with the
#      exact library your benchmark uses (pycryptodome's AES-256-CBC,
#      as used in rsa_aes.py / ecc_aes.py) and measures MB/s. AES-NI
#      acceleration typically produces single-core CBC-encrypt
#      throughput in the hundreds of MB/s to low GB/s range; a pure
#      software (T-table) implementation is typically well under
#      300 MB/s. This is what actually happened during your benchmark
#      run, regardless of what the CPU flag says is theoretically
#      possible.
#
# The two are combined into one verdict. Run this ONCE per machine
# you benchmark on (it's a fixed hardware/software characteristic,
# not something that varies per repetition) and record the verdict
# alongside your results — see benchmark_protocol.md §12.
# ============================================================

import json
import platform
import time

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Empirical throughput thresholds (single-core AES-256-CBC encrypt,
# pycryptodome). These are approximate reference points from published
# AES-NI vs. software-AES benchmarks, not a precise calibration for
# every CPU — treat the empirical result as corroborating evidence
# alongside the CPU flag check, not as a standalone proof either way.
THROUGHPUT_LIKELY_ACCELERATED_MB_S = 500.0
THROUGHPUT_LIKELY_SOFTWARE_MB_S = 250.0


def check_cpu_flag():
    """
    Returns (supported: bool | None, flag_name: str | None, raw_flags: list)
    `supported` is None if detection itself failed (rare, but possible
    on unusual platforms py-cpuinfo doesn't recognise) — this must be
    reported as "unknown", not silently treated as False.
    """
    try:
        import cpuinfo
        info = cpuinfo.get_cpu_info()
        flags = info.get('flags', []) or []
        # x86: 'aes'. ARM: often reported as 'aes' too under py-cpuinfo,
        # sometimes as part of 'crypto' extensions naming.
        for candidate in ('aes', 'aes-ni', 'aesni'):
            if candidate in flags:
                return True, candidate, flags
        return False, None, flags
    except Exception as e:
        print(f"  [!] CPU flag detection failed ({e}). "
              f"py-cpuinfo may not support this platform.")
        return None, None, []


def measure_aes_throughput(data_size_mb=64, iterations=3):
    """
    Encrypts `data_size_mb` MB of data with AES-256-CBC (pycryptodome
    — the exact code path used by rsa_aes.py / ecc_aes.py) and returns
    the mean throughput in MB/s across `iterations` runs.
    """
    key = get_random_bytes(32)
    iv = get_random_bytes(16)
    data = get_random_bytes(data_size_mb * 1024 * 1024)
    # Pad to a block boundary once, outside the timed region — we're
    # measuring raw cipher throughput, not padding overhead.
    if len(data) % AES.block_size != 0:
        data = data[: len(data) - (len(data) % AES.block_size)]

    throughputs = []
    for _ in range(iterations):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        t0 = time.perf_counter()
        cipher.encrypt(data)
        t1 = time.perf_counter()
        mb_per_sec = data_size_mb / (t1 - t0)
        throughputs.append(mb_per_sec)

    return sum(throughputs) / len(throughputs), throughputs


def main():
    print("=" * 60)
    print("AES HARDWARE ACCELERATION CHECK")
    print("=" * 60)
    print(f"Platform: {platform.platform()}")
    print(f"Processor (platform module): {platform.processor() or '(not reported by OS)'}")
    print()

    # ---- Method 1: CPU flag ----
    print("Method 1 — CPU instruction-set flag")
    print("-" * 60)
    flag_supported, flag_name, all_flags = check_cpu_flag()
    if flag_supported is True:
        print(f"  CPU advertises AES acceleration support (flag: '{flag_name}').")
    elif flag_supported is False:
        print(f"  CPU does NOT advertise an AES acceleration flag.")
        aes_related = [f for f in all_flags if 'aes' in f.lower() or 'crypto' in f.lower()]
        if aes_related:
            print(f"  (Related flags found, for reference: {aes_related})")
    else:
        print(f"  Could not determine CPU flag support on this platform.")

    # ---- Method 2: empirical throughput ----
    print("\nMethod 2 — empirical AES-256-CBC throughput "
          "(pycryptodome, same code path as rsa_aes.py / ecc_aes.py)")
    print("-" * 60)
    print("  Encrypting 64MB buffers, 3 runs...")
    mean_throughput, samples = measure_aes_throughput()
    print(f"  Mean throughput: {mean_throughput:,.1f} MB/s "
          f"(individual runs: {[f'{s:,.1f}' for s in samples]})")

    if mean_throughput >= THROUGHPUT_LIKELY_ACCELERATED_MB_S:
        throughput_verdict = "consistent with hardware acceleration being ACTIVE"
    elif mean_throughput <= THROUGHPUT_LIKELY_SOFTWARE_MB_S:
        throughput_verdict = "consistent with a SOFTWARE-ONLY (unaccelerated) implementation"
    else:
        throughput_verdict = "INCONCLUSIVE (falls between the reference thresholds)"
    print(f"  -> {throughput_verdict}")

    # ---- Combined verdict ----
    print("\n" + "=" * 60)
    print("COMBINED VERDICT")
    print("=" * 60)
    if flag_supported is True and mean_throughput >= THROUGHPUT_LIKELY_ACCELERATED_MB_S:
        verdict = "AES acceleration appears ACTIVE (both checks agree)."
        confidence = "high"
    elif flag_supported is False and mean_throughput <= THROUGHPUT_LIKELY_SOFTWARE_MB_S:
        verdict = "AES acceleration appears INACTIVE / UNAVAILABLE (both checks agree)."
        confidence = "high"
    elif flag_supported is None:
        verdict = (f"CPU flag could not be checked; throughput alone suggests "
                   f"acceleration is {'likely ACTIVE' if mean_throughput >= THROUGHPUT_LIKELY_ACCELERATED_MB_S else 'likely INACTIVE' if mean_throughput <= THROUGHPUT_LIKELY_SOFTWARE_MB_S else 'UNCLEAR'}.")
        confidence = "low"
    else:
        verdict = ("The two checks DISAGREE or are inconclusive — do not assert "
                   "AES acceleration status with confidence for this machine.")
        confidence = "low"

    print(f"  {verdict}")
    print(f"  Confidence: {confidence}")

    result = {
        'platform': platform.platform(),
        'processor': platform.processor(),
        'cpu_flag_detected': flag_supported,
        'cpu_flag_name': flag_name,
        'mean_throughput_mb_s': mean_throughput,
        'throughput_samples_mb_s': samples,
        'throughput_verdict': throughput_verdict,
        'combined_verdict': verdict,
        'confidence': confidence,
    }

    with open('aes_acceleration_check.json', 'w') as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved: aes_acceleration_check.json "
          f"(include this alongside your benchmark results)")

    return result


if __name__ == "__main__":
    main()
