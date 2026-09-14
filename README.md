# Hybrid Cryptographic Scheme Benchmarking — Code and Data

Companion repository for [Thesis Title], [Your Name], [Year].

Benchmarks three hybrid cryptographic architectures — RSA+AES-256,
ECC+AES-256, and ECC+ChaCha20 — for securing simulated financial
transactions, across four transaction volumes (100, 500, 1,000, 5,000)
with 5 repetitions each (60 total isolated runs, 99,000 individual
transactions).

## Repository structure

```
src/          Scheme implementations, benchmarking harness, utilities
results/      Raw experimental output (transaction-level, batch-level, summary)
analysis/     Scripts that generate the thesis tables and figures
docs/         Environment specification and hardware/OS details
```

## Reproducing the environment

```bash
python3 -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -r docs/requirements.txt
```

See `docs/SYSTEM.md` for the exact hardware/OS the reported results were
collected on. Absolute timing values are hardware-dependent; relative
performance ordering between schemes is expected to be more stable
across environments (see Limitations, Chapter 4).

## Running the benchmark

```bash
cd src
python benchmark.py
```

Each (scheme, volume, repetition) unit runs in its own isolated
subprocess (see `worker.py`) to prevent memory/CPU state from one run
affecting the next. Results are written to `results/`.

## Security note

All three schemes use HMAC-SHA256 under an encrypt-then-MAC
construction for authenticated integrity verification (not a plain
hash), with two independently HKDF-derived keys (one for encryption,
one for authentication) per scheme. See Section [X] of the thesis for
the full cryptographic design rationale.

## License

[UMAT-Essikado Campus]

## Citation

If you use this code or data, please cite:

[Asare Eliakim Forson]

# Hybrid_Cryptography
Performance Evaluation of Hybrid Cryptographic Architectures 

