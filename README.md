# PELens - PE Triage Analysis

A local dashboard for static analysis of Windows Portable Executable (PE) files. The project parses samples, disassembles x86/x64 code, highlights functions for review, and saves findings in SQLite. It does not execute the sample.

## Project files

| File | Purpose |
| --- | --- |
| `pe_triage.py` | Flask dashboard, PE parsing, automatic analysis, disassembly, and API endpoints. |
| `lifter.py` | Built-in reconstruction of x86/x64 instructions into approximate C-like pseudocode. |
| `triage_db.py` | SQLite schema, sample storage, analysis results, annotations, and queries. |
| `requirements.txt` | Required Python packages and optional analysis dependencies. |

## Setup and launch

Install Python with `venv` and `pip` available. From the project directory, run these commands in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe pe_triage.py
```

Open <http://127.0.0.1:8765> and upload a PE file. The server binds to `127.0.0.1`; automatic analysis runs in the background after a sample is loaded.

To preload a sample:

```powershell
.\.venv\Scripts\python.exe pe_triage.py --sample "C:\Samples\sample.bin"
```

## Features

- PE metadata, file hashes, import hash, sections, entropy, imports, exports, resources, and packer signals.
- Extracted strings, indicators, recognized constants, and optional YARA matches.
- Function discovery, heuristic scores, API usage, call relationships, string references, and reconstructed stack strings.
- Address navigation, disassembly, function renaming, and comments.
- Built-in C-like pseudocode and an optional angr decompilation engine.
- Embedded PE discovery and registration as child samples in the library.
- Persistent sample library, read-only SQL queries, and indicator export to CSV.

## Command-line options

| Option | Description | Default |
| --- | --- | --- |
| `--sample PATH` | Read and preload a PE file. | Upload through the browser. |
| `--rules PATH` | Load a YARA rule file or directory containing `.yar` / `.yara` files. Requires `yara-python`. | No YARA rules. |
| `--port NUMBER` | Choose the dashboard port. | `8765` |
| `--db PATH` | Choose the SQLite database path. | `triage.db` |
| `--no-blob` | Save results without storing sample bytes for that load. | Sample bytes are stored. |

Example:

```powershell
.\.venv\Scripts\python.exe pe_triage.py --sample "C:\Samples\sample.bin" --db analysis.db --port 8766 --no-blob
```

`--no-blob` does not remove bytes already stored for the same sample in an existing database.

## Optional dependencies

For YARA matching:

```powershell
.\.venv\Scripts\python.exe -m pip install yara-python
.\.venv\Scripts\python.exe pe_triage.py --rules .\yara
```

For the optional angr pseudocode engine:

```powershell
.\.venv\Scripts\python.exe -m pip install angr
```

Select **angr** in the pseudocode panel after installation. This is a larger optional dependency; the built-in lifter works without it.

## Database and persistence

The default database is created in the working directory. Samples are identified by SHA-256. Stored findings include sections, resources, imports, exports, strings, constants, functions, calls, API usage, string references, indicators, and annotations.

Convenience views include `v_functions`, `v_api_usage`, `v_string_xrefs`, and `v_call_graph`. Full-text string search uses SQLite FTS5 when available.

Example query for reviewing the highest-scored functions:

```sql
SELECT sample_id, addr, name, score, tags
FROM v_functions
ORDER BY score DESC
LIMIT 25;
```

By default, original sample bytes are stored using zlib compression followed by XOR encoding with `0x5A`. This encoding is reversible and is not encryption or a guarantee that security software will ignore the database. Treat the database as containing the original samples. Samples loaded without stored bytes need to be supplied again for analysis requiring their contents.

## Suggested analysis workflow

1. Start the dashboard in an isolated analysis environment and load a sample.
2. Review metadata, imports, strings, resources, entropy, and optional YARA matches.
3. Allow automatic analysis to finish, then inspect high-scoring functions and their API usage.
4. Follow calls and string references; use disassembly to check the pseudocode.
5. Rename functions, add comments, and inspect any embedded child samples.
6. Review extracted indicators before exporting them or using them in detection rules.

## Limitations

Function scores, packer signals, and extracted indicators are heuristics, not confirmed behavior or malware verdicts. Static analysis may miss behavior hidden by packing, encryption, obfuscation, or dynamically resolved calls.

The built-in lifter is a readability aid. It does not provide full type recovery, cross-block data-flow simplification, calling-convention inference, or switch-table reconstruction. Check its output against the disassembly.

The implementation caps uploads and mapped images at 256 MiB, PE sections at 96, discovered functions at 40,000, instructions per function at 30,000, and extracted strings at 60,000. These limits can affect analysis coverage.

Use an isolated analysis VM for untrusted samples, as recommended by the application's source documentation.
