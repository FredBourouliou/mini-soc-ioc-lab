# Mini SOC IOC Lab

**A small, readable threat-detection lab:** scan files, logs and running processes against a list of indicators of compromise (hashes, IPs, domains) and YARA rules, then get an incident-style report. Built to learn SOC workflows, not to replace an EDR.

## Try it

```bash
pip install -r requirements.txt
python src/scan_ioc.py --targets samples/ --ioc ioc/ioc_list.txt --yara yara/rules.yar --no-processes
```

Output on the bundled sample (excerpt of `report.md`):

```
# IOC Detection Report
**Total Detections:** 4

| Detection Type | Count |
|----------------|-------|
| YARA           | 4     |

### Detection #2
- **Type:** YARA
- **Path:** `samples/sample_malware.bin`
- **YARA Rule:** EICAR_Test_File
```

The exit code is `1` when something is detected, so it can gate a script or a CI job.

## What's inside

| Path | Content |
|---|---|
| `src/scan_ioc.py` | Scanner CLI: file hashes, IPs/domains in logs, running processes (`psutil`), YARA; Markdown / JSON / HTML reports |
| `src/yara_integration.py` | YARA wrapper and a small rule builder |
| `src/osint_enrich.py` | Optional enrichment (`--enrich`) via VirusTotal / AbuseIPDB, keys read from the environment, with a local cache |
| `ioc/ioc_list.txt` | 31 example IOCs, `TYPE\|VALUE\|METADATA` format, documentation IP ranges only |
| `yara/rules.yar` | 8 rules (EICAR, suspicious strings, network indicators…) |
| `powershell/scan-ioc.ps1` | Windows-native equivalent of the scanner |
| `docs/SOC_notes.md` | Triage notes and an example incident write-up |

`samples/sample_malware.bin` is **not malware**: it contains the harmless EICAR test string and fake ransom-note text so the rules have something to match. Some antivirus tools will still flag it.

## Options

```
--targets PATH...   files or directories to scan
--ioc FILE          IOC list (required)
--yara FILE         YARA rules
--logs FILE...      log files to search for IOC IPs/domains
--format            markdown | json | html   (default: markdown)
--output FILE       report path (default: report.md)
--enrich            OSINT enrichment (network + API keys)
--no-processes      skip the running-process scan
```

## Tests and Docker

```bash
pytest tests/ -v                      # 16 tests
docker build -t mini-soc-ioc-lab .
docker run --rm -v "$PWD/samples:/app/samples" mini-soc-ioc-lab \
  --targets samples/ --ioc ioc/ioc_list.txt --yara yara/rules.yar --no-processes
```

## License

[MIT](LICENSE). For education and authorized testing only.
