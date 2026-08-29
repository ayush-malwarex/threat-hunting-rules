# Qakbot (Qbot) Threat Detection & YARA Rules

A dedicated repository containing production-grade YARA rules, detection signatures, and reverse engineering analysis documentation for **Qakbot (Qbot)** malware samples (specifically targeting the **BDNIMBUS** campaign, Version `2.7.23.13110`).

## Repository Structure

- `rules/malware/qakbot/rule_qakbot_loader.yar`: Static detection signature targeting Qakbot PE loaders, campaign strings, and resource probes.
- `rules/malware/qakbot/rule_qakbot_memory_patterns.yar`: Memory signature targeting dynamic unpacker routines, `VirtualProtect` allocation frames, and atomic `xchg` pointer swapping.
- `docs/qakbot-analysis-notes.md`: Detailed technical analysis and reverse engineering notes.

## Quick Start / Rule Testing

Validate rules using the YARA CLI:

```bash
# Test static loader rule against sample
yara -w rules/malware/qakbot/rule_qakbot_loader.yar /path/to/sample.exe

# Test memory signatures against process dump
yara -w rules/malware/qakbot/rule_qakbot_memory_patterns.yar /path/to/process.dmp

```

## Connect & Contact
Author: Ayush Malwarex

LinkedIn: `ayush-malwarex`

X (Twitter): `@ayush_malwarex`

Discord: `ayush.malwarex`

Substack: Ayush MalwareX Writeups(`@ayushmalwarex`)
