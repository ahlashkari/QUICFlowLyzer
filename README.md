![](https://github.com/ahlashkari/QUICFlowLyzer/blob/main/bccc.jpg)

# QUICFlowLyzer

**QUIC Network Flow Analyzer** 

QUICFlowLyzer is a header-only QUIC network traffic analyzer for extracting QUIC packet and flow-level features from PCAP/PCAPNG traffic.


## Features

- Parses QUIC header-level fields without decrypting payloads
- Supports single PCAP, multiple PCAPs, or glob-based batch processing
- Supports VXLAN-decapsulated traffic
- Exports QUIC flow records and feature tables as CSV files
- Includes QUIC-specific feature extraction logic


## Feature Visualization

The figure below shows the QUICFlowLyzer feature taxonomy, organized by feature category and subgroup.

![QUICFlowLyzer Feature Taxonomy](feature_taxonomy.svg)


## Installation

Create a virtual environment and install the package:
```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Usage

Generate QUIC flow records:
```
python3 -m quic_cap.cli --pcap input.pcapng --flows-out output_flows.csv
```
Generate QUIC feature records:
```
python3 -m quic_cap.features.feat_cli --pcap input.pcapng --features-out output_features.csv
```
For VXLAN traffic:
```
python3 -m quic_cap.features.feat_cli \
  --pcap-glob "captures/*.pcap*" \
  --features-out quic_features.csv \
  --vxlan-port 4789 \
  --allow-mirrored-sport
```
## Repository Structure

- `quic_cap/`: QUIC packet parsing, flow tracking, capture processing, and CSV writing
- `quic_cap/features/`: QUIC feature extraction and feature schema
- `vxlan.py`: VXLAN decapsulation helper
- `tests/`: basic test files

## Notes

Large PCAP files, generated CSV outputs, virtual environments, and private datasets are intentionally excluded from this repository.

Contributions are welcome in the form of pull requests. 


## Copyright (c) 2026 & Citation

For citation in your works and also understanding NTLFlowLyzer completely, you can find below published papers:

```
@inproceedings{jafari_2026,
    author={Jafari, Sepehr and Shafi, MohammadMoein and Lashkari, Arash Habibi},
    title={Unveiling Hierarchical Machine Learning UDP–QUIC Intrusion Detection: Protocol-Aware Flow Analysis and a New Cloud-Generated DDoS Dataset}, 
    booktitle={Proceedings of the 23rd International Conference on Security and Cryptography - Volume 1: SECRYPT}, 
    year={2026},
    pages={46-68},
    isbn={978-989-758-858-7},
    doi={10.5220/0015033600004103}
```

## Team Members 

* [**Arash Habibi Lashkari:**](http://ahlashkari.com/index.asp) Founder and supervisor

* [**Sepehr Jafari:**](https://github.com/Aeripsen) Research Assistant, York University (2025–2026)


## Acknowledgment

This project has been made possible through funding from the Natural Sciences and Engineering Research Council of Canada — NSERC (#RGPIN-2020-04701) and Canada Research Chair (Tier II) - (#CRC-2021-00340) to Arash Habibi Lashkari.

