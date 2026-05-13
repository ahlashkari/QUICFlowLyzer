# QUICFlowLyzer

QUICFlowLyzer is a header-only QUIC network traffic analyzer for extracting QUIC packet and flow-level features from PCAP/PCAPNG traffic.

## Features

- Parses QUIC header-level fields without decrypting payloads
- Supports single PCAP, multiple PCAPs, or glob-based batch processing
- Supports VXLAN-decapsulated traffic
- Exports QUIC flow records and feature tables as CSV files
- Includes QUIC-specific feature extraction logic

## Installation

Create a virtual environment and install the package:

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .

## Usage

Generate QUIC flow records:

python3 -m quic_cap.cli --pcap input.pcapng --flows-out output_flows.csv

Generate QUIC feature records:

python3 -m quic_cap.features.feat_cli --pcap input.pcapng --features-out output_features.csv

For VXLAN traffic:

python3 -m quic_cap.features.feat_cli \
  --pcap-glob "captures/*.pcap*" \
  --features-out quic_features.csv \
  --vxlan-port 4789 \
  --allow-mirrored-sport

## Repository Structure

- quic_cap/: QUIC packet parsing, flow tracking, capture processing, and CSV writing
- quic_cap/features/: QUIC feature extraction and feature schema
- vxlan.py: VXLAN decapsulation helper
- tests/: basic test files

## Notes

Large PCAP files, generated CSV outputs, virtual environments, and private datasets are intentionally excluded from this repository.
