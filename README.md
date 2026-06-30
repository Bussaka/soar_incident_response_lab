# Enterprise Threat Intelligence & Automated Incident Response (SOAR) Lab

A hands-on SOAR portfolio project demonstrating log-based threat detection, automated enrichment via threat intelligence APIs, and automated containment.

## Architecture
- **Phase 1 - Sensor**: Ubuntu Server target VM, SSH brute-force detection via journald
- **Phase 2 - Automator**: n8n workflow engine (Docker)
- **Phase 3 - Brain**: AbuseIPDB threat intel enrichment
- **Phase 4 - Responder**: Automated firewall blocking + alerting

## Lab topology
- Kali Linux (attacker) - 192.168.56.20
- Ubuntu Server (target) - 192.168.56.10 (Internal Network) / 192.168.56.101 (Host-only, for n8n webhook reachability)
- n8n - Docker Desktop on Windows host - 192.168.56.1:5678

## Status
- [x] Lab network built and validated
- [x] SSH brute-force simulated via hydra, confirmed in journald
- [x] Sensor script written
- [ ] n8n workflow
- [ ] End-to-end test