# Security Policy

## Supported Versions

Currently, only the `main` branch is actively supported for security updates. 

## Reporting a Vulnerability

Please do not report security vulnerabilities through public GitHub issues.

If you believe you have found a security vulnerability in CyberTrace-Graph, please report it to the maintainers privately via email. We will acknowledge receipt of your vulnerability report and strive to send you regular updates about our progress.

If you have not received a reply to your email within 48 hours, please follow up to ensure we received your message.

## Threat Model Acknowledgement
CyberTrace-Graph is designed as a cybersecurity monitoring tool. However, the sensors and processing nodes must also be secured (e.g., using mTLS for Kafka connections). Default configurations in this repository are intended for local development and simulation only and **must be hardened** before production deployment.
