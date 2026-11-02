# Security Policy

## Threat Model & Privacy Commitments

**Kashef (كاشف)** is engineered under a strict **Zero-Knowledge, On-Device Architecture**:
- **Zero Network Egress**: The application does NOT declare or request the `android.permission.INTERNET` permission in `AndroidManifest.xml`. By operating system enforcement, no telemetry, scanned messages, links, or heuristics can leave the user's device.
- **Data Minimization**: Scanned contents are evaluated in-memory. History records stored in the local Room Database truncate sensitive credentials and never store plain OTP tokens.
- **Cloud Backup Disabled**: `android:allowBackup="false"` is enforced to prevent unencrypted cloud sync of local scan databases.

## Supported Versions

| Version | Supported | Status |
| :--- | :--- | :--- |
| `0.1.x` | Yes | Active Development |

## Reporting a Vulnerability

If you discover a security vulnerability, heuristic bypass, or false negative in a critical fraud pattern:
1. **Email Directly**: Contact `seotarek@gmail.com` with the subject `[SECURITY] Kashef Vulnerability Report`.
2. **Details to Include**:
   - Description of the heuristic bypass or vulnerability.
   - Sample deceptive message or malicious URL (redact any real private personal data).
   - Expected behavior vs. actual behavior.
3. **Response Time**: We acknowledge receipt of security reports within 48 hours and coordinate a public fix.
