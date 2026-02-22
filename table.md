Risk assessment matrix:

| Threat | Vulnerability | Likelihood | Impact | Mitigation |
| :--- | :--- | :--- | :--- | :--- |
| Sniffing | Traffic interception in an open network | High | High | Enforced E2E encryption (TLS 1.3), HTTP prohibition. |
| Session Hijacking | Token theft via a rogue access point | Medium | Critical | Implementation of hardware security keys (FIDO2) for MFA. |
| OS Compromise | Exploitation of known CVEs on the employee's device | Medium | High | Automated updates (DevSecOps), Host hardening, EDR. |