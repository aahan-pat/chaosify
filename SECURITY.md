# Security Policy

## Supported versions

Only the latest published version on npm receives security fixes.

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |
| Older   | No        |

---

## Scope

This policy covers **vulnerabilities in Chaosify itself** — bugs in the CLI, scenario execution engine, or evidence output that could be exploited by an attacker.

**In scope:**
- Command injection or unsafe shell execution in Chaosify's core
- Privilege escalation beyond the `chaosify-tests` namespace (violation of the safety model)
- Evidence output that can be manipulated to produce false PASS/FAIL results
- Dependency vulnerabilities with a realistic exploit path

**Out of scope:**
- Vulnerabilities Chaosify is *designed to detect* (e.g. your cluster admitting privileged containers — that's a finding, not a bug in Chaosify)
- Vulnerabilities in the Kubernetes cluster under test
- Issues that require an attacker to already have cluster-admin access

---

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email: **aahanp@gmail.com**

Include:
- A description of the vulnerability and its potential impact
- Steps to reproduce
- Chaosify version and Kubernetes environment (if relevant)
- Any suggested fix, if you have one

You will receive an acknowledgement within **72 hours** and a resolution timeline within **7 days**.

---

## Disclosure policy

- Vulnerabilities are fixed in a patch release before public disclosure.
- Credit is given to the reporter in the release notes unless they prefer to remain anonymous.
- Coordinated disclosure is preferred — please allow reasonable time to release a fix before publishing details.
