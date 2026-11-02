# Contributing to Kashef (كاشف)

Thank you for contributing to Kashef, an open-source, on-device fraud prevention engine for Egypt and the Arab region.

## Contribution Guidelines

### 1. Adding New Entities to the Whitelist
If a legitimate institution (bank, telecom, government portal) needs to be included in the whitelist:
- Locate `app/src/main/java/eg/kashef/shield/core/whitelist/EgyptianEntitiesWhitelist.kt`.
- Ensure the domain is officially verified (e.g., `.gov.eg`, `.bank`, `.eg`).
- Add corresponding unit tests in `app/src/test/java/eg/kashef/shield/`.

### 2. Enhancing Heuristics & Phishing Classifiers
- Phishing rules live in `app/src/main/java/eg/kashef/shield/core/analyzer/`.
- All heuristics must operate with $O(N)$ string processing efficiency to ensure zero UI frame drops.
- **Rule of Zero Network**: Never introduce network calls or dependencies requiring the `INTERNET` permission.

### 3. Testing & Verification
Before submitting a pull request, run all unit tests:
```bash
./gradlew test
```
Ensure all tests pass and code compiles cleanly.

### 4. Pull Request Process
1. Fork the repository and create your branch: `git checkout -b feature/new-pattern`.
2. Commit with descriptive messages: `git commit -m "feat(whitelist): add official cbe.org.eg banking domain"`.
3. Push to your branch and open a PR with a description of the change and test evidence.
