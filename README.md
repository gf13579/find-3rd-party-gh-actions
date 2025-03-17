# find-3rd-party-gh-actions

Python script to scan a GitHub organization for use of third party GitHub actions. Supports JSON and markdown output.

## Usage

```bash
python3 gh_3rd_party_action_audit.py your-org --output-md your-org-results.md
```

## Notes

- Matches on `uses: ` in yaml files under `.github/.../`
- Ignores references to actions starting with:
    - `github/`
    - `actions/`
    - `./.github/`