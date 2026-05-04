Third-party scanner notices
===========================

The repository root `LICENSE` applies to Cyberscan's own source code. Scanner
engines and template packs that are downloaded, installed, or executed by the
worker keep their own licenses, copied in this directory for review.

| Component | How Cyberscan uses it | License notice |
| --- | --- | --- |
| SSLyze | Installed into an isolated Docker virtualenv and executed only as the `sslyze` CLI subprocess. Cyberscan does not import the `sslyze` Python package. | `third_party/sslyze/LICENSE.txt` |
| Nuclei | Downloaded as a release binary and executed as the `nuclei` CLI subprocess. | `third_party/nuclei/LICENSE.md` |
| Nuclei templates | Fetched by `nuclei -update-templates` at image build/runtime. Review template metadata before enabling commercial scans, especially custom/community templates that may carry non-commercial or other restrictive terms. | `third_party/nuclei-templates/LICENSE.md` |
| Naabu | Downloaded as a release binary and executed as the `naabu` CLI subprocess. | `third_party/naabu/LICENSE.md` |
| httpx | Downloaded as a release binary and executed as the `httpx` CLI subprocess. | `third_party/httpx/LICENSE.md` |
| Katana | Downloaded as a release binary and executed as the `katana` CLI subprocess. | `third_party/katana/LICENSE.md` |
| Subfinder | Downloaded as a release binary and executed as the `subfinder` CLI subprocess. | `third_party/subfinder/LICENSE.md` |
