# Vendored Proton GopenPGP Rust bindings

Source: ProtonMail/proton-crypto-rs, package gopenpgp-sys 0.3.10, MIT license.

This local copy is kept to update its Go module graph without waiting for an
upstream release. Rust binding source and Go GopenPGP wrapper are otherwise
unchanged. The Go module dependencies were updated to golang.org/x/crypto
0.59.0 and golang.org/x/sys 0.50.0, plus compatible x/net, x/term and x/text
versions. The test-only golang.org/x/crypto/openpgp requirement introduced by
a dependency's forwarding test was removed from the production module graph;
the bridge does not import that legacy package. go mod verify and govulncheck
pass on the resulting graph.

Do not edit cryptographic implementation code here without a separate review
and tests. Rebase from Proton's upstream package when a release includes these
dependency updates.

Maintenance note: do not run go mod tidy blindly in this vendored Go module. Go's
module tidy may reintroduce the test-only deprecated OpenPGP compatibility module
from a dependency's test imports. If dependency maintenance requires tidy, inspect
the resulting module graph and remove test-only modules only after confirming
production imports do not use them; then rerun go mod verify and govulncheck.
