TOCKB_CLI := ./target/debug/tockb-cli

test-tockb-cli:
	${TOCKB_CLI} tockb init -f
	${TOCKB_CLI} tockb deploy --tx-fee 0.1 --privkey-path privkeys/0
	${TOCKB_CLI} tockb dev-deploy-sudt --privkey-path privkeys/0
	${TOCKB_CLI} tockb dev-set-price-oracle --privkey-path privkeys/0 --price 10000
	cat .tockb-config.toml

fmt:
	cargo fmt --all -- --check
	cd test && cargo fmt --all -- --check

clippy:
	RUSTFLAGS='-F warnings' cargo clippy --all --tests
	cd test && RUSTFLAGS='-F warnings' cargo clippy --all

test:
	RUSTFLAGS='-F warnings' RUST_BACKTRACE=full cargo test --all

ci: fmt clippy test security-audit
	git diff --exit-code Cargo.lock

integration:
	bash devtools/ci/integration.sh v0.35.0-rc1

prod: ## Build binary with release profile.
	cargo build --release

security-audit: ## Use cargo-audit to audit Cargo.lock for crates with security vulnerabilities.
	@cargo +nightly install cargo-audit
	cargo audit
	# expecting to see "Success No vulnerable packages found"

.PHONY: test clippy fmt integration ci prod security-audit
