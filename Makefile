TOCKB_CLI := ./target/debug/tockb-cli

test-tockb-cli:
	${TOCKB_CLI} tockb init -f
	${TOCKB_CLI} tockb deploy --tx-fee 0.1 --privkey-path privkeys/0
	${TOCKB_CLI} tockb dev-deploy-sudt --privkey-path privkeys/0
	${TOCKB_CLI} tockb dev-set-price-oracle --privkey-path privkeys/0 --price 10000
	${TOCKB_CLI} tockb dev-set-btc-difficulty-cell --privkey-path privkeys/0 --difficulty 17345997805929
	cat .tockb-config.toml
	${TOCKB_CLI} tockb deposit_request -l 1 -k 1 -p 10000 --tx-fee 0.1 --privkey-path privkeys/0 --user-lockscript-addr ckt1qyqvsv5240xeh85wvnau2eky8pwrhh4jr8ts8vyj37
	${TOCKB_CLI} tockb bonding --tx-fee 0.1 --privkey-path privkeys/0 --lock-address bc1qq2pw0kr5yhz3xcs978desw5anfmtwynutwq8quz0t --signer-lockscript-addr ckt1qyqra9hhl26y7ny9vmzu4t6h0xzfkhhpr6cs3jxqas

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
