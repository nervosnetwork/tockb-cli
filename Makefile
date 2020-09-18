TOCKB_CLI := ./target/debug/tockb-cli

test-tockb-cli:
	${TOCKB_CLI} tockb init -f
	${TOCKB_CLI} tockb deploy --tx-fee 0.1 --privkey-path privkeys/0
	${TOCKB_CLI} tockb dev-deploy-sudt --privkey-path privkeys/0
	${TOCKB_CLI} tockb dev-set-price-oracle --privkey-path privkeys/0 --price 10000
	${TOCKB_CLI} tockb dev-set-btc-difficulty-cell --privkey-path privkeys/0 --difficulty 17345997805929
	cat .tockb-config.toml
	${TOCKB_CLI} tockb deposit_request -l 1 -k 1 -p 10000 --tx-fee 0.1 --privkey-path privkeys/0 --user-lockscript-addr ckt1qyqvsv5240xeh85wvnau2eky8pwrhh4jr8ts8vyj37
	${TOCKB_CLI} tockb bonding --tx-fee 0.1 --privkey-path privkeys/0 --lock-address bc1qdekmlav7pglh3k2xm6l7s49c8d0lt5cjxgf52j --signer-lockscript-addr ckt1qyqra9hhl26y7ny9vmzu4t6h0xzfkhhpr6cs3jxqas
	${TOCKB_CLI} tockb mint_xt --tx-fee 0.1 --privkey-path privkeys/0 --spv-proof 900200002c000000300000005e000000a4000000a8000000c8000000d000000024010000880200008c020000020000002a00000001e120d5cc806577ed5d84a9da694f149f19e9229192818285906f4fa4d286ff7a0100000000ffffffff4200000002e0e60b00000000001976a914d51c2f82cef88dcbe6078198b59eaf923369a8dd88ac3d302b27000000001600146e6dbff59e0a3f78d946debfe854b83b5ff5d31200000000f8ea36b3298c05167889ab673d972da05ac001e2303bb4da3fe0d9ba5dae89131d00000000000000500000000000002098c981cb10662d3a815f23e79b24799415ba5d26de000d000000000000000000f3aa3ee9c06ea2e93150c7d7a8e67dea364d3168b617d3d6076ad5226c7073c794a1635f123a1017f1e97f0360010000beba0e94e6866d93db9bb095670dedb65c9b606e3762667447dd1ab134a54c97997d1b9108c23d4c46077ccd28844ca6fe4d60013c0ef1abd7a39b987e5ba5388088b5763da685292cab37dfe7281ceea637ed41a8aaf6d258c39a38fa30e92a5b7f5bb70a4bac9d19b7adf60c796aa677005d481123e6cd7d7b1d79aa9b79663c1b3dc533bc5c771324bda14770688bf81e4ec47f54cb48d8c6b9bf35f429b4fe348f7951390ddab9abf6952bc0deacaae675aecc1e1999666ade2e4ce9b6c1e47bf286f7871390fd3c1b66b3aadead3aa436ac5f4e496ab4b9a811b88580d3ffc09d21b994caf4abb98bb5058b12cbcef124279708a39e4683bc35371f25be14cc4826d97f7853e9612e431071a00ad09d6d219cf96ac7097733b4f8ff6dcaa591dea1579769d7a1d47f34ee1b25975789208745e9dbda47df60cbccbbbf9aa7fcaf28407724c9b06b8ef4cb3080caaf5d664a5fcfce36098c01b45b0b49e10100000000000000

bonding:
	${TOCKB_CLI} tockb bonding --tx-fee 0.1 --privkey-path privkeys/0 --signer_lockscript_addr ckt1qyqvsv5240xeh85wvnau2eky8pwrhh4jr8ts8vyj37 --cell 2c63317868d3ae521de777805ae7538977c31bea3cd7cf738f557097eef5f5c6.0 --lock_address bc1qdekmlav7pglh3k2xm6l7s49c8d0lt5cjxgf52j

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
