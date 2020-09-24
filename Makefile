TOCKB_CLI := ./target/debug/tockb-cli

mint-xt:
	${TOCKB_CLI} tockb init -f
	${TOCKB_CLI} tockb deploy --tx-fee 0.1 --privkey-path privkeys/0
	${TOCKB_CLI} tockb dev-deploy-sudt --privkey-path privkeys/0
	${TOCKB_CLI} tockb dev-set-price-oracle --privkey-path privkeys/0 --price 10000
	${TOCKB_CLI} tockb dev-set-btc-difficulty-cell --privkey-path privkeys/0 --difficulty 17345997805929
	cat .tockb-config.toml
	${TOCKB_CLI} tockb deposit_request -l 1 -k 1 -p 10000 --tx-fee 0.1 --privkey-path privkeys/0 --user-lockscript-addr ckt1qyqvsv5240xeh85wvnau2eky8pwrhh4jr8ts8vyj37
	${TOCKB_CLI} tockb bonding --tx-fee 0.1 --privkey-path privkeys/0 --lock-address bc1qdekmlav7pglh3k2xm6l7s49c8d0lt5cjxgf52j --signer-lockscript-addr ckt1qyqvsv5240xeh85wvnau2eky8pwrhh4jr8ts8vyj37
	${TOCKB_CLI} tockb mint_xt --tx-fee 0.1 --privkey-path privkeys/0 --spv-proof 900200002c000000300000005e000000a4000000a8000000c8000000d000000024010000880200008c020000020000002a00000001e120d5cc806577ed5d84a9da694f149f19e9229192818285906f4fa4d286ff7a0100000000ffffffff4200000002e0e60b00000000001976a914d51c2f82cef88dcbe6078198b59eaf923369a8dd88ac3d302b27000000001600146e6dbff59e0a3f78d946debfe854b83b5ff5d31200000000f8ea36b3298c05167889ab673d972da05ac001e2303bb4da3fe0d9ba5dae89131d00000000000000500000000000002098c981cb10662d3a815f23e79b24799415ba5d26de000d000000000000000000f3aa3ee9c06ea2e93150c7d7a8e67dea364d3168b617d3d6076ad5226c7073c794a1635f123a1017f1e97f0360010000beba0e94e6866d93db9bb095670dedb65c9b606e3762667447dd1ab134a54c97997d1b9108c23d4c46077ccd28844ca6fe4d60013c0ef1abd7a39b987e5ba5388088b5763da685292cab37dfe7281ceea637ed41a8aaf6d258c39a38fa30e92a5b7f5bb70a4bac9d19b7adf60c796aa677005d481123e6cd7d7b1d79aa9b79663c1b3dc533bc5c771324bda14770688bf81e4ec47f54cb48d8c6b9bf35f429b4fe348f7951390ddab9abf6952bc0deacaae675aecc1e1999666ade2e4ce9b6c1e47bf286f7871390fd3c1b66b3aadead3aa436ac5f4e496ab4b9a811b88580d3ffc09d21b994caf4abb98bb5058b12cbcef124279708a39e4683bc35371f25be14cc4826d97f7853e9612e431071a00ad09d6d219cf96ac7097733b4f8ff6dcaa591dea1579769d7a1d47f34ee1b25975789208745e9dbda47df60cbccbbbf9aa7fcaf28407724c9b06b8ef4cb3080caaf5d664a5fcfce36098c01b45b0b49e10100000000000000

test-tockb-cli: mint-xt
	${TOCKB_CLI} tockb pre_term_redeem --tx-fee 0.1 --privkey-path privkeys/0 --unlock-address bc1qy90wlm8mujjuud6qs665gjp7hvn67ekef62aer --redeemer-lockscript-addr ckt1qyqvsv5240xeh85wvnau2eky8pwrhh4jr8ts8vyj37
	${TOCKB_CLI} tockb withdraw_collateral --tx-fee 0.1 --privkey-path privkeys/0 --spv-proof 6d0200002c000000300000005e000000a1000000a5000000c5000000cd000000210100006502000069020000020000002a00000001f8ea36b3298c05167889ab673d972da05ac001e2303bb4da3fe0d9ba5dae89130100000000ffffffff3f00000002d40c0e0000000000160014162cfd632f3f074ef593b6b6b9385865f2286869c3d01c2700000000160014215eefecfbe4a5ce374086b544483ebb27af66d900000000d32513ca22de1945b255a0aa32b0855d077819fbd11dbd9efe86df0cb6eef61b0e000000000000005000000000a0d121d0dc6b9529eeabe4265a308e9c158f3d7358e63fb4b306000000000000000000704040e74e0f3487c3f729861207760fd9715d3add9865fa7b82f04dd70c4a9312a4635f123a101756815c4540010000e6bb50d272ebb52e2993cd5075738f85c459adf6270d8db33e12696e5ad21cf223b47b0b71a9840c413e5cc99f80d3c9e8cc49cbbe5dd4ee505bf03d4187e8d144630fd3eed7cdeccc337a8f93c6347d99bb1f0ce07f66591a58cdad09a572b1267d4713d1b5d491b65d739ab3510fd219f3ce0e9bcf270c760defc24a53729064484b97627510ce6add32f66a2b186a2c712f666b973e7ab06d0a89d6ef156fd95a197b3c6158505d41df27ced3d7de3b70ff220e35964dd3365147a848e2d625776e82be546390e5f402d898fd8673ae4590fe838c924e3d74694afc2196d1e4d0ea99f68f68e926155e4c7168db75864e8cf9024ad1f9731f0eacc76ae0844b447261835b6aa60a0c234e62cd34b71e48e18a4f71dc535fecb0e7c472ac6bbfc869342d6cfa5dd5815152c4ac7f3be44ed11a2542a8a57420a3fc6654f7a80100000000000000

test-at-term-redeem: mint-xt
	${TOCKB_CLI} tockb at_term_redeem --tx-fee 0.1 --privkey-path privkeys/0 --unlock-address bc1qy90wlm8mujjuud6qs665gjp7hvn67ekef62aer --redeemer-lockscript-addr ckt1qyqvsv5240xeh85wvnau2eky8pwrhh4jr8ts8vyj37

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
