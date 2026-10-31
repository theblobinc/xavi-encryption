.PHONY: test checksums package-check
test:
	python3 -m unittest discover -s tests -v
	node --test --test-concurrency=1 tests/*.test.mjs
checksums:
	python3 scripts/release_inventory.py --checksums > SHA256SUMS
package-check:
	python3 -m pip wheel --no-deps --no-build-isolation . -w /tmp/xavi-duo-wheel
