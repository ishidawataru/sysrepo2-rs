builder:
	DOCKER_BUILDKIT=1 docker build -t sysrepo-rs-builder .

bash:
	docker run --rm -it -v `pwd`:/data -w /data sysrepo-rs-builder bash

clean-testenv:
	rm -rf /dev/shm/sr* /etc/sysrepo/*

test:
	cargo test -- --test-threads=1 --nocapture $(TEST_PATTERN)
