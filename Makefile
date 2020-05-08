.PHONY: check
check: precheck test

.PHONY: precheck
precheck: check-fmt check-lint check-licenses

.PHONY: check-fmt
check-fmt:
	@output=$$(goimports -l . | sed 's/ /\n - /') && \
	if [ -n "$$output" ]; then \
		printf "goimports differs:\n $$output\n" >&2 && exit 1; \
	fi

.PHONY: check-licenses
check-licenses:
	go-licenser -d .

.PHONY: check-lint
check-lint:
	golint -set_exit_status

.PHONY: test
test:
	go test -v -race

.PHONY: coverage
coverage:
	go test -v -covermode=atomic -coverprofile=cover.out

.PHONY: fmt
fmt:
	goimports -l -w .

.PHONY: update-licenses
update-licenses:
	go-licenser .
