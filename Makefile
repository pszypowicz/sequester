build:
	bash scripts/bundle.sh

# Remove any existing install first: cp -R into an existing bundle merges
# stale files (or nests the app) instead of replacing it.
install: build
	rm -rf /Applications/Sequester.app
	cp -R .build/Sequester.app /Applications/Sequester.app

uninstall:
	-killall Sequester 2>/dev/null
	rm -rf /Applications/Sequester.app

test:
	swift test

# Development: build the bundle and (re)launch it.
dev: build
	-killall Sequester 2>/dev/null
	open .build/Sequester.app

dev-stop:
	-killall Sequester 2>/dev/null

.PHONY: build install uninstall test dev dev-stop
