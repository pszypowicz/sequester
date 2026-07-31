build:
	bash scripts/bundle.sh

# Unsigned local build, for contributors without the Developer ID cert.
build-adhoc:
	bash scripts/bundle.sh --identity adhoc

# Remove any existing install first: cp -R into an existing bundle merges
# stale files (or nests the app) instead of replacing it. Register the
# installed copy so Launch Services resolves the icon/login item from
# /Applications, not the throwaway .build bundle.
install: build
	rm -rf /Applications/Sequester.app
	cp -R .build/Sequester.app /Applications/Sequester.app
	/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f /Applications/Sequester.app

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

# Build, sign, notarize, staple, and produce the notarized Sequester.zip.
release:
	bash scripts/notarize-release.sh

.PHONY: build build-adhoc install uninstall test dev dev-stop release
