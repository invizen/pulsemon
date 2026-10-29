# pulsemon build targets.
#
# The dashboard's Tailwind CSS is PRECOMPILED to a static stylesheet
# (web/vendor/tailwind.css) at build time — not generated in the browser by
# the Play CDN JIT. `make css` regenerates it; the result is committed so the
# Go build (go:embed web/*) works without a Node toolchain.

# Pinned to the same Tailwind major the Play CDN script used to be (v3), so
# the compiled output matches the classes the dashboard expects.
TAILWIND := npx -y tailwindcss@3.4.17

.PHONY: css build

# Regenerate web/vendor/tailwind.css from web/tailwind.input.css, scanning
# web/index.html + web/app.js for class names. Run after editing classes.
css:
	$(TAILWIND) -i web/tailwind.input.css -o web/vendor/tailwind.css --config web/tailwind.config.js --minify

# Build the binary (embeds web/* via go:embed).
build:
	go build -o dist/pulsemon .
