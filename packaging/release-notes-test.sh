#!/bin/sh
# Tests release-notes.sh (`checks.changelog`): reference-style links inside a
# section survive, the version link footer does not, and the notes of VERSION
# from the real changelog contain no relative links (they would be dead on the
# release page).
#
#   packaging/release-notes-test.sh VERSION [CHANGELOG.md]

set -eu
version=${1:?usage: release-notes-test.sh VERSION [CHANGELOG]}
changelog=${2:-CHANGELOG.md}
script=$(dirname "$0")/release-notes.sh

fail() {
  echo "release-notes-test.sh: $*" >&2
  exit 1
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/CHANGELOG.md" << 'EOF'
# Changelog

## [Unreleased]

## [1.1.0] - 2026-01-02

### Added

- A feature, see [the docs][docs] and [RFC 4251].

[docs]: https://example.org/docs
[RFC 4251]: https://www.rfc-editor.org/rfc/rfc4251

## [1.0.0] - 2026-01-01

- First release.

[Unreleased]: https://example.org/compare/v1.1.0...HEAD
[1.1.0]: https://example.org/compare/v1.0.0...v1.1.0
[1.0.0]: https://example.org/releases/tag/v1.0.0
EOF

notes=$(sh "$script" 1.1.0 "$tmp/CHANGELOG.md")
for line in '[docs]: https://example.org/docs' \
  '[RFC 4251]: https://www.rfc-editor.org/rfc/rfc4251'; do
  printf '%s\n' "$notes" | grep -qxF "$line" || fail "section link dropped: $line"
done

notes=$(sh "$script" 1.0.0 "$tmp/CHANGELOG.md")
[ "$notes" = '- First release.' ] || fail "footer not removed from 1.0.0:
$notes"

# Inline links and link definitions whose target is not absolute.
notes=$(sh "$script" "$version" "$changelog")
relative=$(printf '%s\n' "$notes" \
  | grep -oE '\]\([^)]*\)|^\[[^]]+\]: +[^ ]+' \
  | grep -vE '^\]\((https?://|mailto:)|^\[[^]]+\]: +(https?://|mailto:)' || true)
[ -z "$relative" ] || fail "relative links in the notes of $version:
$relative"

echo "release-notes.sh: ok"
