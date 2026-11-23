#!/bin/sh
# Prints the CHANGELOG.md section of VERSION (without its heading), for the
# release notes. Fails if there is none, so that no release goes out without.
# Of the link reference definitions, only those of the version compare links
# in the footer (`[Unreleased]: ...`, `[0.2.0]: ...`) are dropped; other
# reference-style links inside the section stay, as with parse-changelog.
#
#   packaging/release-notes.sh 0.1.0 [CHANGELOG.md]

set -eu
version=${1:?usage: release-notes.sh VERSION [CHANGELOG]}
changelog=${2:-CHANGELOG.md}

notes=$(awk -v heading="## [$version]" '
  index($0, heading) == 1 { found = 1; next }
  found && /^## \[/ { exit }
  found && /^\[([Uu]nreleased|v?[0-9]+\.[0-9]+\.[0-9]+[^]]*)\]: / { next }
  found { print }
' "$changelog")

# Drop leading and trailing blank lines.
notes=$(printf '%s\n' "$notes" | sed -e '/./,$!d' | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}')

if [ -z "$notes" ]; then
  echo "release-notes.sh: no section '## [$version]' in $changelog" >&2
  exit 1
fi
printf '%s\n' "$notes"
