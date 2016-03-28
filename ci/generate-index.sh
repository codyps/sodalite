#! /bin/sh

set -eu

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <path-to-index>"
  exit 1
fi

o="$1/.tmp_index_$$"
rm -f "$o"
echo '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"></meta></head><body><ul>' >> "$o"

for i in "$1"/*; do
  # TODO: proper encoding & escaping
  f="$(basename $i)"
  echo '<li><a href="'$f'">'$f'</a></li>' >> "$o"
done

echo "</ul></body></html>" >> "$o"

mv -f "$o" "$1"/index.html
