#!/bin/sh

# License: CC0 1.0 Universal
# https://creativecommons.org/publicdomain/zero/1.0/legalcode

set -ex

D="$(dirname "$0")"

. "$D/travis-doc-upload.cfg"

[ "$TRAVIS_BRANCH" = master ]

[ "$TRAVIS_PULL_REQUEST" = false ]

set +x
eval key=\$encrypted_${SSH_KEY_TRAVIS_ID}_key
eval iv=\$encrypted_${SSH_KEY_TRAVIS_ID}_iv
set -x

mkdir -p ~/.ssh
cat > ~/.ssh/config <<EOF
Host github.com
  IdentityFile=~/docs_github_id
  IdentitiesOnly=yes
EOF
chmod 600 ~/.ssh/config
set +x
openssl aes-256-cbc -K "$key" -iv "$iv" -in "$D/docs_github_id.enc" -out ~/.ssh/docs_github_id -d
set -x
chmod 600 ~/.ssh/docs_github_id

git clone --branch gh-pages "git@github.com:$DOCS_REPO" deploy_docs

cd deploy_docs
git config user.name "doc upload bot"
git config user.email "nobody@example.com"
rm -rf "$PROJECT_NAME"
mkdir -p "$(dirname "$PROJECT_NAME")"
mv ../target/doc "$PROJECT_NAME"
git add -A "$PROJECT_NAME"
git commit -qm "doc upload for $PROJECT_NAME ($TRAVIS_REPO_SLUG)"
git push -q origin gh-pages
