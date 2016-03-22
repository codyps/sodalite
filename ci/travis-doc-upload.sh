#!/bin/sh

# License: CC0 1.0 Universal
# https://creativecommons.org/publicdomain/zero/1.0/legalcode

set -eufx

D="$(dirname "$0")"

. "$D/common.sh"
. "$D/travis-doc-upload.cfg"

[ "$TRAVIS_BRANCH" = master ]

[ "$TRAVIS_PULL_REQUEST" = false ]

set +x
eval key=\$encrypted_${SSH_KEY_TRAVIS_ID}_key
eval iv=\$encrypted_${SSH_KEY_TRAVIS_ID}_iv
set -x

# TODO: generalize over other key types (not just rsa)
mkdir -p ~/.ssh
# travis OSX doesn't add these automatically (linux does)
echo >> ~/.ssh/config <<EOF
Host github.com
	StrictHostKeyChecking no
EOF
set +x
openssl aes-256-cbc -K "$key" -iv "$iv" -in "$D/docs_github_id.enc" -out ~/.ssh/id_rsa -d
set -x
chmod -R u=rwX ~/.ssh

git clone --branch gh-pages "git@github.com:$DOCS_REPO" deploy_docs || {
	git clone "git@github.com:$DOCS_REPO" deploy_docs
}

cd deploy_docs
git config user.name "doc upload bot"
git config user.email "nobody@example.com"
rm -rf "$PROJECT_NAME"
mkdir -p "$(dirname "$PROJECT_NAME")"
mv ../target/$TARGET/doc "$PROJECT_NAME"
git add -A "$PROJECT_NAME"
git commit -qm "doc upload for $PROJECT_NAME ($TRAVIS_REPO_SLUG)"

while ! git push -q origin HEAD:refs/heads/gh-pages; do
	git pull --rebase
done
