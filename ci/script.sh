# ex: sts=4 sw=4 ts=4 et
# `script` phase: you usually build, test and generate docs in this phase

set -ex

export PKG_CONFIG_ALLOW_CROSS=1

# TODO modify this phase as you see fit
# PROTIP Always pass `--target $TARGET` to cargo commands, this makes cargo output build artifacts
# to target/$TARGET/{debug,release} which can reduce the number of needed conditionals in the
# `before_deploy`/packaging phase

case "$TRAVIS_OS_NAME" in
  linux)
    # without this, gcc-rs may try to do funny things and guess the name of CC
    export TARGET_CC=gcc
    host=x86_64-unknown-linux-gnu
    ;;
  osx)
    host=x86_64-apple-darwin
    ;;
esac

# NOTE Workaround for rust-lang/rust#31907 - disable doc tests when cross compiling
if [ "$host" != "$TARGET" ]; then
  if [ "$TRAVIS_OS_NAME" = "osx" ]; then
    brew install gnu-sed --default-names
  fi

  find src -name '*.rs' -type f -exec sed -i -e 's:\(//.\s*```\):\1 ignore,:g' \{\} \;
fi

cargo build --target "$TARGET" --verbose

case "$TARGET" in
  # use an emulator to run the cross compiled binaries
  arm-unknown-linux-gnueabihf)
    # build tests but don't run them
    cargo test --target "$TARGET" --no-run

    # run tests in emulator
    find "target/$TARGET/debug" -maxdepth 1 -executable -type f -fprintf /dev/stderr "test: %p" -print0 | xargs -0 qemu-arm -L /usr/arm-linux-gnueabihf
    ;;
  *)
    cargo test --target $TARGET
    ;;
esac
