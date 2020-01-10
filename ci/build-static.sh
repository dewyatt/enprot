: "${PREFIX:=$GITHUB_WORKSPACE/installs}"
: "${RELEASE_TAG=${GITHUB_REF#refs/tags/}}"
. ci/common.inc.sh

mkdir .cargo
cat <<EOF > .cargo/config
[target.$TARGET]
rustflags = "-C link-args=-s"
EOF

. "ci/build-static/pre/$TARGET.sh"

# use cross to build
cargo install --version "$CROSS_VERSION" cross
# update version in manifest to match our tag
sed -ie "s/^version.*/version = \"$RELEASE_TAG\"/" Cargo.toml
# build
cross -vv build --target "$TARGET" --release

. "ci/build-static/post/$TARGET.sh"

