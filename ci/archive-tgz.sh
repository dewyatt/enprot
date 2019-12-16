name="enprot-$RELEASE_TAG-$TARGET"
mkdir -p "staging/$name"
files=("target/$TARGET/release/enprot" README.adoc)
for file in "${files[@]}"; do
  cp "$file" "staging/$name"
done
mkdir -p archives
outname="$PWD/archives/$name.tar.gz"
pushd staging
tar czf "$outname" "$name"
popd

