name="enprot-$RELEASE_TAG-$TARGET"
mkdir -p "staging/$name"
files=("target/$TARGET/release/enprot.exe" README.adoc)
for file in "${files[@]}"; do
  cp "$file" "staging/$name"
done
mkdir -p archives
outname="$PWD/archives/$name.zip"
pushd staging
zip -r "$outname" "$name"
popd

