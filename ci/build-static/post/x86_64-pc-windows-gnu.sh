# TODO: maybe check DLL dependencies here
file "target/$TARGET/release/enprot.exe"

docker run --rm -v "$PWD:/project" -w "/project" "$img" wine "target/$TARGET/release/enprot.exe" --version

