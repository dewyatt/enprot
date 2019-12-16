# check
brew install ripgrep
otool -L "target/$TARGET/release/enprot" | rg -PU "^target/$TARGET/release/enprot:
\t/usr/lib/libc\+\+.1.dylib \(compatibility version \d+\.\d+\.\d+, current version \d+\.\d+\.\d+\)
\t/usr/lib/libSystem.B.dylib \(compatibility version \d+\.\d+\.\d+, current version \d+\.\d+\.\d+\)
\t/usr/lib/libresolv.9.dylib \(compatibility version \d+\.\d+\.\d+, current version \d+\.\d+\.\d+\)$"

"target/$TARGET/release/enprot" --version

