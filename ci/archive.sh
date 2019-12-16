if [[ $TARGET == *"windows"* ]]; then
  . ci/archive-zip.sh
else
  . ci/archive-tgz.sh
fi

