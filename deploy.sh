git reset --hard
git pull
swift build
if [ ! -d release  ];then
  mkdir release
fi
cp -r .build/debug/tlsserver ./release