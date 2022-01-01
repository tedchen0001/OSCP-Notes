Pre-install

```
sudo apt-get install libpng-dev

sudo apt-get install -y pkg-config

git clone --depth=50 https://github.com/AndrewFromMelbourne/fb2png.git AndrewFromMelbourne/fb2png

cd AndrewFromMelbourne/fb2png

git fetch origin +refs/pull/5/merge:

git checkout -qf FETCH_HEAD

export TRAVIS_COMPILER=gcc

export CC=${CC:-gcc}

export CC_FOR_BUILD=${CC_FOR_BUILD:-gcc}

gcc --version

make
```

Target server

```
ls -lah /dev/fb0

cat /dev/fb0 > .tmp
```

Host server

```
cat .tmp > /dev/fb0

./fb2png

ls -la fb.png
```
