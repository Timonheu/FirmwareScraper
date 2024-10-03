#!/bin/sh -xeu

apt-get update

apt-get install --no-install-recommends -y \
  android-sdk-libsparse-utils=1:29.0.6-28 \
  curl=7.88.1-10+deb12u7 \
  lz4=1.9.4-1 \
  lziprecover=1.23-5 \
  lzop=1.04-2 \
  p7zip-full=16.02+dfsg-8 \
  unar=1.10.7+ds1+really1.10.1-2+b2 \
  xz-utils=5.4.1-0.2 \
  libmagic1=1:5.44-3 \
  zstd=1.5.4+dfsg2-5

curl -L -o sasquatch_1.0.deb "https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v4.5.1-4/sasquatch_1.0_$(dpkg --print-architecture).deb"
dpkg -i sasquatch_1.0.deb
rm -f sasquatch_1.0.deb

curl -L -o libext2fs2_1.47.0-3.ok2.deb "https://github.com/onekey-sec/e2fsprogs/releases/download/v1.47.0-3.ok2/libext2fs2_1.47.0-3.ok2_$(dpkg --print-architecture).deb"
curl -L -o e2fsprogs_1.47.0-3.ok2.deb "https://github.com/onekey-sec/e2fsprogs/releases/download/v1.47.0-3.ok2/e2fsprogs_1.47.0-3.ok2_$(dpkg --print-architecture).deb"
curl -L -o libss2_1.47.0-3.ok2.deb "https://github.com/onekey-sec/e2fsprogs/releases/download/v1.47.0-3.ok2/libss2_1.47.0-3.ok2_$(dpkg --print-architecture).deb"
dpkg -i libext2fs2_1.47.0-3.ok2.deb libss2_1.47.0-3.ok2.deb
dpkg -i e2fsprogs_1.47.0-3.ok2.deb
rm -f libext2fs2_1.47.0-3.ok2.deb libss2_1.47.0-3.ok2.deb e2fsprogs_1.47.0-3.ok2.deb
