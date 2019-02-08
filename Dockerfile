FROM yastdevel/cpp
RUN zypper --gpg-auto-import-keys --non-interactive in --no-recommends \
  yast2-python3-bindings
COPY . /usr/src/app
