# syntax=docker/dockerfile:1

# Comments are provided throughout this file to help you get started.
# If you need more help, visit the Dockerfile reference guide at
# https://docs.docker.com/go/dockerfile-reference/

# Want to help us make this template better? Share your feedback here: https://forms.gle/ybq9Krt8jtBL3iCk7

ARG PYTHON_VERSION=3.10.12

FROM python:${PYTHON_VERSION}-slim as base

# Prevents Python from writing pyc files.
ENV PYTHONDONTWRITEBYTECODE=1

# Keeps Python from buffering stdout and stderr to avoid situations where
# the application crashes without emitting any logs due to buffering.
ENV PYTHONUNBUFFERED=1

# Store the name of the project in an environment variable
ENV PROJECTNAME="firmwareScraper"

WORKDIR /app

# Create a non-privileged user that the app will run under.
# See https://docs.docker.com/go/dockerfile-user-best-practices/

# libpq5 needed by pure python install of psycopg (https://www.psycopg.org/psycopg3/docs/basic/install.html)
# the rest is needed for the install process of binwalk dependencies
RUN apt-get update &&\
  apt-get install -y --no-install-recommends libpq5=15.8-0+deb12u1
# git=1:2.39.2-1.1 \
# wget=1.21.3-1+b2 \
# sudo=1.9.13p3-1+deb12u1 \
# unzip=6.0-28 \
# # sasquatch dependencies
# build-essential=12.9 \
# liblzma-dev=5.4.1-0.2 \
# liblzo2-dev=2.10-2 \
# zlib1g-dev=1:1.2.13.dfsg-1


ARG user=scrapyd-user
ARG homedir=/home/${user}
ARG UID=10001
RUN adduser \
  --disabled-password \
  --gecos "" \
  --shell "/sbin/nologin" \
  --uid "${UID}" \
  ${user}

WORKDIR ${homedir}

# Download dependencies as a separate step to take advantage of Docker's caching.
# Leverage a cache mount to /root/.cache/pip to speed up subsequent builds.
# Leverage a bind mount to requirements.txt to avoid having to copy them into
# into this layer.
RUN --mount=type=cache,target=/root/.cache/pip \
  --mount=type=bind,source=requirements.txt,target=requirements.txt \
  python -m pip install -r requirements.txt


# Copy the source code into the container.
# TODO: absolute path? and chown flag here does not seem to work
COPY  . ${homedir}/app

# # Install binwalk from github
# RUN wget --progress=dot:giga https://github.com/OSPG/binwalk/archive/master.zip &&\
#   unzip master.zip
# WORKDIR ${homedir}/binwalk-master
# RUN python setup.py uninstall && python setup.py install
# RUN chmod +x ./deps.sh && ./deps.sh --yes &&\
#   # Delete the apt-get lists
#   rm -rf /var/lib/apt/lists/*

WORKDIR ${homedir}/app

# Install unblob dependencies
RUN chmod +x ./unblob_deps.sh && ./unblob_deps.sh &&\
  # Delete the apt-get lists
  rm -rf /var/lib/apt/lists/*


# RUN chmod +x binwalk_deps.sh && ./binwalk_deps.sh --yes &&\
#   # Delete the apt-get lists
#   rm -rf /var/lib/apt/lists/*

# Install sasquatch first because it is broken: https://gist.github.com/thanoskoutr/4ea24a443879aa7fc04e075ceba6f689
# RUN git clone https://github.com/devttys0/sasquatch
# WORKDIR ${homedir}/sasquatch
# RUN wget --progress=dot:giga https://raw.githubusercontent.com/devttys0/sasquatch/82da12efe97a37ddcd33dba53933bc96db4d7c69/patches/patch0.txt &&\
#   mv patch0.txt patches
# RUN chmod +x ./build.sh && ./build.sh
# WORKDIR ${homedir}
# # Install binwalk from github
# RUN apt-get install -y  --no-install-recommends unzip=6.0-28
# RUN wget --progress=dot:giga https://github.com/ReFirmLabs/binwalk/archive/master.zip &&\
#   unzip master.zip
# WORKDIR ${homedir}/binwalk-master
# RUN python setup.py install
# RUN chmod +x ./deps.sh && ./deps.sh --yes &&\

# WORKDIR ${homedir}/app

# TODO: better solution
RUN chown -R ${user} ${homedir}/app

# Switch to the non-privileged user to run the application.
USER ${user}


# Expose the port that the application listens on.
EXPOSE 6800

# Run the application.
CMD ["scrapyd", "--pidfile="]
