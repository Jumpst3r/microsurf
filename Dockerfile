FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install --no-install-recommends -y python3-pip libmagic-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /opt
ADD setup.cfg setup.py pyproject.toml LICENSE /opt/
ADD src /opt/src/
RUN pip3 install .
