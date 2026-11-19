# Copyright (c) 2018, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
#
# A dockerized hassh. Build from the python/ directory of the repository:
#   $ docker build -t hassh:latest -f docker/Dockerfile .
# - Reading capture files (mount a directory holding them):
#   $ docker run --rm -v ~/pcap:/data hassh:latest -d /data -l json -o /data/hassh.json
# - Fingerprinting a server:
#   $ docker run --rm hassh:latest --probe example.org:22
# - Live capture (Linux hosts only, see https://docs.docker.com/network/host/):
#   $ docker run --rm --net=host --cap-add=NET_RAW hassh:latest -i any -p

FROM python:3.13-alpine
LABEL org.opencontainers.image.title="hassh" \
      org.opencontainers.image.licenses="BSD-3-Clause"
RUN apk --no-cache add tcpdump
WORKDIR /opt/hassh
COPY hassh ./hassh
COPY hasshGen/hassh_fingerprints.json hasshGen/hasshserver_fingerprints.json ./hassh/data/
ENV PYTHONPATH=/opt/hassh PYTHONUNBUFFERED=1
ENTRYPOINT ["python3", "-m", "hassh"]
CMD ["-h"]
