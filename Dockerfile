FROM threatwatch/twigs:latest

MAINTAINER Ketan Nilangekar <ketan@threatwatch.io>

USER root

#SHELL [ "/bin/bash", "-c" ]

COPY build_docker.sh /tmp
RUN /bin/bash /tmp/build_docker.sh
ENTRYPOINT ["python3", "/usr/share/github_app/webservice/__main__.py"]
