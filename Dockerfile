FROM threatworx/twigs:latest
  
MAINTAINER Ketan Nilangekar <ketan@threatwatch.io>

USER root

#SHELL [ "/bin/bash", "-c" ]

COPY build_docker.sh /tmp
COPY requirements.txt /tmp
COPY . /usr/share/github_app
RUN /bin/bash /tmp/build_docker.sh
ENTRYPOINT ["/usr/local/bin/run-app.sh"]
