FROM threatworx/twigs:latest
  
MAINTAINER Ketan Nilangekar <ketan@threatwatch.io>

USER root

#SHELL [ "/bin/bash", "-c" ]

COPY github_app/build_docker.sh /tmp
COPY github_app/requirements.txt /tmp
COPY github_app /usr/share/github_app
RUN apt-get install libssl-dev
RUN /bin/bash /tmp/build_docker.sh
ENTRYPOINT ["/usr/local/bin/update-twigs-run-uwsgi.sh"]
