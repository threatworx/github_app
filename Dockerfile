FROM threatworx/twigs:latest
  
MAINTAINER Ketan Nilangekar <ketan@threatwatch.io>

USER root

#SHELL [ "/bin/bash", "-c" ]

COPY github_app/build_docker.sh /tmp
COPY github_app/requirements.txt /tmp
COPY github_app /usr/share/github_app
COPY twigs-1.1.25-py2.py3-none-any.whl /tmp
RUN sudo apt-get install libssl-dev
RUN /bin/bash /tmp/build_docker.sh
ENTRYPOINT ["/usr/local/bin/uwsgi", "--ini", "/opt/tw_github_app/config/uwsgi.ini"]
