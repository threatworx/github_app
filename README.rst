=====================
ThreatWorx GitHub App
=====================

GitHub App from ThreatWorx which supports updating Pull Requests with information about vulnerabilities introduced in the Pull Request.

Steps to run the GitHub App 
===========================
1. Run command below to pull GitHub App Server container locally:

   docker pull threatworx/github_app_server:latest

2. Create a config folder [HOST_CONFIG_FOLDER] on the host that will run your docker container.

3. Make a copy of uwsgi.ini [https://github.com/threatworx/github_app/blob/master/config/uwsgi.ini] file in your config folder. Update the web server port number and specify certificate details in uwsgi.ini file

4. Make a copy of config.ini [https://github.com/threatworx/github_app/blob/master/config/config.ini] file in your config folder. Update web server port, tweak app configuration and update your TW user details in config.ini file.

5. Run the docker container using the command below (note please update port number and path to config folder):

   docker run -d -p <PORT_NO>:<PORT_NO> -v <HOST_CONFIG_FOLDER>:/opt/tw_github_app/config --restart on-failure:2 threatworx/github_app_server
   
6. Create GitHub App in your GitHub Organization by accessing HTTP(S) URL. This will something like:

   https://HOST_IP:PORT_NO/create_github_app
   
7. Install the GitHub App for your repositories

8. You are all set!
