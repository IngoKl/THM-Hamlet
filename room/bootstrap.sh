#!/bin/bash

echo "Hamlet Bootstrapping"

# Hostname

sudo hostnamectl set-hostname 'hamlet'

# Docker

sudo apt-get update
sudo apt-get install -y docker.io
sudo apt-get install -y docker-compose

# Users and SSH

sudo useradd ophelia
sudo mkdir -p /home/ophelia
sudo chown ophelia:ophelia /home/ophelia
sudo bash -c "echo 'ophelia:REDACTED' | chpasswd"

sudo bash -c 'echo "THM{REDACTED}" > /home/ophelia/flag'
sudo chown ophelia:ophelia /home/ophelia/flag

sudo useradd gravediggers
sudo mkdir -p /home/gravediggers
sudo chown gravediggers:gravediggers /home/gravediggers

sudo bash -c "echo 'ubuntu:REDACTED' | chpasswd"

ssh-keygen -f /data/ssh/key -q -N ""
sudo bash -c 'cat /data/ssh/key.pub > /home/ubuntu/.ssh/authorized_keys'

# HTTP Server / Website (Port 80)

sudo apt-get install -y lighttpd
sudo cp /data/web/* /var/www/html

# Gravediggers (Port 501)

sudo cp /data/gravediggers/* /home/gravediggers
sudo cp /data/gravediggers/gravediggers.service /etc/systemd/system/gravediggers.service
sudo systemctl enable gravediggers
sudo systemctl start gravediggers

# FTP (Port 21)

sudo apt-get install -y vsftpd
sudo cp /data/vsftpd/vsftpd.conf /etc/vsftpd.conf
sudo systemctl restart vsftpd

sudo cp /data/vsftpd/password-policy.md /srv/ftp/

# WebAnno (Port 8080)

sudo mkdir /srv/webanno
sudo cp /data/docker_web/settings.properties /srv/webanno
sudo docker run -d --name webanno --restart always -v /srv/webanno:/export -p8080:8080 webanno/webanno:3.6.7

# WebAnno Docker Webserver (Port 8000)

sudo cp /data/docker_web/index.html /srv/webanno
sudo cp -r /data/docker_web/ /opt/web

sudo mkdir /opt/stage
sudo bash -c 'echo "THM{REDACTED}" > /opt/stage/flag'

sudo docker run -d --name web --restart always -v /srv/webanno:/var/www/html -v /opt/stage:/stage -p8000:80 --privileged --cap-add=SYS_ADMIN --security-opt apparmor=unconfined php:8.0-apache

sudo docker exec web bash -c 'echo "root:REDACTED" | chpasswd'
sudo docker exec web chmod u+s /bin/cat
sudo docker exec web bash -c 'echo "THM{REDACTED}" > /root/.flag'

# Firewall
# This, actually, does not change much as Docker "bypasses" UFW. However, it is interesting for the reverse shell scenario.

sudo ufw default deny outgoing
sudo ufw default deny incoming
sudo ufw allow 20/tcp
sudo ufw allow 21/tcp
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 501/tcp
sudo ufw allow 8080/tcp
sudo ufw allow 8000/tcp
sudo ufw allow 1603/tcp
sudo ufw allow 1564/tcp
sudo ufw allow 50000:50999/tcp
sudo ufw --force enable

sudo bash -c 'ufw status > /srv/ftp/ufw.status'

# Finishing / Final Flag

sudo bash -c 'echo "THM{REDACTED}" > /root/flag'

sudo updatedb

sudo rm /home/*/.bash_history
sudo rm /var/log/auth.log
sudo rm /var/log/lighttpd/*.log

sudo umount /data
sudo umount /vagrant

#sudo deluser vagrant
sudo rm -r /home/vagrant

echo "Hamlet Bootstrapping Done"

# Show IP

ip a