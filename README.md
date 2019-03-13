# Update-client
Dynamic DNS updater for dyndns.life
This a simple Dynamic DNS client updater. It works with dyndns.life DDNS Server and it can be modified to work with any other DDNS server. 
It is mandatory to install curl from the source code (https://curl.haxx.se/download.html) before you can compile this client.

Prerequisite: 
You should sign-up in dyndns.life. Your login/password will be used during the installation process.

Installation:

1) make
2) sudo make install


Configuration:
In the GUI http://dyndns.life/admin/ create the hostname
1) adopt the configuration file /usr/local/etc/dyndns.conf by replacing : TOKEN:xxxxxx by TOKEN:token_of_your_hostname

Run IP update:
You can update the hostname's IP address by running the following comand. You can add this command in a crontab.
1) dyndns -U
