# Partners Research Portal#
## Disaster Recovery Plan##

###Overview###

The Partners Research Portal (PRP) application consists of several components, a Spring Boot web application, a Nginx reverse proxy, a SQL Server database, and an Elasticsearch database. In addition the PRP application is running behind a Citrix Netscaler to load-balance the application and provide an additional layer of network security.  Hyperic is used to monitor the status and health of application services. The application has built-in redundancy supporting two instances of the web application and three instances of Elasticsearch. Application updates can be deployed without any interruption of service.

At this time, there are three core PRP servers/virtual machines running Red Hat 6.3 Enterprise Linux which are hosted on Partners IS infrastructure in two data centers in Needham and Marlborough, Massachusetts. 


### Core PRP Servers ###

| DNS Name | IP Address | Description  | Services | Location |
| ------ | ------ | ------ | ------ | ------ |
|  PHSLXMGHES1  |  172.18.41.157  |   Elasticsearch Server  | Elasticsearch, Kibana, Nginx | Marlborough |
|  PHSLXMGHRP1  |  172.18.41.140  |   RPR Application Server 1  | PRP Web Application, Nginx, Elasticsearch | Marlborough |
|  PHSLXMGHRP2  |  172.31.166.191  |   RPR Application Server 2  | PRP Web Application, Nginx, Elasticsearch | Needham |


----------


###Purpose###

The purpose of this document is to provide a roadmap which will help the Partners Research Portal recover as quickly as possible from an unforeseen disaster, emergency, or unexpected downtime which interrupts Partners Information Systems or one of the core components of the PRP application.  This document will also provide an overview of the various application components and interdependencies and how to restore or reinstall them.

----------


###Contacts###

#### Primary Technical Contact####
    Stephen Lorenz
    MGH / Laboratory of Computer Science
    slorenz@partners.org
    978-476-5054
  
####Secondary Technical Contact####
    Xiaofeng Zhang
    MGH / Laboratory of Computer Science
    xzhang14@partners.org
	617-726-5583
	
####Technical Support/Helpdesk####
	Lloyd Clarke
	MGH / Laboratory of Computer Science
	ldclarke@partners.org
	617-726-0625
	Pager: 15679
  
####Database Administrator####
	Barry Putterman
	MGH / Laboratory of Computer Science
	bputterman@mgh.harvard.edu
	617-724-3543
	Pager: 11049
  
####Administrative Support####
	Jeanhee Chung
	MGH / Laboratory of Computer Science
	jachung@partners.org
	617-643-3292

----------

###Backup and Restore###
All servers are backed up nightly via Tivoli Storage Manager (TSM). Some components such as configuration files, application control scripts, and the core web application jar file, can be restored from a standard file system restore from TSM.  Other components, depending on the severity of the outage, could require a manual restore procedure. Elasticsearch is an example of such a component.

#### Tivoli Storage Manager (TSM)####

The Tivoli Storage Manager Web client GUI can be accessed on port 1580 on the three core PRP servers. The following file structures should be restored from TSM:

	/apps/**
	/etc/nginx/**
	/etc/sysconfig/iptables
	/etc/stunnel/**
	/etc/elasticsearch/**
	/etc/kibana/** (phslxmghes1 only)
	/etc/init.d/stunnel
	/etc/init.d/elasticsearch
	/etc/init.d/prp (phslxmghrp1 and phslxmghrp2 only)
	/etc/init.d/prpmgh (phslxmghrp1 and phslxmghrp2 only)
 
#### Elasticsearch####

An incremental backup of the Elasticsearch cluster is performed nightly. A complete restore of the cluster is possible with this backup. In addition, the Elasticsearch cluster keeps at least one replica of the data in real time. We should be able to lose one Elasticsearch node without any loss of data or interruption of service. The backups of the backups are performed nightly by TSM.

Elasticsearch cluster backups require a shared mount point on which to persist the backup. Our share is mounted to `/apps/elasticsearch/backup`. The shared mount must be accessible to all members of the cluster. We are using an NFS mount to achieve this. For an NFS mount to work, Elasticsearch must be running as the same Linux uuid on all servers. Check your /etc/passwd file and the file permissions and ownership of the shared mount point to ensure this is the case. The backup (and backup rotation script) is triggered by a nightly cron job. The backup scripts are located here, `/apps/elasticsearch/script`.

More information on an Elasticsearch restore can be found here: https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-snapshots.html.

----------


### Components and Dependencies###

#### Java####

Java 1.8 is required for several of the key Partners Research Portal components. We recommend the Oracle version of the JDK as OpenJDK has been known to have memory allocation issues with Elasticsearch.  You may download and install the Oracle JDK 8 via the following commands:

	> sudo su
	> cd ~/
	> wget --no-check-certificate --no-cookies --header "Cookie: oraclelicense=accept-securebackup-cookie" http://download.oracle.com/otn-pub/java/jdk/8u101-b13/jdk-8u101-linux-x64.rpm
	> rpm -ivh jdk-8u101-linux-x64.rpm
 
 Java needs to be installed on all three core Partners Research Portal servers prior to installing the other PRP components.

#### Spring Boot Web Application####

The Partners Research Portal is running as a Sprout Boot 1.4 executable jar web application on two virtual machines, phslxmghrp1 and phslxmghrp2. It runs on http port 8080. Ngnix is running as a reverse proxy on https port 8443 in front of the Sprout Boot application. We are using Ngnix to terminate the SSL connection to simplify certificate management.

The web application environment is backed up nightly and also stored off-site in Github.

#### Elasticsearch####

Elasticsearch serves as the public-facing data source for the Partners Research Portal. As the name implies, Elasticsearch supports the search functionality of the PRP site. Elasticsearch is also used to track study access log statistics.  Elasticsearch is running in a cluster of three servers, phslsmghes1, phslxmghrp1, and phslxmghrp2. These are Red Hat 6.3 Linux servers. These servers are administratively available at https://prpes.partners.org.  You will be prompted for a username and password.

Behind the scenes Elasticsearch network traffic is configured to run through secure, stunnel channels. These channels are used to encrypt intra-application traffic and prevent unauthorized access (as managed by iptables) and man-in-the-middle attacks. The Elasticsearch uses these secure channels to manage the cluster and ensure the replicas are kept in-sync. Unfortunately, this configuration adds significant complexity to the Elasticsearch configuration.

##### Elasticsearch Installation####

Run these commands as root:

    > cd ~/
    > mkdir elasticsearch

Download and install Elasticsearch 2.4:

    > wget https://download.elastic.co/elasticsearch/release/org/elasticsearch/distribution/rpm/elasticsearch/2.4.0/elasticsearch-2.4.0.rpm
    > rpm -ivh elasticsearch-2.4.0.rpm

Install Elasticsearch as a Linux service:

    > chkconfig --add elasticsearch
    > service elasticsearch start

The main Elasticsearch configuration file, elasticsearch.yml, is located in /etc/elasticsearch. We need to create a new directory structure to store all the Elasticsearch data files and then edit the elasticsearch.yml file to point to these new directories:

	> cd /apps
	> mkdir elasticsearch
	> cd elasticsearch
	> mkdir plugins logs work backup scripts
	> cd /apps
	> chmod -R 755 elasticsearch
	> chown -R elasticsearch:elasticsearch elasticsearch

Open the main configuration file:

	> vim /etc/elasticsearch/elasticsearch.yml

1. Find the `cluster.name` setting and assign it to `prpprod`.
2. Find the `node.name` setting and assign it to the name of the server, for example, `phslxmghes1`.
3. Find the `path.data` setting and assign it to `/apps/elasticsearch/data`.
4. Find the `path.logs` setting and assign it to `/apps/elasticsearch/logs`.
5. Find the `network.host` setting and assign it to `0.0.0.0`.
6. Add the following lines:
	
		network.bind_host: 0.0.0.0
		transport.tcp.port: 9300
		network.publish_host: 127.0.0.1
		transport.publish_port: 6301
		http.port: 9200

7. Find the `discovery.zen.minimum_master_nodes` setting and assign it to `3`.
8. Add the following line to define a backup location:

		path.repo: ["/apps/elasticsearch"]

#####Stunnel Installation####

Run `yum` as root to install stunnel:

	> yum install stunnel

Create an ssl certificate for stunnel:

	> cd /etc/stunnel
	> openssl req -new -x509 -days 3650 -nodes -config stunnel.conf -out stunnel.pem
	
Create an stunnel configuration file, `/etc/stunnel/stunnel.conf` with these settings:

	debug = 1
	output = /var/log/stunnel.log
	cert = /etc/stunnel/stunnel.pem
	options = NO_SSLv2
	fips = no
	
	[me]
	accept = 6300
	connect = 127.0.0.1:9300
	
	[loopback]
	accept = 6301
	connect = 127.0.0.1:9300
	
	[PHSLXMGHRP2_STUNNEL_9300]
	client = yes
	accept = 6303
	connect = PHSLXMGHRP2:6300
	
	[PHSLXMGHRP1_STUNNEL_9300]
	client = yes
	accept = 6302
	connect = PHSLXMGHRP1:6300

For some reason the stunnel package does not include an stunnel service script so you have to roll your own. Here's how:

	> cd /etc/init.d
	> vim stunnel

Add the following lines to the `stunnel` file:

	#!/bin/bash
	#
	# Script to run stunnel in daemon mode at boot time.
	#
	# Check http://www.gaztronics.net/ for the
	# most up-to-date version of this script.
	#
	# This script is realeased under the terms of the GPL.
	# You can source a copy at:
	# http://www.fsf.org/copyleft/copyleft.html
	#
	# Please feel free to modify the script to suite your own needs.
	# I always welcome email feedback with suggestions for improvements.
	# Please do not email for general support. I do not have time to answer
	# personal help requests.
	
	# Author: Gary Myers MIIE MBCS
	# email: http://www.gaztronics.net/webform/
	# Revision 1.0 - 4th March 2005
	
	#====================================================================
	# Run level information:
	#
	# chkconfig: 2345 99 99
	# description: Secure Tunnel
	# processname: stunnel
	#
	# Run "/sbin/chkconfig --add stunnel" to add the Run levels.
	# This will setup the symlinks and set the process to run at boot.
	#====================================================================
	
	#====================================================================
	# Paths and variables and system checks.
	
	# Source function library (It's a Red Hat thing!)
	. /etc/rc.d/init.d/functions
	
	# Check that networking is up.
	#
	[ ${NETWORKING} ="yes" ] || exit 0
	
	# Path to the executable.
	#
	SEXE=`which stunnel`
	
	# Path to the configuration file.
	#
	CONF=/etc/stunnel/stunnel.conf
	
	# Check the configuration file exists.
	#
	if [ ! -f $CONF ] ; then
	  echo "The configuration file cannot be found!"
	exit 0
	fi
	
	CHROOT=`grep '^chroot' /etc/stunnel/stunnel.conf | head -n 1 | sed 's/ //g' | awk -F= '{ print $2 }'`
	#PIDFILE=`grep '^pid' /etc/stunnel/stunnel.conf | head -n 1 | sed 's/ //g' | awk -F= '{ print $2 }'`
	PIDFILE=/var/run/stunnel.pid
	if [ -n "$CHROOT" ]; then
	    PIDFILE=$CHROOT/$PIDFILE
	fi
	
	# Path to the lock file.
	#
	LOCK_FILE=/var/lock/subsys/stunnel
	
	#====================================================================
	
	#====================================================================
	# Run controls:
	
	prog=$"stunnel"
	
	RETVAL=0
	
	# Start stunnel as daemon.
	#
	start() {
	  if [ -f $LOCK_FILE ]; then
	    echo "stunnel is already running!"
	    exit 0
	  else
	    echo -n $"Starting $prog: "
	    $SEXE $CONF
	  fi
	
	  RETVAL=$?
	  [ $RETVAL -eq 0 ] && success
	  echo
	  [ $RETVAL -eq 0 ] && touch $LOCK_FILE
	  return $RETVAL
	}
	
	
	# Stop stunnel.
	#
	stop() {
	  if [ ! -f $LOCK_FILE ]; then
	    echo "stunnel is not running!"
	    exit 0
	
	  else
	
	    echo -n $"Shutting down $prog: "
	    killproc -p $PIDFILE stunnel
	    RETVAL=$?
	    [ $RETVAL -eq 0 ]
	     rm -f $LOCK_FILE
	    echo
	    return $RETVAL
	
	  fi
	}
	
	# See how we were called.
	case "$1" in
	   start)
	  start
	  ;;
	   stop)
	  stop
	  ;;
	   restart)
	  stop
	  start
	  ;;
	   condrestart)
	  if [ -f $LOCK_FILE ]; then
	     stop
	     start
	     RETVAL=$?
	  fi
	  ;;
	   status)
	  status -p $PIDFILE stunnel
	  RETVAL=$?
	  ;;
	   *)
	    echo $"Usage: $0 {start|stop|restart|condrestart|status}"
	    RETVAL=1
	esac
	
	exit $RETVAL

After you have created this file, make sure it has the proper permissions:

	> chmod 755 /etc/init.d/stunnel

Then install the service:

	> chkconfig --add /etc/init.d/stunnel
	> /etc/init.d/stunnel start

Re-open the Elasticsearch configuration file, /etc/elasticsearch/elasticsearch.yml, and find the `discovery.zen.ping.unicast.hosts` setting and assign it to the other two Elasticsearch hosts as defined in the stunnel.conf, for example: 

	discovery.zen.ping.unicast.hosts: ["localhost:6300", "localhost:6302"]

### Iptables###

Open the `/etc/sysconfig/iptables` file and add the following lines 

	
	-A RH-Firewall-1-INPUT -m state --state NEW -m tcp -p tcp --dport 6081 -j ACCEPT
	-A RH-Firewall-1-INPUT -m state --state NEW -m tcp -p tcp -s 172.18.40.196 --dport 2144 -j ACCEPT
	-A RH-Firewall-1-INPUT -m state --state NEW -m tcp -p tcp --dport 5666 -j ACCEPT
	-A RH-Firewall-1-INPUT -m state --state NEW -m tcp -p tcp --dport 8443 -j ACCEPT
	-A RH-Firewall-1-INPUT -m state --state NEW -m tcp -p tcp -s 172.18.41.157,172.18.41.140,172.31.166.191 --dport 6300 -j ACCEPT
	-A RH-Firewall-1-INPUT -m state --state NEW -m tcp -p tcp --dport 9443 -j ACCEPT
	-A RH-Firewall-1-INPUT -m state --state NEW -m tcp -p tcp --dport 7443 -j ACCEPT

Restart iptables:

		> /etc/init.d/iptables condrestart

### Nginx###

Nginx provides a reverse proxy service for the main Spring Boot web application as well as Elasticsearch and Kibana. Nginx also terminates the SSL connection, serves as a cache for images and other static content, and generates and serves thumbnails for a large images. Download Nginx and the Nginx Image Filter module from the internet:

	> wget https://nginx.org/packages/rhel/6/x86_64/RPMS/nginx-1.10.1-1.el6.ngx.x86_64.rpm
	> wget nginx-module-image-filter-1.10.1-1.el6.ngx.x86_64.rpm

You will likely need to also need to install the gd, a graphics library for the generation of PNG and JPEG images, before you can install the Nginx Image Filter module:

	> yum -y install gd-2.0.35-11.el6.x86_64

First install the main nginx server:

	> rpm -ivh nginx-1.10.1-1.el6.ngx.x86_64.rpm

Then install the Nginx Image Filter module:

	> rpm -ivh nginx-module-image-filter-1.10.1-1.el6.ngx.x86_64.rpm
	
Open the `/etc/nginx/nginx.conf` file and prepend the following line to enable the Nginx Image Filter module:

	load_module modules/ngx_http_image_filter_module.so;
	
Create the following directory to hold the Nginx cache and set the directory owner to the nginx user:

	> mkdir -p /apps/prp/cache
	> chown -R nginx:nginx /apps/prp/cache
	
Copy the Partners 2019 wildcard certificates to the /etc/nginx directory. On the dedicated Elasticsearch server, phslxmghes1, open the default server configuration file, `/etc/nginx/conf.d/default.conf` and add the following lines:

	upstream elasticsearch {
	    server 127.0.0.1:9200;
	    keepalive 15;
	}
	
	upstream kibana {
	    server 127.0.0.1:5601;
	    keepalive 15;
	}
	
	server {
	  listen 7443 ssl;
	
	    auth_basic "Protected Kibana";
	    auth_basic_user_file passwords;
	
	    ssl_certificate     partners2019.cer;
	    ssl_certificate_key partners2019.key;
	    ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
	    ssl_ciphers         HIGH:!aNULL:!MD5;
	
	    location / {
	      proxy_pass http://kibana;
	      proxy_http_version 1.1;
	      proxy_set_header Connection "Keep-Alive";
	      proxy_set_header Proxy-Connection "Keep-Alive";
	    }
	}
	
	server {
	  listen 9443 ssl;
	
	    auth_basic "Protected Elasticsearch";
	    auth_basic_user_file passwords;
	
	    ssl_certificate     partners2019.cer;
	    ssl_certificate_key partners2019.key;
	    ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
	    ssl_ciphers         HIGH:!aNULL:!MD5;
	
	    location / {
	      proxy_pass http://elasticsearch;
	      proxy_http_version 1.1;
	      proxy_set_header Connection "Keep-Alive";
	      proxy_set_header Proxy-Connection "Keep-Alive";
	    }
	}
	
	server {
	  listen 6081;
	
	  location / {
	      # proxy_pass https://phslxmghes1.partners.org:9443/_cluster/health;
	      proxy_pass http://elasticsearch/_cluster/health;
	      proxy_http_version 1.1;
	      proxy_set_header Connection "Keep-Alive";
	      proxy_set_header Proxy-Connection "Keep-Alive";
	  }
	}

On the application servers, phslxmghrp1 and phslxmghrp2, open the default server configuration file, `/etc/nginx/conf.d/default.conf` and add the following lines:

	proxy_cache_path /apps/prp/cache levels=1:2 keys_zone=my_zone:10m inactive=60m;
	proxy_cache_key "$scheme$request_method$host$request_uri";
	
	upstream elasticsearch {
	    server 127.0.0.1:9200;
	    keepalive 15;
	}
	
	upstream tomcat {
	    server 127.0.0.1:8080;
	}
	
	server {
	  listen 9443 ssl;
	
	    auth_basic "Protected Elasticsearch";
	    auth_basic_user_file passwords;
	
	    ssl_certificate     partners2019.cer;
	    ssl_certificate_key partners2019.key;
	    ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
	    ssl_ciphers         HIGH:!aNULL:!MD5;
	
	    location / {
	      proxy_pass http://elasticsearch;
	      proxy_http_version 1.1;
	      proxy_set_header Connection "Keep-Alive";
	      proxy_set_header Proxy-Connection "Keep-Alive";
	    }
	}
	
	server {
	    # Internal image resizing server.
	    server_name 127.0.0.1;
	    listen 8888;
	
	    location ~ ^/(thumb/study/image|thumb/study/photo|thumb/assets/images/cards)/ {
	        image_filter resize 400 -;
	        image_filter_jpeg_quality 75;
	        image_filter_buffer 8M;
	
	        proxy_pass http://tomcat;
	        proxy_http_version 1.1;
	        proxy_redirect     off;
	
	        proxy_set_header   Host             $host;
	        proxy_set_header   X-Real-IP        $remote_addr;
	        proxy_set_header   X-Forwarded-For  $proxy_add_x_forwarded_for;
	
	        client_max_body_size       10m;
	        client_body_buffer_size    128k;
	
	        proxy_connect_timeout      90;
	        proxy_send_timeout         90;
	        proxy_read_timeout         90;
	
	        proxy_buffer_size          4k;
	        proxy_buffers              4 32k;
	        proxy_busy_buffers_size    64k;
	        proxy_temp_file_write_size 64k;
	
	        expires 30m;
	        access_log off;
	        add_header Cache-Control "public";
	    }
	
	    location ~ ^/(thumb/study/avatar)/ {
	        image_filter resize 60 -;
	        image_filter_jpeg_quality 75;
	        image_filter_buffer 8M;
	
	        proxy_pass http://tomcat;
	        proxy_http_version 1.1;
	        proxy_redirect     off;
	
	        proxy_set_header   Host             $host;
	        proxy_set_header   X-Real-IP        $remote_addr;
	        proxy_set_header   X-Forwarded-For  $proxy_add_x_forwarded_for;
	
	        client_max_body_size       10m;
	        client_body_buffer_size    128k;
	
	        proxy_connect_timeout      90;
	        proxy_send_timeout         90;
	        proxy_read_timeout         90;
	
	        proxy_buffer_size          4k;
	        proxy_buffers              4 32k;
	        proxy_busy_buffers_size    64k;
	        proxy_temp_file_write_size 64k;
	
	        expires 30m;
	        access_log off;
	        add_header Cache-Control "public";
	    }
	}
	
	server {
	    listen 8443 ssl;
	
	    ssl_certificate     partners2019.cer;
	    ssl_certificate_key partners2019.key;
	    ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
	    ssl_ciphers         HIGH:!aNULL:!MD5;
	
	    location ~ ^/(thumb/study/image|thumb/study/photo|thumb/assets/images/cards|thumb/study/avatar)/ {
	        # Proxy to internal image resizing server.
	        proxy_pass http://127.0.0.1:8888;
	        proxy_cache my_zone;
	        add_header X-Proxy-Cache $upstream_cache_status;
	        #proxy_cache_valid 200 24h;
	    }
	
	    location / {
	        proxy_cache my_zone;
	        add_header X-Proxy-Cache $upstream_cache_status;
	
		    proxy_set_header   Host             $host;
	        proxy_set_header   X-Real-IP        $remote_addr;
	        proxy_set_header   X-Forwarded-For  $proxy_add_x_forwarded_for;
	      
	        #include proxy_params;
	        proxy_pass http://127.0.0.1:8085;
	    }
	
	    location /analytics {
	      proxy_pass https://lcsn173.partners.org;
	      proxy_http_version 1.1;
	      proxy_redirect     off;
	
	      proxy_set_header   Host             $host;
	      proxy_set_header   X-Real-IP        $remote_addr;
	      proxy_set_header   X-Forwarded-For  $proxy_add_x_forwarded_for;
	
	      client_max_body_size       10m;
	      client_body_buffer_size    128k;
	
	      proxy_connect_timeout      90;
	      proxy_send_timeout         90;
	      proxy_read_timeout         90;
	
	      proxy_buffer_size          4k;
	      proxy_buffers              4 32k;
	      proxy_busy_buffers_size    64k;
	      proxy_temp_file_write_size 64k;
	   }
	}
	
	server {
	    listen 8085;
	
	    location / {
	      proxy_pass http://tomcat;
	      proxy_http_version 1.1;
	      proxy_redirect     off;
	
	      proxy_set_header   Host             $host;
	      proxy_set_header   X-Real-IP        $remote_addr;
	      proxy_set_header   X-Forwarded-For  $proxy_add_x_forwarded_for;
	
	      client_max_body_size       10m;
	      client_body_buffer_size    128k;
	
	      proxy_connect_timeout      90;
	      proxy_send_timeout         90;
	      proxy_read_timeout         90;
	
	      proxy_buffer_size          4k;
	      proxy_buffers              4 32k;
	      proxy_busy_buffers_size    64k;
	      proxy_temp_file_write_size 64k;
	   }
	
	    location ~ ^/(assets|apps|webjars)/ {
	      proxy_pass http://tomcat;
	      proxy_http_version 1.1;
	      proxy_redirect     off;
	
	      proxy_set_header   Host             $host;
	      proxy_set_header   X-Real-IP        $remote_addr;
	      proxy_set_header   X-Forwarded-For  $proxy_add_x_forwarded_for;
	
	      client_max_body_size       10m;
	      client_body_buffer_size    128k;
	
	      proxy_connect_timeout      90;
	      proxy_send_timeout         90;
	      proxy_read_timeout         90;
	
	      proxy_buffer_size          4k;
	      proxy_buffers              4 32k;
	      proxy_busy_buffers_size    64k;
	      proxy_temp_file_write_size 64k;
	
	      expires 5m;
	      access_log off;
	      add_header Cache-Control "public";
	   }
	
	    location ~ ^/(study/photo|study/image)/ {
	      proxy_pass http://tomcat;
	      proxy_http_version 1.1;
	      proxy_redirect     off;
	
	      proxy_set_header   Host             $host;
	      proxy_set_header   X-Real-IP        $remote_addr;
	      proxy_set_header   X-Forwarded-For  $proxy_add_x_forwarded_for;
	
	      client_max_body_size       10m;
	      client_body_buffer_size    128k;
	
	      proxy_connect_timeout      90;
	      proxy_send_timeout         90;
	      proxy_read_timeout         90;
	
	      proxy_buffer_size          4k;
	      proxy_buffers              4 32k;
	      proxy_busy_buffers_size    64k;
	      proxy_temp_file_write_size 64k;
	
	      expires 30m;
	      access_log off;
	      add_header Cache-Control "public";
	   }
	}
	
	server {
	  listen 6081;
	
	  location / {
	      proxy_pass https://phslxmghrp1.partners.org:6082;
	      proxy_http_version 1.1;
	      proxy_set_header Connection "Keep-Alive";
	      proxy_set_header Proxy-Connection "Keep-Alive";
	  }
	}



Make sure you change the hostname on the line with `proxy_pass https://phslxmghrp1.partners.org:6082;` to reflect the server on which this configuration sits.

### Kibana

The Kibana server provides an analytic GUI interface onto of Elasticsearch. Kibana is only running on the dedicated Elasticsearch server, phslxmghes1.  To install Kibana add a new yum repository.  Create a new repository file:

	> vim /etc/yum.repos.d/kibana.repo

Add the following lines:

	[kibana-4.1]
	name=Kibana repository for 4.1.x packages
	baseurl=http://packages.elastic.co/kibana/4.1/centos
	gpgcheck=1
	gpgkey=http://packages.elastic.co/GPG-KEY-elasticsearch
	enabled=1
	
Finally, install the kibana package:

	> yum -y install kibana
	
Kibana should be able to automatically discover the local node of Elasticsearch which, in turn, will allow it to discover the rest of the cluster. Next, install Kibana as a Linux service:

	> chkconfig /etc/init.d/kibana on

And start the service:

	> /etc/init.d/kibana start

### Hyperic

Hyperic is used to monitor the Partners Research Portal environment. If a web application where to go down or if Elasticsearch were to lose a member cluster, then Hyperic will send out an alert so we can track down the problem. Hyperic is accessible here: `http://lcs196.mgh.harvard.edu:7080/app/login`. Hyperic configuration is out of scope for this document.

### SQL Server

The SQL Server environment is maintained and supported by the MGH Lab of Computer Science. The SQL Server environment is mirrored in real-time. Failover is not automatic.  In addition, the SQL Server environment is backup nightly and backups are transferred off-site. Transaction logs can also be used to restore lost data in the event of data loss. Please refer to the DBA contact for SQL Server support.




