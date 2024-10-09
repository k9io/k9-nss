
Join the Key9 Slack channel
---------------------------

[![Slack](./images/slack.png)](https://key9identity.slack.com/)


What is they Key9 NSS?
----------------------

Key9 is a provider of "Identity and Access Management" that offers a completely "passwordless" solution. The concept behind Key9 is that by not storing passwords, there is nothing for hackers to steal.


Key9 NSS (Network Security Services) is a shared library used by operating systems (Linux, etc.) to look up user and authentication data from the Key9 API.  


What software uses they Key9 SSH?
---------------------------------

Operating system (Linux, OpenBSD, etc).


Building and installing the Key9 NSS
------------------------------------

Building k9-nss requires a C compiler and the following external libraries. 

<pre>
   * libcurl ( https://curl.se/libcurl/ ) 
	- apt-get install libcurl4-openssl-dev

   * libyaml ( https://github.com/yaml/libyaml )
	- apt-get install libyaml-dev

   * libjson-c ( https://github.com/json-c/json-c )
	- apt-get install libjson-c-dev

   * libpthread
</pre>



