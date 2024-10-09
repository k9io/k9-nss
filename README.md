
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

If these prerequisites are met, you can build the library like this:

<pre>
$ make 
$ sudo mkdir -p /opt/k9/lib
$ sudo cp libnss_k9.so.2 /opt/k9/lib  # May need to change to match your arch!
$ cd /lib/x86_64-linux-gnu/
$ sudo ln -s /opt/k9/lib/libnss_k9.so.2 . 
$ sudo ldconfig
</pre>

Make sure you have your k9.yaml configured and stored in /opt/k9/etc/k9.yaml. This file can be found in the k9-ssh repo at https://github.com/k9io/k9-ssh/blob/main/etc/k9.yaml

Once that has been completed, you can enabled the k9-nss in your /etc/nsswitch.conf file.  Your configuration file might look something like this:

<pre>
passwd:         files
group:          files
shadow:         files
</pre>

Using your favorite editor,  append "k9" to the end of each line.  You only need to passwd to "passwd", "group" and "shadow".   It should look something like this:

<pre>
passwd:         files k9
group:          files k9
shadow:         files k9
</pre>

You can then use tools like "getent" to test and see if data is being pulled from Key9. 



