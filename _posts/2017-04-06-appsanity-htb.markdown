---
layout: post
title: Appsanity
date: 2023-10-31
description:
img:
fig-caption:
tags: []
---
___

<center><img src="/writeups/assets/img/Appsanity-htb/Appsanity.png" alt="" style="height: 394px; width:520px;"></center>

***

# Conocimientos



***

# Reconocimiento

## Escaneo de puertos con nmap

### Descubrimiento de puertos abiertos

```null
nmap -p- --open --min-rate 5000 -n -Pn -sS 10.129.128.10 -oG openports
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-31 16:29 GMT
Nmap scan report for 10.129.128.10
Host is up (0.089s latency).
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
80/tcp   open  http
443/tcp  open  https
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 26.72 seconds
```

### Escaneo de versión y servicios de cada puerto

```null
nmap -sCV -p80,443,5985 10.129.128.10 -oN portscan
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-31 16:34 GMT
Nmap scan report for 10.129.128.10
Host is up (0.073s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to https://meddigi.htb/
443/tcp  open  https?
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.23 seconds
```

Añado el dominio ```meddigi.htb``` al ```/etc/hosts```

## Puerto 80,443 (HTTP, HTTPS)

Con ```whatweb``` analizo las tecnologías que emplea el servidor web

```null
whatweb http://10.129.128.10
http://10.129.128.10 [302 Found] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.129.128.10], Microsoft-IIS[10.0], RedirectLocation[https://meddigi.htb/], Title[Document Moved]
https://meddigi.htb/ [200 OK] Bootstrap, Cookies[.AspNetCore.Mvc.CookieTempDataProvider], Country[RESERVED][ZZ], Email[support@meddigi.htb], HTML5, HTTPServer[Microsoft-IIS/10.0], HttpOnly[.AspNetCore.Mvc.CookieTempDataProvider], IP[10.129.128.10], JQuery, Microsoft-IIS[10.0], Script, Strict-Transport-Security[max-age=2592000], Title[MedDigi]
```

La página principal se ve así:

<img src="/writeups/assets/img/Appsanity-htb/1.png" alt="">

Puedo ver un panel de inicio de sesión

<img src="/writeups/assets/img/Appsanity-htb/2.png" alt="">

Creo una cuenta y accedo a la interfaz

<img src="/writeups/assets/img/Appsanity-htb/3.png" alt="">

Este menú consta de un formulario para cambiar la información personal y un apartado para enviar un mensaje al supervisor

<img src="/writeups/assets/img/Appsanity-htb/4.png" alt="">

Vuelvo a registrarme, pero esta vez interceptando la petición. Se añade el parámetro por POST ```Acctype``` igualado a uno

<img src="/writeups/assets/img/Appsanity-htb/5.png" alt="">

Al cambiarlo a 2, el rol se me asigna con más privilegios y en el menú puedo ver los pacientes

