---
layout: posts
title:  "parsing sysmon events using krabs etw"
date:   2021-10-05 11:17:14 +0530
categories: etw, krabsetw, windows, sysmon
---

**TL;DR**

> krabsetw is a C++ library that simplifies interacting with ETW. It allows for
> any number of traces and providers to be enabled and for client code to
> register for event notifications from these traces. krabsetw also provides
> code to simplify parsing generic event data into strongly typed data types.

[krabsetw](https://github.com/microsoft/krabsetw)

The repo has sufficient docs and examples to go through.
I was just playing with parsing sysmon events a while back for something.

[sysmon events parse](https://gist.github.com/manurautela/1c5079dff426c338aa9e2fe6e3f8d0de)


# Steps
Clone and build the project from krabsetw repo with code shared above.
* make sure sysmon is installed
* launch **NativeExamples.exe**
* watch the events fly by.

# Code
![setup](/assets/images/sysmon-krabsetw/setup_krabsetw.jpg)

<br>

**sample output when the application is run with sysmon installed**

___

![output](/assets/images/sysmon-krabsetw/sysmon_output.jpg)


Enjoy and Profit ;)
