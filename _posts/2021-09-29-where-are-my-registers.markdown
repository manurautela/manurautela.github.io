---
layout: post
title:  "Lost registers during kernel debugging Win7"
date:   2021-09-29 11:17:14 +0530
categories: windbg, debugging, win7
---

When kernel debugging an old target like Windows 7 after a long time using windbg. I noticed not being able to see the registers in register pane. That was kind of frustated at times, when there was a real need to have a look at them instead of doing an 'r' command each time in command window.

TL;DR

![registers not visible](/assets/images/registers.jpg)

Here is a really neat windbg extension named `wingdbg` that solves the issue.

# Extension repository
[wingdbg](https://github.com/mbikovitsky/WingDbg)

[compilation](https://github.com/mbikovitsky/WingDbg/issues/2)

# Setup

Copy the extension over to your extension path set via .extpath or default path.

```
.load wingdbg.dll
!regfix
```