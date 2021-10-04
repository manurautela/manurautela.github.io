---
layout: post
title:  "building windows driver with cmake and wdk from cmdline"
date:   2021-10-04 11:17:14 +0530
categories: driver, wdk, cmake, build, windows
---

**TL;DR**

[FindWdk](https://github.com/SergiusTheBest/FindWDK)

Having a clean and lightweight enviroment is what everyone wants. Building
drivers on windows is supported via visual studio with cmake support. But
having to open the bloated ui might not be on everyone's mind.

I really like FindWDK often which is CMake module for building drivers with WDK.


# Folder structure

```
│   .gitignore
│   .gitmodules
│   CMakeLists.txt
│   LICENSE
│   README.md
│
├───build
│       .ninja_deps
│       .ninja_log
│
├───FindWDK
│   │   .appveyor.yml
│   │   .editorconfig
│   │   .gitignore
│   │   LICENSE
│   │   README.md
│   │
│   ├───cmake
│   │       FindWdk.cmake
│   │
|   | **snipped**
│
└───simple
        CMakeLists.txt
        simple.c

```

**cmake file preset at root directory**

![root cmake file](/assets/images/findwdk/root_cmake.jpg)

**cmake file for simple driver**

![simple cmake file](/assets/images/findwdk/cmake_simple.jpg)

# Build steps
* Launch vcvars64.bat for VS2019
> %comspec% /k "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"

* mkdir build
* cd build
* cmake -G Ninja ..
* cmake --build . --config Debug --target simple

![build steps](/assets/images/findwdk/build_steps.jpg)


NOTE: The above steps used ninja the other option should work fine as well.

# Repo for a simple driver using FindWdk

[simple driver](https://github.com/manurautela/findwdk-simple)
