ctd
====
[![C++ CI](https://github.com/johanhedin/ctd/actions/workflows/ci.yaml/badge.svg)](https://github.com/johanhedin/ctd/actions/workflows/ci.yaml)

`ctd` is a small example how to build a deamon with C++17 and cmake. It include
examples of how to parse command line arguments with `argparse`, how read yaml
configuration files with `yaml-cpp` and how to log with `spdlog`. The cmake files
work with cmake from 3.6 all the way up to 3.28.

Requirements
----
`ctd` builds on a great variety of Linux distributions as long as cmake 3.6 and
g++ 9.x or newer are available. On CentOS 6 g++ 9.1 is available from the
devtoolset-9 SCL and cmake 3.6 is available from EPEL.

Download and build
----
Clone `ctd` from GitHub with the needed submodules:

    $ git clone --recurse-submodules https://github.com/johanhedin/ctd.git
    $ cd ctd

and then build with cmake:

    $ mkdir build
    $ cd build
    $ cmake .. -DCMAKE_BUILD_TYPE=Release
    $ make

`cte` accepts the following build options on the command line (set with -D):

 * `CMAKE_BUILD_TYPE={Debug,Release,RelWithDebInfo}` Defaults to `Debug` if not set
 * `CMAKE_INSTALL_PREFIX=<path>` Defaults to `/usr/local` if not set

Keep up to date with changes
----
To keep up to date with changes and updates to `ctd`, simply run:

    $ cd ctd
    $ git pull --ff-only
    $ git submodule update --init --recursive
    $ cd build
    $ cmake ..
    $ make
