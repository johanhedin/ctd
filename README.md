ctd
====
[![C++ CI](https://github.com/johanhedin/ctd/actions/workflows/ci.yaml/badge.svg)](https://github.com/johanhedin/ctd/actions/workflows/ci.yaml)

`ctd` is a skeleton of a small threded deamon written in  C++17. The skeleton
include examples of how to parse command line arguments with `argparse`, how read
yaml configuration files with `yaml-cpp`, how to log with `spdlog`, how to
embed a small HTTP REST server with `cpp-httplib` and how to handle JSON with
`nlohmann/json`. CMake is used as the build system and the configuration works
with cmake from 3.6 all the way up to 3.28.

Requirements
----
`ctd` builds on a great variety of Linux distributions as long as cmake 3.6 and
g++ 9.x or newer are available. It even builds on the EOL CentOS 6 (where g++ 9.1
is available from the devtoolset-9 SCL and cmake 3.6 is available from EPEL).

All external libraries that `ctd` depend on are linked as git submodules and
the compiled binary does not link to any extra libraries.

Download and build
----
Clone `ctd` and the required submodules from GitHub:

    $ git clone --recurse-submodules https://github.com/johanhedin/ctd.git
    $ cd ctd

Then configure and build with cmake:

    $ mkdir build
    $ cd build
    $ cmake .. -DCMAKE_BUILD_TYPE=Release
    $ make

`ctd` cmake accepts the following command line configuration options (set with -D):

 * `CMAKE_BUILD_TYPE={Debug,Release,RelWithDebInfo}` Defaults to `Debug` if not set
 * `CMAKE_INSTALL_PREFIX=<path>` Defaults to `/usr/local` if not set

Keep up to date with changes
----
To keep up to date with changes in `ctd`, simply run:

    $ cd ctd
    $ git pull --ff-only
    $ git submodule update --init --recursive
    $ cd build
    $ cmake ..
    $ make
