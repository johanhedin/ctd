ctd
====
`ctd` is a small example how to build a C++ deamon application with cmake. It
include examples of how to parse command line arguments and how read yaml
config. The cmake files work with cmake from 2.8.12 all the way up to 3.28.

Download and build
----
Clone `ctd` from GitHub with the needed submodules:

    $ git clone https://github.com/johanhedin/ctd.git
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
    $ cd build
    $ cmake ..
    $ make
