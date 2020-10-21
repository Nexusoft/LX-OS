### Quick Start

#### Building RefOS

In order to build RefOS's codebase:

1. Read: https://wiki.sel4.systems/Getting_started#Setting_up_your_machine. Set up the environment
   (repo tool, cross compilers and build dependencies) as per the instructions on the page.

2. Install the following packages (package named based on Ubuntu 14.04):
   > sudo apt-get install python-tempita

3. make help (to list the default configurations)

4. make \<config\>, where \<config\> is one of the configurations listed with the \<make help\> command:
   eg. make kzm\_debug\_test\_defconfig

5. make silentoldconfig

6. make

   You should now have a bootable system image (refos/images/refos-image).


7. make simulate-kzm (or a different command depending on the configuration you chose, run \<make help\>
   to list the different configurations and how to run them)

Overview
--------

The repository is organised as follows.

 * [`impl/apps`](impl/apps/): RefOS system and userland applications
    * [`selfloader`](impl/apps/selfloader/): Bootstrap application, which is responsible for starting
      user processes.
    * [`process_server`](impl/apps/process_server/): The process server, which runs as the root
      task and provides process and thread abstraction and initialises the entire system.
    * [`file_server`](impl/apps/file_server/): The cpio file server, which stores files and
      executables in a cpio archive and exposes them via a dataspace interface.
    * [`console_server`](impl/apps/console_server/): The console server, a system process which acts
      as the console device driver and manages serial input and output and EGA text mode output.
    * [`timer_server`](impl/apps/timer_server/): The timer server, a userland driver process which
      manages the timer device and provides timer get time and sleep functionality.
    * [`terminal`](impl/apps/terminal/): The interactive terminal application.
    * [`test_os`](impl/apps/test_os/): RefOS operating system level test suite, which tests the
      operating system environment.
    * [`test_user`](impl/apps/test_os/): RefOS user-level test application, which is responsible for
      testing the operating system user environment.
    * [`snake`](impl/apps/snake/): Example snake game.
    * [`tetris`](impl/apps/tetris/): Example tetris game.
    * [`nethack`](impl/apps/nethack/): Port of Nethack 3.4.3 roguelike game.
 * [`impl/libs`](impl/libs/): RefOS system and userland applications
    * [`libdatastruct`](impl/libs/libdatastruct/): RefOS library that provides simple C data structures such as
      vectors, hash tables and allocation tables.
    * [`librefos`](impl/libs/librefos/): RefOS user and server shared definitions, RPC specifications and
      generated stubs and low level helper libraries.
    * [`librefossys`](impl/libs/librefossys/): RefOS library that implements some POSIX system calls using low-level
      RefOS and thus allows the C library to work. This directory is intended to simplify RefOS 
      userland applications and facilitate porting.
 * [`impl/docs`](impl/docs/): RefOS doxygen code documentation.
 * [`design`](design/): RefOS protocol design document.

License
-------

The files in this repository are released under standard open source
licenses. RefOS code is released under the BSD license where possible and GPL for some
external software. Please see the individual file headers and
[`LICENSE_BSD2.txt`](LICENSE_BSD2.txt) for details.

Please note that RefOS is intended to be sample code and is not high assurance software.
We are not reponsible for any consequences if you choose to deploy this software in
production.
