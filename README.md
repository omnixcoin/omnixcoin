What is Omnix?
-------------

Development resources:

1. Deploying a token to Omnix (https://github.com/omnixofficial/OMNIX20Token)
2. Omnix PlayBook - A Developer's Guide To OMNIX (Comming Soon)



Developer's Tools
-----------------

1. Smart contract deployment tool https://github.com/omnixofficial/solar (Comming Soon)
2. DApp JavaScript Library https://github.com/omnixofficial/Omnixjs (Coming Soon)
3. A toolkit for building omnix light wallets https://github.com/omnixofficial/Omnixjs-wallet (Coming Soon)
4. CORS omnixd RPC proxy for DApp https://github.com/omnixofficial/Omnix-Core/portal (Coming Soon)
5. Docker images for running omnix services https://github.com/omnixofficial/Omnix-docker (Coming Soon)
6. HTTP API that powers the block explorer and the OMNIX web wallet https://github.com/omnixofficial/insight-api-omnix


What is Omnix Core?
------------------

Omnix Core is our primary mainnet wallet. It implements a full node and is capable of storing, validating, and distributing all history of the Omnix network. Omnix Core is considered the reference implementation for the Omnix network.

Omnix Core currently implements the following:

1. Sending/Receiving Omnix
2. Sending/Receiving OMNIX20 tokens on the Omnix network
3. Staking and creating blocks for the Omnix network
4. Creating and interacting with smart contracts
5. Running a full node for distributing the blockchain to other users
6. Prune+ACI- mode, which minimizes disk usage
7. Regtest mode, which enables developers to very quickly build their own private Omnix network for Dapp testing
8. Compatibility with the Bitcoin Core set of RPC commands and APIs

Alternative Wallets
-------------------

Omnix Core uses a full node model, and thus requires downloading the entire blockchain. If you do not need the entire blockchain, and do not intend on developing smart contracts, it may be more ideal to use an alternative wallet such as one of our light wallets that can be synchronized in a matter of seconds.

Omnix Electrum (Coming Soon)

A light wallet that supports the Ledger hardware wallet and is based on the well known Electrum wallet software.

Download: https://github.com/omnixofficial/

iOS and Android Wallets (Coming Soon)

Android Download: https://github.com/omnixofficial/

iOS Download: https://github.com/omnixofficial/




Building Omnix Core
----------

#Build on Ubuntu

    This is a quick start script for compiling Omnix on  Ubuntu


    sudo apt-get install build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils git cmake libboost-all-dev
    sudo apt-get install software-properties-common
    sudo add-apt-repository ppa:bitcoin/bitcoin
    sudo apt-get update
    sudo apt-get install libdb4.8-dev libdb4.8++-dev

    #If you want to build the Qt GUI:
    sudo apt-get install libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools libprotobuf-dev protobuf-compiler qrencode

    git clone https://github.com/omnixofficial/Omnix-Core --recursive
    cd omnix

    #Note autogen will prompt to install some more dependencies if needed
    ./autogen.sh
    ./configure
    make -j2

#Build on CentOS

Here is a brief description for compiling Omnix on CentOS, for more details please refer to https://github.com/omnixofficial/Omnix-Core/blob/master/doc/build-unix.md

    #Compiling boost manually
    sudo yum install python-devel bzip2-devel
    git clone https://github.com/boostorg/boost.git
    cd boost
    git checkout boost-1.66.0
    git submodule update --init --recursive
    ./bootstrap.sh --prefix=/usr --libdir=/usr/lib64
    ./b2 headers
    sudo ./b2 -j4 install

    #Installing Dependencies for Omnix
    sudo yum install epel-release
    sudo yum install libtool libdb4-cxx-devel openssl-devel libevent-devel

    #If you want to build the Qt GUI:
    sudo yum install qt5-qttools-devel protobuf-devel qrencode-devel

    Building Omnix
    git clone --recursive https://github.com/omnixofficial/Omnix-Core.git
    cd omnix
    ./autogen.sh
    ./configure
    make -j4

#Build on OSX

The commands in this guide should be executed in a Terminal application.
The built-in one is located in `/Applications/Utilities/Terminal.app`.

#Preparation

Install the OS X command line tools:

`xcode-select --install`

When the popup appears, click `Install`.

Then install [Homebrew](https://brew.sh).

#Dependencies

    brew install cmake automake berkeley-db4 libtool boost --c++11 --without-single --without-static miniupnpc openssl pkg-config protobuf qt5 libevent imagemagick --with-librsvg qrencode

NOTE: Building with Qt4 is still supported, however, could result in a broken UI. Building with Qt5 is recommended.

#Build Omnix Core

1. Clone the omnix source code and cd into `omnix`

        git clone --recursive https://github.com/omnixofficial/Omnix-Core.git
        cd omnix

2.  Build omnix-core:

    Configure and build the headless omnix binaries as well as the GUI (if Qt is found).

    You can disable the GUI build by passing `--without-gui` to configure.

        ./autogen.sh
        ./configure
        make

3.  It is recommended to build and run the unit tests:

        make check

#Run

Then you can either run the command-line daemon using `src/omnixd` and `src/omnix-cli`, or you can run the Qt GUI using `src/qt/omnix-qt`

License
-------

Omnix is GPLv3 licensed.


Development Process
-------------------

The master branch is regularly built and tested, but is not guaranteed to be
completely stable. Tags (https://github.com/omnixofficial/Omnix-Core/tags) are created
regularly to indicate new official, stable release versions of Omnix.

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md).

Developer Chat can be found on Discord

Testing
-------

Testing and code review is the bottleneck for development+ADs- we get more pull
requests than we can review and test on short notice. Please be patient and help out by testing
other people's pull requests, and remember this is a security-critical project where any mistake might cost people
lots of money.

#Automated Testing

Developers are strongly encouraged to write 'unit tests' (src/test/README.md) for new code, and to
submit new unit tests for old code. Unit tests can be compiled and run
(assuming they weren't disabled in configure) with: 'make check'. Further details on running
and extending unit tests can be found in '/src/test/README.md' (/src/test/README.md).

There are also +'regression and integration tests' (/test), written
in Python, that are run automatically on the build server.
These tests can be run (if the 'test dependencies' (/test) are installed) with: 'test/functional/test-runner.py'

#Manual Quality Assurance (QA) Testing

Changes should be tested by somebody other than the developer who wrote the
code. This is especially important for large or high-risk changes. It is useful
to add a test plan to the pull request description if testing the changes is
not straightforward.
