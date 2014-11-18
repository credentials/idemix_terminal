# Idemix terminal

This library provides a terminal implementation to bridge between the Idemix 
cryptographic library and an Idemix capable smart card. There are basically
two modes of operation. The first mode uses a SCUBA CardService to interact
directly with the smart card. The second mode is used for asynchronous or
indirect communication with the card. Hence the library only constructs the
protocol commands to be send to the card, whereas the developer is responsible
for performing the actual communication with the card.


## Prerequisites

This library has the following dependencies.  All these dependencies will be automatically downloaded by gradle when building or installing the library.

Internal dependencies:

 * [credentials/idemix_library](https://github.com/credentials/idemix_library) The Idemix library
 * [credentials/scuba](https://github.com/credentials/scuba/), scuba_smartcards The Scuba smart-card abstraction layer

Note that you must make sure that you [build and install the idemix_library](https://github.com/credentials/idemix_library/) yourself.

## Building using Gradle (recommended)

When you are using the Gradle build system, just run

    gradle install

to install the library to your local repository. Alternatively, you can run

    gradle build

to just build the library.

## Eclipse development files

You can run

    gradle eclipse

to create the required files for importing the project into Eclipse.
