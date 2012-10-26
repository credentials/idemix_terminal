* Idemix terminal

This library provides a terminal implementation to bridge between the Idemix 
cryptographic library and an Idemix capable smart card. There are basically
two modes of operation. The first mode uses a SCUBA CardService to interact
directly with the smart card. The second mode is used for asynchronous or
indirect communication with the card. Hence the library only constructs the
protocol commands to be send to the card, whereas the developer is responsible
for performing the actual communication with the card.

