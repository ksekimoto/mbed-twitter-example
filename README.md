# mbed-twitter-example

The mbed-twitter-example is a sample program which tweets a specified string by using Twitter API.

https://twitter.com/fm3fan2012/status/948272313413246976

It is tested on GR-PEACH rev.C (with ESP8266 board) and GR-LYCHEE rev.C (with ESP32 module).

## How to build

To build the program, Mbed CLI is needed.
For Mbed CLI, please refer to https://github.com/ARMmbed/mbed-cli
https://os.mbed.com/users/MACRUM/notebook/mbed-offline-development/ 

### Download source files
>mbed import https://github.com/ksekimoto/mbed-twitter-example

>cd mbed-twitter-example

### Prepare for Twitter API information
add twitter api comsumer_key and comsumer_secret in twitter_conf.h

add twitter api access_token and access_token_secret in twitter_conf.h

### Build For GR-PEACH
>mbed compile -m RZ_A1H -t GCC_ARM --profile debug

### Build For GR-LYCHEE
For GR-LYCHEE
>mbed compile -m GR_LYCHEE -t GCC_ARM --profile debug

Reference
- https://os.mbed.com/platforms/Renesas-GR-PEACH/
- http://gadget.renesas.com/ja/product/peach.html
- https://os.mbed.com/platforms/Renesas-GR-LYCHEE/
- http://gadget.renesas.com/ja/product/lychee.html 