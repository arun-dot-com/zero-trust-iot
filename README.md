# Zero trust Module for IoT devices in  ns-3

# Getting Started

1. Clone the ns-3 mainline code

    ```bash
    git clone -b ns-3.45 https://gitlab.com/nsnam/ns-3-dev.git
    ```
2. Change into the contrib directory

    ```bash
    cd contrib
    ```
3. Clone the Zero Trust Simulation Module

    ```bash

    ```
4. Configure ns-3 and build it. Ensure the following [cryptopp](https://github.com/weidai11/cryptopp) is installed:

    ```bash
    ./ns3 configure --enable-examples --enable-qpp --enable-crypto
    ```

    ```bash
    ./ns3 build
    ```
5. Run the examples:

   ```bash
   ./ns3 run 
   ```
