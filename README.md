# Pico OpenPGP
This project aims at transforming your Raspberry Pico into a Smart Card with an OpenPGP applet integrated. The Pico works as a reader with an embedded OpenPGP card, like a USB card.

OpenPGP cards are used to manage PGP keys and do cryptographic operations, such as keypair generation, signing and asymmetric deciphering. Pico OpenPGP follows the [**OpenPGP 3.4.1** specifications](https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf "**OpenPGP 3.4.1** specifications"), available at [GnuPG](http://gnupg.org "GnuPG").

## Features
Pico OpenPGP has implemented the following features:

- Key generation and encrypted storage.
- RSA key generation from 1024 to 4096 bits.
- ECDSA key generation from 192 to 521 bits.
- ECC curves secp256r1, secp384r1, secp521r1, brainpoolP256r1, brainpoolP384r1, brainpoolP512r1, secp256k1.
- SHA1, SHA224, SHA256, SHA384, SHA512 digests.
- RSA-PKCS and raw RSA signature.
- ECDSA raw and hash signature.
- ECDH key derivation.
- PIN authorization.
- PKCS11 compliant interface.
- HRNG (hardware random number generator).
- Device Encryption Key (DEK).
- USB/CCID support with OpenSC, openssl, etc.
- Extended APDU support.
- Lifecycle card (termination and activation).

All these features are compliant with the specification. Therefore, if you detect some behaviour that is not expected or it does not follow the rules of specs, please open an issue.

### About Gnuk
This project was inspired by [Gnuk](https://wiki.debian.org/GNUK "Gnuk"), a same project but focused on STM32 processor family. Despite the initial idea was to port Gnuk to the Raspberry Pico family, the underlaying architecture is widely different (although they run on ARM). For instance, the Pico has two ARM cores, with an appropiate SDK able to leverage them. Also, Pico has an internal flash storage, which is farly larger compared to STM32 ROM storage. Finally, the Pico has a complete USB interface based on TinyUSB, which difficults to port Gnuk. These are only few examples of the difficulties of porting Gnuk to the Raspberry Pico.

As a consequence, Pico OpenPGP is designed from zero. Well, not strictly from zero, as it borrows some of the buffering between USB and CCID interfaces from Gnuk. Cryptographic operations are implemented with MBEDTLS library.

## Security considerations
All secret keys (asymmetric and symmetric) are stored encrypted in the flash memory of the Raspberry Pico. DEK is used as a 256 bit AES key to protect private and secret keys. Keys are never stored in RAM except for signature and decryption operations and only during the process. All keys (including DEK) are loaded and cleared every time to avoid potential security flaws.

At the same time, DEK is encrypted with doubled salted and hashed PIN. Also, the PIN is hashed in memory during the session. Hence, PIN is never stored in plain text neither in flash nor in memory. Note that PIN is conveyed from the host to the Pico in plain text if no secure channel is provided.

If the Pico is stolen the contents of private and secret keys cannot be read without the PIN, even if the flash memory is dumped.

## Download
Please, go to the [Release page](https://github.com/polhenarejos/pico-openpgp/releases "Release page"))  and download the UF2 file for your board.

Note that UF2 files are shiped with a dummy VID/PID to avoid license issues (FEFF:FCFD). If you are planning to use it with OpenSC or similar, you should modify Info.plist of CCID driver to add these VID/PID or use the VID/PID patcher as follows: ./patch_vidpid.sh VID:PID input_openpgp_file.uf2 output_openpgp_file.uf2

You can use whatever VID/PID (i.e., 234b:0000 from FISJ), but remember that you are not authorized to distribute the binary with a VID/PID that you do not own.

## Build
Before building, ensure you have installed the toolchain for the Pico and the Pico SDK is properly located in your drive.

    git clone https://github.com/polhenarejos/pico-openpgp
    cd pico-openpgp
    mkdir build
    cd build
    PICO_SDK_PATH=/path/to/pico-sdk cmake .. -DPICO_BOARD=board_type -DUSB_VID=0x1234 -DUSB_PID=0x5678
    make

Note that PICO_BOARD, USB_VID and USB_PID are optional. If not provided, pico board and VID/PID FEFF:FCFD will be used.

After make ends, the binary file pico_openpgp.uf2 will be generated. Put your pico board into loading mode, by pushing BOOTSEL button while pluging on, and copy the UF2 to the new fresh usb mass storage Pico device. Once copied, the pico mass storage will be disconnected automatically and the pico board will reset with the new firmware. A blinking led will indicate the device is ready to work.

## Operation time
### Keypair generation
Generating EC keys is almost instant. RSA keypair generation takes some time, specially for 3072 and 4096 bits.
### Keypair generation
Generating EC keys is almost instant. RSA keypair generation takes some time, specially for `3072` and `4096` bits. 

| RSA key length (bits) | Average time (seconds) |
| :---: | :---: |
| 1024 | 16 |
| 2048 | 124 |
| 3072 | 600 |
| 4096 | ~1000 |

### Signature and decrypt
| RSA key length (bits) | Average time (seconds) |
| :---: | :---: |
| 1024 | 1 |
| 2048 | 3 |
| 3072 | 7 |
| 4096 | 15 |

## Led blink
Pico OpenPGP uses the led to indicate the current status. Four states are available:
### Press to confirm
The Led is almost on all the time. It goes off for 100 miliseconds every second.

![Press to confirm](https://user-images.githubusercontent.com/55573252/162008917-6a730eac-396c-44cc-890e-802294be30a3.gif)

### Idle mode
In idle mode, the Pico OpenPGP goes to sleep. It waits for a command and it is awaken by the driver. The Led is almost off all the time. It goes on for 500 milliseconds every second.

![Idle mode](https://user-images.githubusercontent.com/55573252/162008980-d5a5caad-072e-400c-98e3-2c606b4b2af9.gif)

### Active mode
In active mode, the Pico OpenPGP is awaken and ready to receive a command. It blinks four times in a second.

![Active](https://user-images.githubusercontent.com/55573252/162008997-1ea8cd7e-5384-4893-9dcb-b473153fc375.gif)

### Processing
While processing, the Pico OpenPGP is busy and cannot receive additional commands until the current is processed. In this state, the Led blinks 20 times in a second.

![Processing](https://user-images.githubusercontent.com/55573252/162009007-df45111e-2473-4a92-97c5-15c3cd19babd.gif)

## Driver

Pico OpenPGP uses the `openpgp` driver provided by [OpenSC](https://github.com/OpenSC/OpenSC/ "OpenSC"). This driver utilizes the standardized PKCS#11 interface to communicate with the user and it can be used with many engines that accept PKCS#11 interface, such as OpenSSL, P11 library or pkcs11-tool. 

It also accepts the use of GnuPG programs (`gpg` and `gpg2`) to manipulate the card. For instance, it can be used with the `gpg --edit-card --expert` interface to change the cryptographic keys, generate new keypairs or simply set the cardholder name.

Pico OpenPGP relies on PKCS#15 structure to store and manipulate the internal files (PINs, private keys, certificates, etc.) and directories. Therefore, it accepts the commands from `pkcs15-tool`. For instance, `pkcs15-tool -D` will list all elements stored in the Pico OpenPGP.

The way to communicate is exactly the same as with other cards, such as OpenPGP or similar.

### Important
OpenSC relies on PCSC driver, which reads a list (`Info.plist`) that contains a pair of VID/PID of supported readers. In order to be detectable, you must patch the UF2 binary (if you just downloaded from the [Release section](https://github.com/polhenarejos/pico-openpgp/releases "Release section")) or configure the project with the proper VID/PID with `USB_VID` and `USB_PID` parameters in `CMake` (see [Build section](#build "Build section")). Note that you cannot distribute the patched/compiled binary if you do not own the VID/PID or have an explicit authorization.

## Credits
Pico OpenPGP uses the following libraries or portion of code:
- mbedTLS for cryptographic operations.
- gnuk for low level CCID procedures support.
- TinyUSB for low level USB procedures.

