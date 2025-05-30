# Pico OpenPGP
This project aims at transforming your Raspberry Pico or ESP32 microcontroller into a Smart Card with an OpenPGP applet integrated. The Pico works as a reader with an embedded OpenPGP card, like a USB card.

OpenPGP cards are used to manage PGP keys and do cryptographic operations, such as keypair generation, signing and asymmetric deciphering. Pico OpenPGP follows the [**OpenPGP 3.4.1** specifications](https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf "**OpenPGP 3.4.1** specifications"), available at [GnuPG](http://gnupg.org "GnuPG").

If you are looking for a OpenPGP + Fido, see: https://github.com/polhenarejos/pico-fido2

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
- Press-to-confirm button.
- User Interaction Flag for enabling/disabling press-to-confirm button.
- Key Derivation Function (KDF) for PIN.
- Manage Security Environment (MSE).
- DEK for internal safe storage.
- AES key generation.
- AES ciphering and deciphering.
- Cardholder certificates support.
- Secure Boot and Secure Lock in RP2350 and ESP32-S3 MCUs.
- One Time Programming to store the master key that encrypts all resident keys and seeds.
- Rescue interface to allow recovery of the device if it becomes unresponsive or undetectable.
- LED customization with Pico Commissioner.

All these features are compliant with the specification. Therefore, if you detect some behaviour that is not expected or it does not follow the rules of specs, please open an issue.

## AES support
There is no known software that supports AES with OpenPGP. Nevertheless, it can be used with customized PKCS11 modules or interfacing with raw APDU packets.

During asymmetric key generation for DEC key, Pico OpenPGP also generates a 32 bits symmetric key for AES operations.

OpenPGP card 3.4 specifications describe the procedure to perform ciphering (encryption and decryption) with AES via PSO:ENCIPHER and PSO:DECIPHER. Both commands are supported by Pico OpenPGP.

### About Gnuk
This project was inspired by [Gnuk](https://wiki.debian.org/GNUK "Gnuk"), a same project but focused on STM32 processor family. Despite the initial idea was to port Gnuk to the Raspberry Pico family, the underlaying architecture is widely different (although boh run on ARM). For instance, the Pico has two ARM cores, with an appropiate SDK able to leverage them. Also, Pico has an internal flash storage, which is farly larger compared to STM32 ROM storage. Finally, the Pico has a complete USB interface based on TinyUSB, which difficults to port Gnuk. These are only few examples of the difficulties of porting Gnuk to the Raspberry Pico.

As a consequence, Pico OpenPGP is designed from zero. Well, not strictly from zero, as it borrows some of the cryptographic operations implemented with MbedTLS library.

Whilst Gnuk is OpenPGP 2.0 with small set of enhancements, Pico OpenPGP aims at being OpenPGP 3.4 compliant, with new features (not present in Gnuk), such as Manage Security Environment (MSE) or UIF.

## Security considerations
All secret keys (asymmetric and symmetric) are stored encrypted in the flash memory of the Raspberry Pico using a Device Encyrption Key (DEK). DEK is a 256 bit AES key used to protect private and secret keys. Keys are never stored in RAM except for signature and decryption operations and only during the process. All keys (including DEK) are loaded and cleared every time to avoid potential security flaws.

At the same time, DEK is encrypted with doubled salted and hashed PIN. For RP2350 and ESP32-S3 microcontrollers it is masked by a secure device 32 bytes key. Also, the PIN is hashed in memory during the session. Hence, PIN is never stored in plain text neither in flash nor in memory. Note that PIN is conveyed from the host to the Pico in plain text if no secure channel is provided.

If the Pico is stolen the contents of private and secret keys cannot be read without the PIN, even if the flash memory is dumped.

### RP2350 and ESP32-S3
RP2350 and ESP32-S3 microcontrollers are equipped with advanced security features, including Secure Boot and Secure Lock, ensuring that firmware integrity and authenticity are tightly controlled. Both devices support the storage of the Device Encryption Key (DEK) in an OTP (One-Time Programmable) memory region, making it permanently inaccessible for external access or tampering. This secure, non-volatile region guarantees that critical security keys are embedded into the hardware, preventing unauthorized access and supporting robust defenses against code injection or firmware modification. Together, Secure Boot and Secure Lock enforce firmware authentication, while the DEK in OTP memory solidifies the foundation for secure operations.

### Secure Boot
Secure Boot is a security feature that ensures that only trusted firmware, verified through digital signatures, can be loaded onto the device during the boot process. Once enabled, Secure Boot checks every piece of firmware against a cryptographic signature before execution, rejecting any unauthorized or modified code. This prevents malicious firmware from compromising the device’s operation and integrity. With Secure Boot activated, only firmware versions signed by a trusted authority, such as the device manufacturer, will be accepted, ensuring the device remains protected from unauthorized software modifications. **This is irreversible. Once enabled, it CANNOT be disabled.**

**IMPORTANT:** For users wishing to develop and compile custom firmware, a private-public key pair is essential. Activating Secure Boot requires users to generate and manage their own unique private-public key pair. The public key from this pair must be embedded into the device to validate all firmware. Firmware will not boot without a proper digital signature from this key pair. This means that users must sign all future firmware versions with their private key and embed the public key in the device to ensure compatibility.

### Secure Lock
Secure Lock builds on Secure Boot by imposing an even stricter security model. Once activated, Secure Lock prevents any further installation of new boot keys, effectively locking the device to only run firmware that is authorized by the device's primary vendor—in this case, Pico Keys. In addition to preventing additional keys, Secure Lock disables debugging interfaces and puts additional safeguards in place to resist tampering and intrusion attempts. This ensures that the device operates exclusively with the original vendor’s firmware and resists unauthorized access, making it highly secure against external threats. **This is irreversible. Once enabled, it CANNOT be disabled.**

**IMPORTANT:** Activating Secure Lock not only enables Secure Boot but also invalidates all keys except the official Pico Key. This means that only firmware signed by Pico Key will be recognized, and custom code will no longer be allowed. Once enabled, the Pico Key device will run solely on the official firmware available on the website, with no option for generating or compiling new code for the device.

## Download
**If you own an ESP32-S3 board, go to [ESP32 Flasher](https://www.picokeys.com/esp32-flasher/) for flashing your Pico OpenPGP.**

If you own a Raspberry Pico (RP2040 or RP2350), go to [Download page](https://www.picokeys.com/getting-started/), select your vendor and model and download the proper firmware; or go to [Release page](https://www.github.com/polhenarejos/pico-openpgp/releases/) and download the UF2 file for your board.

Note that UF2 files are shiped with a dummy VID/PID to avoid license issues (FEFF:FCFD). If you plan to use it with OpenSC or similar tools, you should modify Info.plist of CCID driver to add these VID/PID or use the [Pico Commissioner](https://www.picokeys.com/pico-commissioner/ "Pico Commissioner").

You can use whatever VID/PID (i.e., 234b:0000 from FISJ), but remember that you are not authorized to distribute the binary with a VID/PID that you do not own.

Note that the pure-browser option [Pico Commissioner](https://www.picokeys.com/pico-commissioner/ "Pico Commissioner") is the most recommended.

## Build for Raspberry Pico
Before building, ensure you have installed the toolchain for the Pico and the Pico SDK is properly located in your drive.
```
git clone https://github.com/polhenarejos/pico-openpgp
git submodule update --init --recursive
cd pico-openpgp
mkdir build
cd build
PICO_SDK_PATH=/path/to/pico-sdk cmake .. -DPICO_BOARD=board_type -DUSB_VID=0x1234 -DUSB_PID=0x5678
make
```
Note that `PICO_BOARD`, `USB_VID` and `USB_PID` are optional. If not provided, `pico` board and VID/PID `FEFF:FCFD` will be used.

Additionally, you can pass the `VIDPID=value` parameter to build the firmware with a known VID/PID. The supported values are:

- `NitroHSM`
- `NitroFIDO2`
- `NitroStart`
- `NitroPro`
- `Nitro3`
- `Yubikey5`
- `YubikeyNeo`
- `YubiHSM`
- `Gnuk`
- `GnuPG`

After running `make`, the binary file `pico_openpgp.uf2` will be generated. To load this onto your Pico board:

1. Put the Pico board into loading mode by holding the `BOOTSEL` button while plugging it in.
2. Copy the `pico_openpgp.uf2` file to the new USB mass storage device that appears.
3. Once the file is copied, the Pico mass storage device will automatically disconnect, and the Pico board will reset with the new firmware.
4. A blinking LED will indicate that the device is ready to work.

## Operation time
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
OpenSC relies on PCSC driver, which reads a list (`Info.plist`) that contains a pair of VID/PID of supported readers. In order to be detectable, you have several options:
- Use the pure-browser online [Pico Commissioner](https://www.picokeys.com/pico-commissioner/ "Pico Commissioner") that commissions the Pico Key on-the-fly without external tools.
- Build and configure the project with the proper VID/PID with `USB_VID` and `USB_PID` parameters in `CMake` (see [Build section](#build "Build section")). Note that you cannot distribute the patched/compiled binary if you do not own the VID/PID or have an explicit authorization.

## Credits
Pico OpenPGP uses the following libraries or portion of code:
- MbedTLS for cryptographic operations.
- TinyUSB for low level USB procedures.

