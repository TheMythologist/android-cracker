# Android Cracker

This is a little tool to crack the pattern lock on Android devices.
This tool works **up to Android 8.0 (included)**. Android 6.0 introduces Gatekeeper and changes the way it store the password/pattern/pin.

## General information

Files can be pulled via `adb` (from a rooted phone).

```bash
adb pull /data/system/<file_of_interest>
```

Files of interest are listed below in their respective modules.

The key length as well as other information (e.g. number of digits and letters respectively) can be found in `/data/system/device_policies.xml` (only applies for Android versions < 8.0).

## Installation/running of android-cracker

### Installation via pip **(recommended)**

  ```bash
  pip install android-cracker
  android-cracker -h
  ```

### Installation from source

  ```bash
  # Clone the repository
  git clone https://github.com/TheMythologist/android-cracker.git

  # Ensure poetry is installed
  pip install poetry

  # Running via poetry
  poetry install
  poetry run android-cracker -h

  # Running via pip installation
  cd android-cracker
  pip install .
  android-cracker -h
  ```

## How does this tool work?

## Android 5.1 and below

### How does the pattern lock work?

For pattern locks, the hash of interest is stored in `/data/system/gesture.key`.

The pattern lock is just the SHA1 hash sequence of digits (0-8) with length from 3 (4 since Android 2.3.3) to 9.

The gesture board is a 3x3 matrix, and can be repressented as follows (each digit represents a "ball"):

```
-------------------
| 0 |  | 1 |  | 2 |
-------------------
| 3 |  | 4 |  | 5 |
-------------------
| 6 |  | 7 |  | 8 |
-------------------
```

So if you set the pattern lock to 0 -> 1 -> 2 -> 5 -> 4, the SHA1 hash will be output of SHA1("\x00\x01\x02\x05\x04").

### How does the PIN/password lock work?

For PINs and password locks, the hash of interest is stored in `/data/system/password.key`. You will also need to dump out the salt used during the hashing, which can be found in the following files:

- locksettings.db
- locksettings.db-shm
- locksettings.db-wal

`/data/system/locksettings.db` is a sqlite file and you can open it with sqlite3 cmdline tool or the [DB browser](https://sqlitebrowser.org/).

The pin lock contains 4 digits (0-9) and the password is a sequence of digits (0-9) and/or alphabet (a-z, A-Z) with length of 4 or more. Android adds a salt to the end of pin/password, and calculates the SHA1 and MD5 hashes of the salted password.

## Android 6.0 to 8.0

For gestures, the gesture is represented as an integer of "balls" in order (e.g. 1258). (Note the change in the digits, as the digits are now from 1-9 instead of the previous 0-8. The hashed sequence is also now in raw integer format instead of the previous hexstring.) The relevant files are located either in `/data/system/gatekeeper.password.key` for PINS and passwords, or `/data/system/gatekeeper.gesture.key` for gestures.

All gatekeeper key files are stored in the following format:

- Meta Information - First 17 bytes
- Salt - Next 8 bytes
- Signature - Last 32 bytes

Unless otherwise implemented by the Android device supplier, the default Android hashing algorithm is `scrypt` with 16384 rounds, block size (n) of 1 and parallelism factor (p) of 8.

After calculation of the salted hash, verification can be done by matching the first 32 bytes of the hash with the signature located in the gatekeeper files.
