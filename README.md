## Concept

This project builds on top of [grnet's BG-Mixnet library](https://github.com/grnet/bg-mixnet), which in turn builds on top of the [Stadium software project](https://github.com/nirvantyagi/stadium).
Stadium is a distributed metadata-private messaging system.
Bg-mixnet is concerned with the adapted mixnet of Bayer-Groth that is used internally by Stadium to shuffle messages.
Of particular importance are the mixnet's efficiency and limitations.
The LICENSE, README, and NOTICE files of the original repos are retained in this repo also.

## Software dependencies

- Make
- GCC
- NTL library (>=10.5.0)
- GMP
- Boost
- OpenMP (comes with GCC >=4.2)

Remember to set `LD_LIBRARY_PATH` to the install location of the shared libraries.
For convenience, you can export the variable in your favorite shell profile, say `~/.bashrc`, e.g.:

`export LD_LIBRARY_PATH=/usr/local/lib`

## Configure

Modify the `config/config` file

## Build test executable and shared library

`make`

By default the bgmix shared library (`libbgmix.so`) is installed in the local directory.
Again, for convenience, you can add the path to `LD_LIBRARY_PATH` as before to avoid specifying it when invoking executables that link to it.

## Logging

By default the mixnet (library) logs messages in /var/log/celery/bg\_mixnet.log.
This behavior can be changed at compile time with:

`make LOG_CRYPTO_OUTPUT=log_file_with_absolute_path`

## Execute

### C++

The stress test defined at `src/main.cpp` can be executed with the following command providing the dimensions of the cipher matrix:

`./bgmix <m> <n>`

### Python 3.x

The script `main.py` provides the use cases `mix` and `verify`:

#### `mix` 
Takes as input the dimensions of the cipher matrix and the file names for its 3 output files and the file containing the election data.
It collects the cryptosystem configuration and ElGammal encryptions from the election data, it pads the data with the provided padding pair to reach the required dimensions and executes the Bayer Groth scheme over the cipher matrix.
It returns 3 files:
* A `json` file containing: configuration, input ciphers (padded) and mixed ciphers.
* A text file listing the public key of the commitments.
* A text file containing the NIZK proof.

`python main.py mix <m> <n> <ciphers> <publics> <proof> <election>`

#### `verify` 
Takes as input the dimensions of the cipher matrix and the file names for its 3 input files.
It collects the cryptosystem configuration and ElGammal ciphers (before and after mixing), the public key of the commitments and the NIZK proof and executes the verification protocol.

`python main.py verify <m> <n> <ciphers> <publics> <proof>`

### Flask

This implementation also provides a flask web application that can be initialized using:

```
pip install -r requirements.txt
python app.py
```

This application has 2 interfaces:

#### `/mix`

A form requesting the cipher matrix's dimensions and the election's `json` file

#### `/verify`

A form requesting the cipher matrix's dimensions and the 3 output files of `/mix`

## IO Files

### ciphers

Ciphers is a `json` file with the following scheme:
```lang=python
{
    'generator': BigInt,
    'modulus': BigInt,
    'order': BigInt,
    'public': BigInt,
    'original_ciphers': [
        BigInt Array
    ],
    'mixed_ciphers': [
        BigInt Array
    ]
}
```

### randoms

Is a text file listing all the public keys from the Pedersen commitments

### proof

Is a text file containing the Non-Interactive Zero-Knowledge proof for the mixing

### election

Election is a `json` file with the following scheme:
```lang=python
{
    'publicKey': {
        'g': BigInt,
        'p': BigInt,
        'q': BigInt,
        'y': BigInt
    },
    'ciphertextForPadding': {
        'alpha': BigInt,
        'beta': BigInt
    },
    'cipherTexts': [
        {
            'alpha': BigInt,
            'beta': BigInt
        },
    ]
}
```