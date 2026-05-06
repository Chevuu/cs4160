# CS4160 Lab 1 IPv8 PoW Client

Fresh implementation of the Lab 1 client for Proof of Work registration over IPv8.

## Setup

Use Python 3.10 or newer.

```bash
python3.10 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

## Run

The email and GitHub URL are hardcoded in `src/constants.py`:

```bash
v.jurisic@student.tudelft.nl
https://github.com/Chevuu/cs4160
```

Run the client with:

```bash
python -m src
```

The client writes mining progress to `pow-progress.json` and creates
`lab1_identity.pem` if the key does not exist yet. Keep that `.pem` file private
and back it up after a successful registration.

If you already have a nonce, set `PRECOMPUTED_NONCE` in `src/constants.py` to
that integer and run the same command again.
