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

Pick the exact GitHub repository URL before mining. Changing the URL changes the
Proof of Work input and requires a new nonce.

```bash
python -m cs4160_lab1 \
  --email "your-netid@student.tudelft.nl" \
  --github-url "https://github.com/Chevuu/cs4160"
```

The client writes mining progress to `pow-progress.json` and creates
`lab1_identity.pem` if the key does not exist yet. Keep that `.pem` file private
and back it up after a successful registration.

If you already have a nonce, skip mining:

```bash
python -m cs4160_lab1 \
  --email "your-netid@student.tudelft.nl" \
  --github-url "https://github.com/Chevuu/cs4160" \
  --nonce 123456789
```

## Tests

The local tests cover deterministic PoW behavior and do not require IPv8:

```bash
python -m unittest discover -s tests
```
