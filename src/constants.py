"""Assignment constants for the Lab 1 registration community."""

COMMUNITY_ID_HEX = "2c1cc6e35ff484f99ebdfb6108477783c0102881"
SERVER_PUBLIC_KEY_HEX = (
    "4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb178bc5a811da6d"
    "87d27ef319b2638ef60cc8d119724f4c53a1ebfad919c3ac4136c501ce5c09364e0ebb"
)

DIFFICULTY_BITS = 28
MAX_WIRE_NONCE = (1 << 63) - 1
DEFAULT_KEY_FILE = "lab1_identity.pem"
DEFAULT_PROGRESS_FILE = "pow-progress.json"

STUDENT_EMAIL = "v.jurisic@student.tudelft.nl"
GITHUB_URL = "https://github.com/Chevuu/cs4160"

# Set this to an integer if you want to submit a known-good nonce without mining again.
PRECOMPUTED_NONCE = None
