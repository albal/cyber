"""Suppress library warnings that aren't about our code."""
import warnings


def pytest_configure(config):
    # JWT-with-short-keys is a deliberate test choice (we use the dev
    # default secret); the warning is just noise.
    warnings.filterwarnings(
        "ignore",
        message=r"The HMAC key.*is.*bytes long.*",
    )
