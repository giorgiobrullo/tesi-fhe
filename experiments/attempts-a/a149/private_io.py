"""Exclusive owner-only creation, including during the initial write."""

import os


def private_text(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(descriptor, "w")
