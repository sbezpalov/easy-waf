#!/usr/bin/env python3
# Copyright 2026 Sergey Bezpalov
# SPDX-License-Identifier: Apache-2.0
"""Launch a PostgreSQL archive client with connection settings off argv."""

import ctypes
import os
import sys
import tempfile


class ConnOption(ctypes.Structure):
    # Public PQconninfoOption layout from libpq-fe.h.
    _fields_ = [
        (name, ctypes.c_char_p)
        for name in ("keyword", "envvar", "compiled", "val", "label", "dispchar")
    ] + [("dispsize", ctypes.c_int)]


def options_from(libpq, options):
    if not options:
        raise ValueError("could not load PostgreSQL connection settings")
    values = {}
    try:
        for option in options:
            if option.keyword is None:
                break
            if option.val is not None:
                values[option.keyword] = (option.val, option.envvar)
    finally:
        libpq.PQconninfoFree(options)
    return values


def connection_options(dsn):
    libpq = ctypes.CDLL("libpq.so.5")
    option_pointer = ctypes.POINTER(ConnOption)
    libpq.PQconninfoParse.argtypes = (ctypes.c_char_p, ctypes.c_void_p)
    libpq.PQconninfoParse.restype = option_pointer
    libpq.PQconndefaults.argtypes = ()
    libpq.PQconndefaults.restype = option_pointer
    libpq.PQconninfoFree.argtypes = (option_pointer,)
    libpq.PQconninfoFree.restype = None

    explicit = options_from(libpq, libpq.PQconninfoParse(dsn, None))
    service = explicit.pop(b"service", None)
    if service is not None:
        os.environb[b"PGSERVICE"] = service[0]
    if b"PGSERVICE" not in os.environb:
        return explicit

    # Resolve the original service using libpq's normal search order. Explicit
    # DSN fields keep precedence over service and environment defaults.
    defaults = options_from(libpq, libpq.PQconndefaults())
    defaults.pop(b"service", None)
    return defaults | explicit


def private_service_file(directory, options, environment):
    with tempfile.NamedTemporaryFile(dir=directory, prefix="pg-service-", delete=False) as service:
        service.write(b"[easy-waf-archive]\n")
        for key, (value, envvar) in options.items():
            line = key + b"=" + value
            # PostgreSQL 16 trims trailing whitespace and caps service lines at
            # 1022 bytes including the newline. Preserve unusual values via
            # libpq's environment entry where it provides one.
            if b"\n" in line or b"\r" in line or value.rstrip() != value or len(line) > 1021:
                if envvar is None:
                    raise ValueError("a PostgreSQL option cannot be represented privately")
                environment[envvar] = value
                continue
            service.write(line + b"\n")
        return os.fsencode(service.name)


def main():
    directory, command, *args = sys.argv[1:]
    if command not in ("pg_dump", "pg_restore"):
        raise ValueError("expected pg_dump or pg_restore")
    dsn = sys.stdin.buffer.read().removesuffix(b"\n")
    if not dsn or b"\0" in dsn:
        raise ValueError("invalid PostgreSQL connection settings")
    options = connection_options(dsn)
    environment = os.environb.copy()
    environment.pop(b"DATABASE_URL", None)
    environment.pop(b"PGSERVICE", None)
    environment[b"PGSERVICEFILE"] = private_service_file(directory, options, environment)
    os.execvpe(command, [command, "--dbname=service=easy-waf-archive", *args], environment)


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        sys.exit(f"ERROR: {error}")
    except OSError:
        sys.exit("ERROR: could not launch PostgreSQL archive client (check libpq and client installation)")
