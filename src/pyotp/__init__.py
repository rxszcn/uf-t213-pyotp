# mypy: implicit-reexport
from __future__ import annotations

import binascii
import hashlib
from collections.abc import Sequence
from re import split
from typing import Any
from urllib.parse import parse_qsl, unquote, urlparse

from . import contrib
from .compat import random
from .exceptions import InvalidProvisioningURIError, OTPVerificationError, PyOTPError
from .hotp import HOTP
from .otp import OTP
from .totp import TOTP

# Parameters whose values configure security-relevant behaviour. Duplicates are
# rejected for these, even when one occurrence is blank.
_SECURITY_PARAMETERS = frozenset({"secret", "issuer", "algorithm", "encoder", "digits", "period", "counter"})

_SUPPORTED_ALGORITHMS = {"sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha512": hashlib.sha512}

# The otpauth Key URI Format only allows these code lengths.
_SUPPORTED_DIGITS = (6, 7, 8)

# TOTP/Steam intervals must stay at or below two minutes (NIST SP 800-63B-4, 3.1.4.1).
_MAX_INTERVAL = 120

_OTP_TYPES = ("totp", "hotp")


def random_base32(length: int = 32, chars: Sequence[str] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") -> str:
    # Note: the otpauth scheme DOES NOT use base32 padding for secret lengths not divisible by 8.
    # Some third-party tools have bugs when dealing with such secrets.
    # We might consider warning the user when generating a secret of length not divisible by 8.
    if length < 32:
        raise ValueError("Secrets should be at least 160 bits")

    return "".join(random.choice(chars) for _ in range(length))


def random_hex(length: int = 40, chars: Sequence[str] = "ABCDEF0123456789") -> str:
    if length < 40:
        raise ValueError("Secrets should be at least 160 bits")
    return random_base32(length=length, chars=chars)


def _parse_int(name: str, value: str) -> int:
    """Parse an integer URI parameter without accepting int()'s extra spellings.

    ``int()`` tolerates surrounding whitespace, a leading ``+``, and digit
    grouping underscores. A provisioning URI should spell the number plainly,
    so reject those forms with a configuration error instead of quietly
    interpreting them.
    """
    digits_part = value.removeprefix("-")
    if not digits_part.isascii() or not digits_part.isdigit():
        raise InvalidProvisioningURIError(f"Invalid value for {name}: must be an integer")
    return int(value)


def _parse_digits(value: str) -> int:
    """Parse the otpauth ``digits`` parameter, which may only be 6, 7, or 8."""
    digits = _parse_int("digits", value)
    if digits not in _SUPPORTED_DIGITS:
        raise InvalidProvisioningURIError("Digits may only be 6, 7, or 8")
    return digits


def _parse_otp_parameters(query: str) -> dict[str, str]:
    """Collect the recognised otpauth parameters, rejecting duplicates.

    Parameter names are matched case-insensitively, like the OTP type and the
    ``algorithm``/``encoder`` values, so a generator that emits ``Secret`` or
    ``PERIOD`` still imports correctly. Duplicate detection uses the
    normalised name, so ``secret`` and ``SECRET`` count as the same parameter.

    A repeated parameter is a configuration error even when one occurrence is
    blank, because it makes the intended value ambiguous. A single blank value
    is treated as absent, matching "the client did not specify this".

    Unknown parameters are ignored: third-party generators routinely add
    vendor-specific keys, and dropping them cannot change how codes are
    generated.
    """
    parameters: dict[str, str] = {}
    seen: set[str] = set()
    for key, value in parse_qsl(query, keep_blank_values=True):
        key = key.lower()
        if key not in _SECURITY_PARAMETERS:
            continue
        if key in seen:
            raise InvalidProvisioningURIError(f"Duplicate {key} parameter")
        seen.add(key)
        if value:
            parameters[key] = value
    return parameters


def _reject_parameters(otp_type: str, parameters: dict[str, str], allowed: Sequence[str]) -> None:
    """Reject parameters that belong to a different OTP type.

    A parameter is only meaningful for the type that defines its semantics, so
    a cross-type parameter (``counter`` on TOTP, ``period`` on HOTP, ...) is an
    error rather than something to silently drop: silently dropping it would
    make the imported credential differ from what the QR code described.
    """
    rejected = sorted(set(parameters).difference(allowed) - {"secret", "issuer"})
    if rejected:
        raise InvalidProvisioningURIError(f"Parameter {', '.join(rejected)} is not supported for OTP type {otp_type}")


def parse_uri(uri: str) -> OTP:
    """
    Parses the provisioning URI for the OTP; works for either TOTP or HOTP.

    Only parameters that are meaningful for the URI's OTP type are accepted.
    A parameter belonging to another type (for example ``counter`` on a
    ``totp`` URI, ``period`` on an ``hotp`` URI, or ``algorithm`` on a Steam
    credential) raises :class:`~pyotp.exceptions.InvalidProvisioningURIError`
    instead of being forwarded to a constructor that cannot accept it.
    Unknown parameters are ignored.

    The OTP type, parameter names, and the ``algorithm``/``encoder`` values are
    matched case-insensitively. Parameter names that are not recognised are
    ignored as unknown parameters.

    See also:
        https://github.com/google/google-authenticator/wiki/Key-Uri-Format

    :param uri: the hotp/totp URI to parse
    :returns: OTP object
    :raises pyotp.exceptions.InvalidProvisioningURIError: if the URI is not a
        supported otpauth URI, carries a parameter the OTP type does not accept,
        or yields a configuration the OTP classes reject. This exception is a
        ``ValueError`` subclass.
    """
    parsed_uri = urlparse(uri)

    # urlparse lowercases the scheme but not the host, which holds the OTP type.
    if parsed_uri.scheme != "otpauth":
        raise InvalidProvisioningURIError("Not an otpauth URI")

    otp_type = parsed_uri.netloc.lower()
    if otp_type not in _OTP_TYPES:
        raise InvalidProvisioningURIError("Not a supported OTP type")

    try:
        # Parse the URI structure first, then unquote individual components.
        # Unquoting the whole URI before splitting the label would turn an
        # encoded colon (%3A) inside the issuer or account name into a literal
        # ":" and mis-parse the issuer:account separator (see GitHub issue #174).
        otp_data: dict[str, Any] = {}

        # The label uses a literal ":" as the issuer:account separator; a
        # percent-encoded "%3A" is a colon that is part of the issuer or
        # account name, not a separator. Split on the literal ":" while the
        # components are still percent-encoded, then unquote each component on
        # its own.
        accountinfo_parts = split(":", parsed_uri.path[1:], maxsplit=1)
        if len(accountinfo_parts) == 1:
            otp_data["name"] = unquote(accountinfo_parts[0])
        else:
            otp_data["issuer"] = unquote(accountinfo_parts[0])
            otp_data["name"] = unquote(accountinfo_parts[1])

        parameters = _parse_otp_parameters(parsed_uri.query)

        issuer = parameters.get("issuer")
        if issuer is not None:
            label_issuer = otp_data.get("issuer")
            if label_issuer is not None and label_issuer != issuer:
                raise InvalidProvisioningURIError(
                    "If issuer is specified in both label and parameters, it should be equal."
                )
            otp_data["issuer"] = issuer

        # The Steam encoder is only defined for TOTP credentials, where it
        # fixes the digest to SHA1 and the code to Steam's own format.
        encoder = parameters.get("encoder")
        is_steam = False
        if encoder is not None:
            if encoder.lower() != "steam":
                raise InvalidProvisioningURIError(f"Invalid value for encoder: {encoder!r} is not a supported encoder")
            if otp_type != "totp":
                raise InvalidProvisioningURIError("Parameter encoder=steam is not supported for OTP type hotp")
            is_steam = True

        # Drop cross-type parameters before interpreting any values, so a
        # parameter that does not apply to this type is reported as such
        # rather than as a malformed value.
        if is_steam:
            _reject_parameters("steam", parameters, ("encoder", "algorithm", "digits", "period"))
        elif otp_type == "totp":
            _reject_parameters(otp_type, parameters, ("algorithm", "digits", "period", "encoder"))
        else:
            _reject_parameters(otp_type, parameters, ("algorithm", "digits", "counter"))

        algorithm = parameters.get("algorithm")
        if algorithm is not None:
            try:
                digest = _SUPPORTED_ALGORITHMS[algorithm.lower()]
            except KeyError:
                raise InvalidProvisioningURIError(
                    "Invalid value for algorithm, must be SHA1, SHA256 or SHA512"
                ) from None
            if is_steam:
                # Steam always uses SHA1. Accept a URI that states the default
                # explicitly, but reject one that asks for a different digest
                # rather than silently generating different codes.
                if digest is not hashlib.sha1:
                    raise InvalidProvisioningURIError(
                        f"Parameter algorithm={algorithm.upper()} is not supported for OTP type steam"
                    )
            else:
                otp_data["digest"] = digest

        digits = parameters.get("digits")
        if digits is not None:
            # Validate the format for every type so a malformed value cannot
            # slip through just because the type ignores the parameter.
            digits_value = _parse_digits(digits)
            if not is_steam:
                otp_data["digits"] = digits_value

        period = parameters.get("period")
        if period is not None:
            interval = _parse_int("period", period)
            if not 0 < interval <= _MAX_INTERVAL:
                # Same wording as the OTP classes use.
                raise InvalidProvisioningURIError("interval must be positive and at most 120 seconds")
            # Steam credentials are always 30-second TOTP; a period on a Steam
            # URI is validated for range but does not alter the credential.
            if not is_steam:
                otp_data["interval"] = interval

        counter = parameters.get("counter")
        if counter is not None:
            initial_count = _parse_int("counter", counter)
            if initial_count < 0:
                # A negative starting counter can never produce a code, so treat
                # it as a configuration error rather than an unusable credential.
                raise InvalidProvisioningURIError("Invalid value for counter: must not be negative")
            otp_data["initial_count"] = initial_count

        secret = parameters.get("secret")
        if not secret:
            raise InvalidProvisioningURIError("No secret found in URI")

        # Create the object; the OTP classes own configuration range checks
        # (secret length, interval bounds, ...).
        if is_steam:
            return contrib.Steam(secret, **otp_data)
        if otp_type == "totp":
            return TOTP(secret, **otp_data)
        return HOTP(secret, **otp_data)
    except InvalidProvisioningURIError:
        raise
    except binascii.Error as error:
        # A malformed Base32 secret raises binascii.Error from the constructor;
        # report it as a provisioning configuration error instead of leaking the
        # decoder's own wording.
        raise InvalidProvisioningURIError("Invalid secret in URI: secret must be valid Base32") from error
    except ValueError as error:
        # Other constructor rejections (secret length, interval bounds, ...)
        # are configuration errors; re-raise them as such.
        raise InvalidProvisioningURIError(str(error)) from error
