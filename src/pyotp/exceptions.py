class PyOTPError(Exception):
    """Base class for PyOTP-specific errors."""


class OTPVerificationError(PyOTPError):
    """Raised when an OTP does not match any permitted counter."""


class InvalidProvisioningURIError(PyOTPError, ValueError):
    """Raised when an otpauth provisioning URI cannot be parsed or configured.

    This covers malformed URIs, unsupported OTP types, parameters that do not
    belong to the URI's OTP type, invalid parameter values, and OTP
    configurations rejected by the OTP classes.

    It subclasses :class:`ValueError` so callers that already catch
    ``ValueError`` from :func:`pyotp.parse_uri` keep working.
    """
