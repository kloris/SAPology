#!/usr/bin/env python3
"""
SAP RFC via ctypes — Cross-Platform Python Wrapper for the SAP NW RFC SDK

A pure-Python ctypes wrapper around the SAP NetWeaver RFC SDK shared library
(sapnwrfc.dll / libsapnwrfc.so / libsapnwrfc.dylib). This provides RFC function
module invocation without PyRFC's Cython build step, while maintaining
cross-platform compatibility (Windows, Linux, macOS).

Requirements:
  - SAP NetWeaver RFC SDK installed (download from SAP Support Portal)
  - Python 3.8+
  - No pip dependencies (stdlib only: ctypes, struct, os, sys)

Usage:
  from sap_rfc_ctypes import RFCConnection

  with RFCConnection(ashost='saphost', sysnr='00', client='100',
                     user='USER', passwd='PASS') as conn:
      result = conn.call('BAPI_COMPANY_GETLIST')
      for company in result['COMPANY_LIST']:
          print(company['COMPANY'], company['NAME1'])

Cross-platform SAP_UC handling:
  SAP_UC is always UTF-16 (2 bytes per character), regardless of platform.
  On Windows, c_wchar is 2 bytes (UTF-16), so it maps directly.
  On Linux/macOS, c_wchar is 4 bytes (UCS-4), so we use c_uint16 arrays
  with manual UTF-16LE encoding/decoding.

Based on research of:
  - SAP-archive/PyRFC (csapnwrfc.pxd / _cyrfc.pyx)
  - jdsricardo/SAP-RFC-Python-without-PyRFC
  - SAP NW RFC SDK sapnwrfc.h header
  - Wireshark SAP dissector (packet-saprfc.c)

License: Same as SAPology project.
"""

import ctypes
import ctypes.util
import logging
import os
import sys
from ctypes import (
    POINTER, Structure, byref, c_double, c_int, c_int16, c_int64,
    c_long, c_ubyte, c_uint, c_uint16, c_ulong, c_void_p,
)
from decimal import Decimal

logger = logging.getLogger(__name__)

# ============================================================================
# Platform Detection and SAP_UC Abstraction
# ============================================================================

_WCHAR_SIZE = ctypes.sizeof(ctypes.c_wchar)
_IS_WINDOWS = sys.platform == 'win32'
_IS_LINUX = sys.platform.startswith('linux')
_IS_MACOS = sys.platform == 'darwin'
_IS_64BIT = sys.maxsize > 2**32

# SAP_UC is always UTF-16 (2 bytes). On Windows, c_wchar matches.
# On Linux/macOS, c_wchar is 4 bytes (UCS-4), so we must use c_uint16.
_UC_NATIVE = (_WCHAR_SIZE == 2)


def _str_to_uc(s):
    """Convert Python str to a null-terminated SAP_UC buffer.

    Returns a ctypes object suitable for passing to SDK functions expecting
    SAP_UC* (const or mutable). On Windows, returns a c_wchar_p-compatible
    string. On Linux/macOS, returns a c_uint16 array with UTF-16LE encoding.
    """
    if s is None:
        return None
    if _UC_NATIVE:
        # c_wchar is 2 bytes = SAP_UC. ctypes handles conversion natively.
        return ctypes.c_wchar_p(s)
    # Encode to UTF-16LE, create uint16 array
    encoded = s.encode('utf-16-le')
    n_chars = len(encoded) // 2
    buf = (c_uint16 * (n_chars + 1))()
    ctypes.memmove(buf, encoded, len(encoded))
    buf[n_chars] = 0  # null terminator
    return buf


def _uc_to_str(buf, char_count=None):
    """Convert a SAP_UC buffer (array or pointer) to a Python str.

    Args:
        buf: A ctypes c_wchar array (Windows) or c_uint16 array (Linux/macOS),
             or a pointer to such memory.
        char_count: Number of UTF-16 characters to read. If None, reads until
                    null terminator (for arrays with .value attribute) or
                    scans for null.
    """
    if buf is None:
        return ''
    if _UC_NATIVE:
        # c_wchar array or c_wchar_p — .value gives Python str directly
        if hasattr(buf, 'value'):
            v = buf.value
            return v[:char_count] if char_count is not None else v
        # It's a raw pointer; unlikely path but handle it
        return ctypes.cast(buf, ctypes.c_wchar_p).value or ''

    # Linux/macOS: buf is c_uint16 array
    if char_count is None:
        # Find null terminator
        char_count = 0
        try:
            while buf[char_count] != 0:
                char_count += 1
        except (IndexError, ValueError):
            pass
    if char_count == 0:
        return ''
    # Read raw bytes and decode UTF-16LE
    raw_arr = (c_uint16 * char_count)()
    ctypes.memmove(raw_arr, buf, char_count * 2)
    return bytes(raw_arr).decode('utf-16-le')


def _create_uc_buffer(size):
    """Create a mutable SAP_UC buffer of 'size' characters.

    Returns a ctypes array suitable for receiving SAP_UC output from SDK
    functions (e.g., RfcGetString output buffer).
    """
    if _UC_NATIVE:
        return ctypes.create_unicode_buffer(size)
    return (c_uint16 * size)()


# ============================================================================
# Constants — RFC Return Codes
# ============================================================================

RFC_OK = 0
RFC_COMMUNICATION_FAILURE = 1
RFC_LOGON_FAILURE = 2
RFC_ABAP_RUNTIME_FAILURE = 3
RFC_ABAP_MESSAGE = 4
RFC_ABAP_EXCEPTION = 5
RFC_CLOSED = 6
RFC_CANCELED = 7
RFC_TIMEOUT = 8
RFC_MEMORY_INSUFFICIENT = 9
RFC_VERSION_MISMATCH = 10
RFC_INVALID_PROTOCOL = 11
RFC_SERIALIZATION_FAILURE = 12
RFC_INVALID_HANDLE = 13
RFC_RETRY = 14
RFC_EXTERNAL_FAILURE = 15
RFC_EXECUTED = 16
RFC_NOT_FOUND = 17
RFC_NOT_SUPPORTED = 18
RFC_ILLEGAL_STATE = 19
RFC_INVALID_PARAMETER = 20
RFC_CODEPAGE_CONVERSION_FAILURE = 21
RFC_CONVERSION_FAILURE = 22
RFC_BUFFER_TOO_SMALL = 23
RFC_TABLE_MOVE_BOF = 24
RFC_TABLE_MOVE_EOF = 25
RFC_START_SAPGUI_FAILURE = 26
RFC_ABAP_CLASS_EXCEPTION = 27
RFC_UNKNOWN_ERROR = 28
RFC_AUTHORIZATION_FAILURE = 29
RFC_AUTHENTICATION_FAILURE = 30
RFC_CRYPTOLIB_FAILURE = 31
RFC_IO_FAILURE = 32
RFC_LOCKING_FAILURE = 33

_RC_NAMES = {
    0: 'RFC_OK', 1: 'RFC_COMMUNICATION_FAILURE', 2: 'RFC_LOGON_FAILURE',
    3: 'RFC_ABAP_RUNTIME_FAILURE', 4: 'RFC_ABAP_MESSAGE',
    5: 'RFC_ABAP_EXCEPTION', 6: 'RFC_CLOSED', 7: 'RFC_CANCELED',
    8: 'RFC_TIMEOUT', 13: 'RFC_INVALID_HANDLE', 17: 'RFC_NOT_FOUND',
    20: 'RFC_INVALID_PARAMETER', 23: 'RFC_BUFFER_TOO_SMALL',
    29: 'RFC_AUTHORIZATION_FAILURE', 30: 'RFC_AUTHENTICATION_FAILURE',
}

# ============================================================================
# Constants — RFCTYPE (ABAP Data Types)
# ============================================================================

RFCTYPE_CHAR = 0
RFCTYPE_DATE = 1
RFCTYPE_BCD = 2
RFCTYPE_TIME = 3
RFCTYPE_BYTE = 4
RFCTYPE_TABLE = 5
RFCTYPE_NUM = 6
RFCTYPE_FLOAT = 7
RFCTYPE_INT = 8
RFCTYPE_INT2 = 9
RFCTYPE_INT1 = 10
RFCTYPE_NULL = 14
RFCTYPE_STRUCTURE = 17
RFCTYPE_DECF16 = 23
RFCTYPE_DECF34 = 24
RFCTYPE_STRING = 29
RFCTYPE_XSTRING = 30
RFCTYPE_INT8 = 31
RFCTYPE_UTCLONG = 32

_TYPE_NAMES = {
    0: 'CHAR', 1: 'DATE', 2: 'BCD', 3: 'TIME', 4: 'BYTE', 5: 'TABLE',
    6: 'NUM', 7: 'FLOAT', 8: 'INT', 9: 'INT2', 10: 'INT1', 14: 'NULL',
    17: 'STRUCTURE', 23: 'DECF16', 24: 'DECF34', 29: 'STRING',
    30: 'XSTRING', 31: 'INT8', 32: 'UTCLONG',
}

# ============================================================================
# Constants — RFC Direction (Parameter Direction)
# ============================================================================

RFC_IMPORT = 0x01
RFC_EXPORT = 0x02
RFC_CHANGING = 0x03
RFC_TABLES = 0x07

# ============================================================================
# Constants — RFC Error Group
# ============================================================================

ERGRP_OK = 0
ERGRP_ABAP_APPLICATION_FAILURE = 1
ERGRP_ABAP_RUNTIME_FAILURE = 2
ERGRP_LOGON_FAILURE = 3
ERGRP_COMMUNICATION_FAILURE = 4
ERGRP_EXTERNAL_RUNTIME_FAILURE = 5
ERGRP_EXTERNAL_APPLICATION_FAILURE = 6
ERGRP_EXTERNAL_AUTHORIZATION_FAILURE = 7

# ============================================================================
# ctypes Structure Definitions
# ============================================================================

# The SAP_UC field type depends on the platform.
# On Windows: c_wchar (2 bytes) matches SAP_UC directly.
# On Linux/macOS: c_uint16 (2 bytes) is needed since c_wchar is 4 bytes.
_UC = ctypes.c_wchar if _UC_NATIVE else c_uint16
_UC_P = ctypes.c_wchar_p if _UC_NATIVE else POINTER(c_uint16)


class RFC_ERROR_INFO(Structure):
    """SAP RFC error information structure.

    Filled by every SDK function call. Check 'code' field for RFC_OK (0).
    """
    _fields_ = [
        ('code', c_long),          # RFC_RC enum
        ('group', c_long),         # RFC_ERROR_GROUP enum
        ('key', _UC * 128),        # Error key
        ('message', _UC * 512),    # Error message (human-readable)
        ('abapMsgClass', _UC * 21),
        ('abapMsgType', _UC * 2),
        ('abapMsgNumber', _UC * 4),
        ('abapMsgV1', _UC * 51),
        ('abapMsgV2', _UC * 51),
        ('abapMsgV3', _UC * 51),
        ('abapMsgV4', _UC * 51),
    ]


class RFC_CONNECTION_PARAMETER(Structure):
    """Name-value pair for connection parameters."""
    _fields_ = [
        ('name', _UC_P),
        ('value', _UC_P),
    ]


class RFC_PARAMETER_DESC(Structure):
    """Function module parameter descriptor (from metadata introspection)."""
    _fields_ = [
        ('name', _UC * 31),           # RFC_ABAP_NAME: 30 chars + null
        ('direction', c_uint),         # RFC_DIRECTION
        ('type', c_uint),              # RFCTYPE
        ('nucLength', c_uint),
        ('ucLength', c_uint),
        ('decimals', c_uint),
        ('typeDescHandle', c_void_p),  # RFC_TYPE_DESC_HANDLE
        ('defaultValue', _UC * 31),    # RFC_ABAP_NAME
        ('parameterText', _UC * 80),   # RFC_PARAMETER_TEXT: 79 chars + null
        ('optional', c_ubyte),         # 0 or 1
        ('extendedDescription', c_void_p),
    ]


class RFC_FIELD_DESC(Structure):
    """Structure/table field descriptor (from type metadata)."""
    _fields_ = [
        ('name', _UC * 31),           # RFC_ABAP_NAME
        ('type', c_uint),              # RFCTYPE
        ('nucLength', c_uint),
        ('nucOffset', c_uint),
        ('ucLength', c_uint),
        ('ucOffset', c_uint),
        ('decimals', c_uint),
        ('typeDescHandle', c_void_p),  # RFC_TYPE_DESC_HANDLE
        ('extendedDescription', c_void_p),
    ]


class RFC_ATTRIBUTES(Structure):
    """Connection attributes returned by RfcGetConnectionAttributes."""
    _fields_ = [
        ('dest', _UC * 65),
        ('host', _UC * 101),
        ('partnerHost', _UC * 101),
        ('sysNumber', _UC * 3),
        ('sysId', _UC * 9),
        ('client', _UC * 4),
        ('user', _UC * 13),
        ('language', _UC * 3),
        ('trace', _UC * 2),
        ('isoLanguage', _UC * 3),
        ('codepage', _UC * 5),
        ('partnerCodepage', _UC * 5),
        ('rfcRole', _UC * 2),
        ('type', _UC * 2),
        ('partnerType', _UC * 2),
        ('rel', _UC * 5),
        ('partnerRel', _UC * 5),
        ('kernelRel', _UC * 5),
        ('cpicConvId', _UC * 9),
        ('progName', _UC * 129),
        ('partnerBytesPerChar', _UC * 2),
        ('partnerSystemCodepage', _UC * 5),
        ('partnerIP', _UC * 16),
        ('partnerIPv6', _UC * 46),
        ('reserved', _UC * 17),
    ]


# ============================================================================
# Exception Classes
# ============================================================================

class RFCError(Exception):
    """Base exception for SAP RFC errors."""
    def __init__(self, message='', code=0, key='', group=0,
                 msg_class='', msg_type='', msg_number='',
                 msg_v1='', msg_v2='', msg_v3='', msg_v4=''):
        self.code = code
        self.key = key
        self.group = group
        self.msg_class = msg_class
        self.msg_type = msg_type
        self.msg_number = msg_number
        self.msg_v1 = msg_v1
        self.msg_v2 = msg_v2
        self.msg_v3 = msg_v3
        self.msg_v4 = msg_v4
        rc_name = _RC_NAMES.get(code, f'RC={code}')
        super().__init__(f'{rc_name}: {message}')


class CommunicationError(RFCError):
    """Network or communication failure."""
    pass


class LogonError(RFCError):
    """Authentication/logon failure."""
    pass


class ABAPApplicationError(RFCError):
    """ABAP application exception (raised by RAISE in the function module)."""
    pass


class ABAPRuntimeError(RFCError):
    """ABAP runtime error (short dump on the server)."""
    pass


class ExternalError(RFCError):
    """Error in external (non-SAP) code."""
    pass


_ERROR_GROUP_MAP = {
    ERGRP_ABAP_APPLICATION_FAILURE: ABAPApplicationError,
    ERGRP_ABAP_RUNTIME_FAILURE: ABAPRuntimeError,
    ERGRP_LOGON_FAILURE: LogonError,
    ERGRP_COMMUNICATION_FAILURE: CommunicationError,
    ERGRP_EXTERNAL_RUNTIME_FAILURE: ExternalError,
    ERGRP_EXTERNAL_APPLICATION_FAILURE: ExternalError,
    ERGRP_EXTERNAL_AUTHORIZATION_FAILURE: ExternalError,
}


def _raise_on_error(error_info, operation=''):
    """Check RFC_ERROR_INFO and raise appropriate exception if code != RFC_OK."""
    if error_info.code == RFC_OK:
        return
    msg = _uc_to_str(error_info.message).rstrip()
    key = _uc_to_str(error_info.key).rstrip()
    exc_class = _ERROR_GROUP_MAP.get(error_info.group, RFCError)
    raise exc_class(
        message=msg, code=error_info.code, key=key, group=error_info.group,
        msg_class=_uc_to_str(error_info.abapMsgClass).rstrip(),
        msg_type=_uc_to_str(error_info.abapMsgType).rstrip(),
        msg_number=_uc_to_str(error_info.abapMsgNumber).rstrip(),
        msg_v1=_uc_to_str(error_info.abapMsgV1).rstrip(),
        msg_v2=_uc_to_str(error_info.abapMsgV2).rstrip(),
        msg_v3=_uc_to_str(error_info.abapMsgV3).rstrip(),
        msg_v4=_uc_to_str(error_info.abapMsgV4).rstrip(),
    )


# ============================================================================
# SDK Library Loader
# ============================================================================

class _SDKLibrary:
    """Loads and configures the SAP NW RFC SDK shared library.

    Handles platform-specific library loading (windll vs cdll), library
    file names, and function prototype setup.
    """

    _instance = None

    def __init__(self, sdk_path=None):
        self._lib = None
        self._load(sdk_path)
        self._setup_prototypes()

    @classmethod
    def get(cls, sdk_path=None):
        """Get or create the singleton library instance."""
        if cls._instance is None:
            cls._instance = cls(sdk_path)
        return cls._instance

    def _find_library(self, sdk_path):
        """Locate the SAP NW RFC SDK shared library."""
        if _IS_WINDOWS:
            lib_name = 'sapnwrfc.dll'
        elif _IS_MACOS:
            lib_name = 'libsapnwrfc.dylib'
        else:
            lib_name = 'libsapnwrfc.so'

        # 1. Explicit path
        if sdk_path:
            candidate = os.path.join(sdk_path, lib_name)
            if os.path.isfile(candidate):
                return candidate, sdk_path
            # Maybe sdk_path is the full file path
            if os.path.isfile(sdk_path):
                return sdk_path, os.path.dirname(sdk_path)

        # 2. SAPNWRFC_HOME environment variable (same as PyRFC)
        env_home = os.environ.get('SAPNWRFC_HOME')
        if env_home:
            lib_dir = os.path.join(env_home, 'lib')
            candidate = os.path.join(lib_dir, lib_name)
            if os.path.isfile(candidate):
                return candidate, lib_dir

        # 3. Common default paths
        search_paths = []
        if _IS_WINDOWS:
            search_paths = [
                r'C:\nwrfcsdk\lib',
                r'C:\Program Files\SAP\nwrfcsdk\lib',
                os.path.join(os.environ.get('ProgramFiles', ''), 'SAP', 'nwrfcsdk', 'lib'),
            ]
        else:
            search_paths = [
                '/usr/local/sap/nwrfcsdk/lib',
                '/opt/sap/nwrfcsdk/lib',
                '/usr/sap/nwrfcsdk/lib',
                os.path.expanduser('~/nwrfcsdk/lib'),
            ]

        for path in search_paths:
            candidate = os.path.join(path, lib_name)
            if os.path.isfile(candidate):
                return candidate, path

        # 4. System library path (ldconfig, PATH, etc.)
        found = ctypes.util.find_library('sapnwrfc')
        if found:
            return found, os.path.dirname(found) or None

        raise RFCError(
            f'SAP NW RFC SDK library ({lib_name}) not found. '
            f'Set SAPNWRFC_HOME environment variable to the SDK root directory, '
            f'or pass sdk_path to RFCConnection. '
            f'Download the SDK from https://support.sap.com/connectors'
        )

    def _load(self, sdk_path):
        """Load the shared library with platform-appropriate loader."""
        lib_path, lib_dir = self._find_library(sdk_path)

        if _IS_WINDOWS:
            # Add SDK lib directory to DLL search path (Python 3.8+)
            if lib_dir and hasattr(os, 'add_dll_directory'):
                os.add_dll_directory(lib_dir)
            # Windows: SAP SDK uses __stdcall calling convention
            self._lib = ctypes.WinDLL(lib_path)
        else:
            # Linux/macOS: standard cdecl calling convention
            self._lib = ctypes.CDLL(lib_path)

        logger.info('SAP NW RFC SDK loaded from %s', lib_path)

    def _setup_prototypes(self):
        """Define argument types and return types for all wrapped functions."""
        lib = self._lib

        # For SAP_UC* parameters, we use c_void_p universally. This works
        # because ctypes auto-converts c_wchar_p and c_uint16 arrays to
        # void pointers. This avoids platform-specific argtype definitions.
        VP = c_void_p
        EI = POINTER(RFC_ERROR_INFO)

        # -- Version --
        lib.RfcGetVersion.argtypes = [POINTER(c_uint), POINTER(c_uint), POINTER(c_uint)]
        lib.RfcGetVersion.restype = VP  # SAP_UC* (static)

        # -- Connection --
        lib.RfcOpenConnection.argtypes = [POINTER(RFC_CONNECTION_PARAMETER), c_uint, EI]
        lib.RfcOpenConnection.restype = VP

        lib.RfcCloseConnection.argtypes = [VP, EI]
        lib.RfcCloseConnection.restype = c_ulong

        lib.RfcPing.argtypes = [VP, EI]
        lib.RfcPing.restype = c_ulong

        lib.RfcGetConnectionAttributes.argtypes = [VP, POINTER(RFC_ATTRIBUTES), EI]
        lib.RfcGetConnectionAttributes.restype = c_ulong

        lib.RfcIsConnectionHandleValid.argtypes = [VP, POINTER(c_int), EI]
        lib.RfcIsConnectionHandleValid.restype = c_ulong

        # -- Function Description --
        lib.RfcGetFunctionDesc.argtypes = [VP, VP, EI]
        lib.RfcGetFunctionDesc.restype = VP

        lib.RfcGetParameterCount.argtypes = [VP, POINTER(c_uint), EI]
        lib.RfcGetParameterCount.restype = c_ulong

        lib.RfcGetParameterDescByIndex.argtypes = [VP, c_uint, POINTER(RFC_PARAMETER_DESC), EI]
        lib.RfcGetParameterDescByIndex.restype = c_ulong

        lib.RfcGetParameterDescByName.argtypes = [VP, VP, POINTER(RFC_PARAMETER_DESC), EI]
        lib.RfcGetParameterDescByName.restype = c_ulong

        # -- Type Description (for structure/table introspection) --
        lib.RfcGetFieldCount.argtypes = [VP, POINTER(c_uint), EI]
        lib.RfcGetFieldCount.restype = c_ulong

        lib.RfcGetFieldDescByIndex.argtypes = [VP, c_uint, POINTER(RFC_FIELD_DESC), EI]
        lib.RfcGetFieldDescByIndex.restype = c_ulong

        # -- Function Handle --
        lib.RfcCreateFunction.argtypes = [VP, EI]
        lib.RfcCreateFunction.restype = VP

        lib.RfcDestroyFunction.argtypes = [VP, EI]
        lib.RfcDestroyFunction.restype = c_ulong

        lib.RfcInvoke.argtypes = [VP, VP, EI]
        lib.RfcInvoke.restype = c_ulong

        # -- String getters/setters --
        lib.RfcSetString.argtypes = [VP, VP, VP, c_uint, EI]
        lib.RfcSetString.restype = c_ulong

        lib.RfcGetString.argtypes = [VP, VP, VP, c_uint, POINTER(c_uint), EI]
        lib.RfcGetString.restype = c_ulong

        lib.RfcGetStringLength.argtypes = [VP, VP, POINTER(c_uint), EI]
        lib.RfcGetStringLength.restype = c_ulong

        # -- Char getters/setters --
        lib.RfcSetChars.argtypes = [VP, VP, VP, c_uint, EI]
        lib.RfcSetChars.restype = c_ulong

        lib.RfcGetChars.argtypes = [VP, VP, VP, c_uint, EI]
        lib.RfcGetChars.restype = c_ulong

        # -- Numeric string --
        lib.RfcSetNum.argtypes = [VP, VP, VP, c_uint, EI]
        lib.RfcSetNum.restype = c_ulong

        lib.RfcGetNum.argtypes = [VP, VP, VP, c_uint, EI]
        lib.RfcGetNum.restype = c_ulong

        # -- Integer getters/setters --
        lib.RfcSetInt.argtypes = [VP, VP, c_int, EI]
        lib.RfcSetInt.restype = c_ulong

        lib.RfcGetInt.argtypes = [VP, VP, POINTER(c_int), EI]
        lib.RfcGetInt.restype = c_ulong

        lib.RfcSetInt8.argtypes = [VP, VP, c_int64, EI]
        lib.RfcSetInt8.restype = c_ulong

        lib.RfcGetInt8.argtypes = [VP, VP, POINTER(c_int64), EI]
        lib.RfcGetInt8.restype = c_ulong

        # -- Float --
        lib.RfcSetFloat.argtypes = [VP, VP, c_double, EI]
        lib.RfcSetFloat.restype = c_ulong

        lib.RfcGetFloat.argtypes = [VP, VP, POINTER(c_double), EI]
        lib.RfcGetFloat.restype = c_ulong

        # -- Date/Time (SAP_UC[8] / SAP_UC[6]) --
        lib.RfcSetDate.argtypes = [VP, VP, VP, EI]
        lib.RfcSetDate.restype = c_ulong

        lib.RfcGetDate.argtypes = [VP, VP, VP, EI]
        lib.RfcGetDate.restype = c_ulong

        lib.RfcSetTime.argtypes = [VP, VP, VP, EI]
        lib.RfcSetTime.restype = c_ulong

        lib.RfcGetTime.argtypes = [VP, VP, VP, EI]
        lib.RfcGetTime.restype = c_ulong

        # -- Bytes/XString --
        lib.RfcSetBytes.argtypes = [VP, VP, POINTER(c_ubyte), c_uint, EI]
        lib.RfcSetBytes.restype = c_ulong

        lib.RfcGetBytes.argtypes = [VP, VP, POINTER(c_ubyte), c_uint, EI]
        lib.RfcGetBytes.restype = c_ulong

        lib.RfcSetXString.argtypes = [VP, VP, POINTER(c_ubyte), c_uint, EI]
        lib.RfcSetXString.restype = c_ulong

        lib.RfcGetXString.argtypes = [VP, VP, POINTER(c_ubyte), c_uint, POINTER(c_uint), EI]
        lib.RfcGetXString.restype = c_ulong

        # -- Structure --
        lib.RfcGetStructure.argtypes = [VP, VP, POINTER(VP), EI]
        lib.RfcGetStructure.restype = c_ulong

        # -- Table --
        lib.RfcGetTable.argtypes = [VP, VP, POINTER(VP), EI]
        lib.RfcGetTable.restype = c_ulong

        lib.RfcGetRowCount.argtypes = [VP, POINTER(c_uint), EI]
        lib.RfcGetRowCount.restype = c_ulong

        lib.RfcMoveToFirstRow.argtypes = [VP, EI]
        lib.RfcMoveToFirstRow.restype = c_ulong

        lib.RfcMoveToNextRow.argtypes = [VP, EI]
        lib.RfcMoveToNextRow.restype = c_ulong

        lib.RfcMoveTo.argtypes = [VP, c_uint, EI]
        lib.RfcMoveTo.restype = c_ulong

        lib.RfcGetCurrentRow.argtypes = [VP, EI]
        lib.RfcGetCurrentRow.restype = VP

        lib.RfcAppendNewRow.argtypes = [VP, EI]
        lib.RfcAppendNewRow.restype = VP

        lib.RfcDeleteCurrentRow.argtypes = [VP, EI]
        lib.RfcDeleteCurrentRow.restype = c_ulong

    def __getattr__(self, name):
        """Proxy attribute access to the underlying ctypes library."""
        return getattr(self._lib, name)


# ============================================================================
# RFCConnection — Main User-Facing Class
# ============================================================================

class RFCConnection:
    """A connection to an SAP system via the RFC protocol.

    Uses the SAP NW RFC SDK via ctypes. Supports context manager protocol
    for automatic cleanup.

    Args:
        sdk_path: Path to the SDK lib directory (optional if SAPNWRFC_HOME is set
                  or the SDK is installed in a standard location).
        **params: RFC connection parameters. Common parameters:
            ashost: Application server hostname
            sysnr:  System number (00-99)
            client: Client number (000-999)
            user:   SAP username
            passwd: Password
            lang:   Login language (default: EN)
            mshost: Message server host (for load balancing)
            group:  Logon group (for load balancing)
            sysid:  System ID (for load balancing)
            saprouter: SAP Router string
            snc_mode:  SNC enabled (0/1)
            snc_partnername: SNC partner name
            trace:  Trace level (0-3)

    Example:
        with RFCConnection(ashost='sap01', sysnr='00', client='100',
                           user='RFC_USER', passwd='secret') as conn:
            result = conn.call('RFC_READ_TABLE',
                               QUERY_TABLE='USR02',
                               DELIMITER='|',
                               ROWCOUNT=10)
            for row in result['DATA']:
                print(row['WA'])
    """

    def __init__(self, sdk_path=None, **params):
        self._sdk = _SDKLibrary.get(sdk_path)
        self._params = params
        self._handle = None
        # Keep references to UC string buffers to prevent GC during connection
        self._param_bufs = []

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    # -- Connection lifecycle --

    def open(self):
        """Open the RFC connection to the SAP system."""
        if self._handle is not None:
            return  # already open

        params = self._params
        count = len(params)
        conn_params = (RFC_CONNECTION_PARAMETER * count)()
        self._param_bufs = []

        for i, (key, value) in enumerate(params.items()):
            # Connection parameter names are UPPER CASE in the SDK
            name_buf = _str_to_uc(key.upper())
            value_buf = _str_to_uc(str(value))
            self._param_bufs.extend([name_buf, value_buf])

            if _UC_NATIVE:
                conn_params[i].name = name_buf
                conn_params[i].value = value_buf
            else:
                conn_params[i].name = ctypes.cast(name_buf, _UC_P)
                conn_params[i].value = ctypes.cast(value_buf, _UC_P)

        error_info = RFC_ERROR_INFO()
        self._handle = self._sdk.RfcOpenConnection(
            conn_params, count, byref(error_info)
        )

        if not self._handle:
            _raise_on_error(error_info, 'RfcOpenConnection')
            raise RFCError('RfcOpenConnection returned NULL handle')

        logger.info('RFC connection opened')

    def close(self):
        """Close the RFC connection."""
        if self._handle is None:
            return
        error_info = RFC_ERROR_INFO()
        self._sdk.RfcCloseConnection(self._handle, byref(error_info))
        self._handle = None
        self._param_bufs = []
        logger.info('RFC connection closed')

    @property
    def is_open(self):
        """Check if the connection is open and valid."""
        if self._handle is None:
            return False
        is_valid = c_int(0)
        error_info = RFC_ERROR_INFO()
        rc = self._sdk.RfcIsConnectionHandleValid(
            self._handle, byref(is_valid), byref(error_info)
        )
        return rc == RFC_OK and is_valid.value != 0

    def ping(self):
        """Send an RFC ping to verify the connection is alive.

        Returns True if the connection is alive, False otherwise.
        """
        if self._handle is None:
            return False
        error_info = RFC_ERROR_INFO()
        rc = self._sdk.RfcPing(self._handle, byref(error_info))
        return rc == RFC_OK

    def get_attributes(self):
        """Get connection attributes (system ID, hostname, user, etc.).

        Returns a dict with connection metadata.
        """
        self._ensure_open()
        attrs = RFC_ATTRIBUTES()
        error_info = RFC_ERROR_INFO()
        rc = self._sdk.RfcGetConnectionAttributes(
            self._handle, byref(attrs), byref(error_info)
        )
        _raise_on_error(error_info, 'RfcGetConnectionAttributes')

        result = {}
        for field_name, field_type in RFC_ATTRIBUTES._fields_:
            val = _uc_to_str(getattr(attrs, field_name)).rstrip()
            if val:
                result[field_name] = val
        return result

    # -- RFC Function Invocation --

    def call(self, func_name, **kwargs):
        """Call an RFC-enabled function module on the SAP system.

        Args:
            func_name: Name of the function module (e.g., 'BAPI_COMPANY_GETLIST')
            **kwargs: Import/changing/table parameters. Python types are mapped
                      to ABAP types automatically:
                - str    → CHAR/STRING/NUM/DATE/TIME
                - int    → INT/INT1/INT2/INT8
                - float  → FLOAT
                - Decimal → BCD/DECF16/DECF34
                - bytes  → BYTE/XSTRING
                - list   → TABLE (list of dicts, each dict is a row)
                - dict   → STRUCTURE

        Returns:
            dict: All export, changing, and table parameters. Tables are
                  returned as lists of dicts with auto-discovered field names.

        Example:
            result = conn.call('RFC_READ_TABLE',
                               QUERY_TABLE='MARA',
                               DELIMITER='|',
                               ROWCOUNT=5,
                               FIELDS=[{'FIELDNAME': 'MATNR'},
                                       {'FIELDNAME': 'MTART'}])
        """
        self._ensure_open()
        error_info = RFC_ERROR_INFO()

        # 1. Get function description (metadata)
        func_name_uc = _str_to_uc(func_name)
        func_desc = self._sdk.RfcGetFunctionDesc(
            self._handle, func_name_uc, byref(error_info)
        )
        _raise_on_error(error_info, f'RfcGetFunctionDesc({func_name})')
        if not func_desc:
            raise RFCError(f'Function description for {func_name} is NULL')

        # 2. Create function call container
        func_handle = self._sdk.RfcCreateFunction(func_desc, byref(error_info))
        _raise_on_error(error_info, f'RfcCreateFunction({func_name})')

        try:
            # 3. Set import/changing/table parameters from kwargs
            for param_name, param_value in kwargs.items():
                self._set_parameter(func_handle, func_desc, param_name, param_value)

            # 4. Invoke the RFC call
            rc = self._sdk.RfcInvoke(self._handle, func_handle, byref(error_info))
            _raise_on_error(error_info, f'RfcInvoke({func_name})')

            # 5. Read all export/changing/table parameters
            return self._read_output(func_handle, func_desc)

        finally:
            # 6. Always destroy the function container
            self._sdk.RfcDestroyFunction(func_handle, byref(error_info))

    # -- Internal: Parameter Setting --

    def _set_parameter(self, container, func_desc, name, value):
        """Set a single parameter on a function/structure container.

        Dispatches to the appropriate RfcSet* function based on the
        parameter's ABAP type from metadata, or infers from the Python type.
        """
        error_info = RFC_ERROR_INFO()
        name_uc = _str_to_uc(name)

        # Look up parameter metadata to determine ABAP type
        param_desc = RFC_PARAMETER_DESC()
        rc = self._sdk.RfcGetParameterDescByName(
            func_desc, name_uc, byref(param_desc), byref(error_info)
        )
        if rc != RFC_OK:
            # Parameter not found in metadata — try setting as string
            self._set_value(container, name_uc, value, RFCTYPE_STRING, None, 0)
            return

        self._set_value(
            container, name_uc, value,
            param_desc.type, param_desc.typeDescHandle, param_desc.decimals
        )

    def _set_value(self, container, name_uc, value, abap_type, type_desc, decimals):
        """Set a value on a container using the appropriate SDK setter."""
        error_info = RFC_ERROR_INFO()

        # Table parameter: list of dicts
        if abap_type == RFCTYPE_TABLE and isinstance(value, list):
            table_handle = c_void_p()
            rc = self._sdk.RfcGetTable(
                container, name_uc, byref(table_handle), byref(error_info)
            )
            _raise_on_error(error_info, 'RfcGetTable (set)')
            self._fill_table(table_handle, type_desc, value)
            return

        # Structure parameter: dict
        if abap_type == RFCTYPE_STRUCTURE and isinstance(value, dict):
            struct_handle = c_void_p()
            rc = self._sdk.RfcGetStructure(
                container, name_uc, byref(struct_handle), byref(error_info)
            )
            _raise_on_error(error_info, 'RfcGetStructure (set)')
            self._fill_structure(struct_handle, type_desc, value)
            return

        # Scalar types
        if isinstance(value, bytes):
            buf = (c_ubyte * len(value))(*value)
            if abap_type == RFCTYPE_XSTRING:
                rc = self._sdk.RfcSetXString(
                    container, name_uc, buf, len(value), byref(error_info)
                )
            else:
                rc = self._sdk.RfcSetBytes(
                    container, name_uc, buf, len(value), byref(error_info)
                )
            _raise_on_error(error_info, 'RfcSetBytes/XString')
            return

        if isinstance(value, int) and not isinstance(value, bool):
            if abap_type in (RFCTYPE_INT, RFCTYPE_INT1, RFCTYPE_INT2):
                rc = self._sdk.RfcSetInt(
                    container, name_uc, c_int(value), byref(error_info)
                )
                _raise_on_error(error_info, 'RfcSetInt')
                return
            if abap_type == RFCTYPE_INT8:
                rc = self._sdk.RfcSetInt8(
                    container, name_uc, c_int64(value), byref(error_info)
                )
                _raise_on_error(error_info, 'RfcSetInt8')
                return
            # For other numeric types, fall through to string

        if isinstance(value, float):
            if abap_type == RFCTYPE_FLOAT:
                rc = self._sdk.RfcSetFloat(
                    container, name_uc, c_double(value), byref(error_info)
                )
                _raise_on_error(error_info, 'RfcSetFloat')
                return
            # For BCD, use string representation to avoid rounding

        # Default: set as string (SAP handles most type conversions)
        str_value = str(value)
        value_uc = _str_to_uc(str_value)
        rc = self._sdk.RfcSetString(
            container, name_uc, value_uc, len(str_value), byref(error_info)
        )
        _raise_on_error(error_info, 'RfcSetString')

    def _fill_table(self, table_handle, type_desc, rows):
        """Fill a table parameter with rows (list of dicts)."""
        error_info = RFC_ERROR_INFO()
        for row_dict in rows:
            row_handle = self._sdk.RfcAppendNewRow(table_handle, byref(error_info))
            _raise_on_error(error_info, 'RfcAppendNewRow')
            if row_handle and isinstance(row_dict, dict):
                self._fill_structure(row_handle, type_desc, row_dict)

    def _fill_structure(self, struct_handle, type_desc, fields):
        """Fill a structure with field values from a dict."""
        error_info = RFC_ERROR_INFO()
        for field_name, field_value in fields.items():
            name_uc = _str_to_uc(field_name)

            if type_desc:
                # Look up field metadata for proper typing
                field_desc = RFC_FIELD_DESC()
                rc = self._sdk.RfcGetFieldDescByName(
                    type_desc, name_uc, byref(field_desc), byref(error_info)
                )
                if rc == RFC_OK:
                    self._set_value(
                        struct_handle, name_uc, field_value,
                        field_desc.type, field_desc.typeDescHandle,
                        field_desc.decimals
                    )
                    continue

            # Fallback: set as string
            str_val = str(field_value)
            val_uc = _str_to_uc(str_val)
            self._sdk.RfcSetString(
                struct_handle, name_uc, val_uc, len(str_val), byref(error_info)
            )

    # -- Internal: Output Reading --

    def _read_output(self, func_handle, func_desc):
        """Read all export/changing/table parameters from a completed call.

        Uses metadata introspection to auto-discover parameter names and types.
        """
        error_info = RFC_ERROR_INFO()
        result = {}

        # Get parameter count
        param_count = c_uint(0)
        rc = self._sdk.RfcGetParameterCount(
            func_desc, byref(param_count), byref(error_info)
        )
        _raise_on_error(error_info, 'RfcGetParameterCount')

        for i in range(param_count.value):
            param_desc = RFC_PARAMETER_DESC()
            rc = self._sdk.RfcGetParameterDescByIndex(
                func_desc, i, byref(param_desc), byref(error_info)
            )
            if rc != RFC_OK:
                continue

            direction = param_desc.direction
            # Read EXPORT, CHANGING, and TABLES parameters
            if direction not in (RFC_EXPORT, RFC_CHANGING, RFC_TABLES):
                continue

            param_name = _uc_to_str(param_desc.name).rstrip()
            if not param_name:
                continue

            try:
                value = self._get_value(
                    func_handle, param_desc.name,
                    param_desc.type, param_desc.typeDescHandle,
                    param_desc.ucLength, param_desc.decimals
                )
                result[param_name] = value
            except RFCError:
                # Skip parameters that can't be read (e.g., inactive)
                pass

        return result

    def _get_value(self, container, name_uc, abap_type, type_desc, uc_length, decimals):
        """Read a single value from a container using the appropriate getter."""
        error_info = RFC_ERROR_INFO()

        # -- Table --
        if abap_type == RFCTYPE_TABLE:
            table_handle = c_void_p()
            rc = self._sdk.RfcGetTable(
                container, name_uc, byref(table_handle), byref(error_info)
            )
            _raise_on_error(error_info, 'RfcGetTable')
            return self._read_table(table_handle, type_desc)

        # -- Structure --
        if abap_type == RFCTYPE_STRUCTURE:
            struct_handle = c_void_p()
            rc = self._sdk.RfcGetStructure(
                container, name_uc, byref(struct_handle), byref(error_info)
            )
            _raise_on_error(error_info, 'RfcGetStructure')
            return self._read_structure(struct_handle, type_desc)

        # -- Integer types --
        if abap_type == RFCTYPE_INT:
            val = c_int(0)
            rc = self._sdk.RfcGetInt(container, name_uc, byref(val), byref(error_info))
            _raise_on_error(error_info, 'RfcGetInt')
            return val.value

        if abap_type == RFCTYPE_INT8:
            val = c_int64(0)
            rc = self._sdk.RfcGetInt8(container, name_uc, byref(val), byref(error_info))
            _raise_on_error(error_info, 'RfcGetInt8')
            return val.value

        if abap_type in (RFCTYPE_INT1, RFCTYPE_INT2):
            # Use RfcGetInt for INT1/INT2 — SDK handles promotion
            val = c_int(0)
            rc = self._sdk.RfcGetInt(container, name_uc, byref(val), byref(error_info))
            _raise_on_error(error_info, 'RfcGetInt')
            return val.value

        # -- Float --
        if abap_type == RFCTYPE_FLOAT:
            val = c_double(0.0)
            rc = self._sdk.RfcGetFloat(
                container, name_uc, byref(val), byref(error_info)
            )
            _raise_on_error(error_info, 'RfcGetFloat')
            return val.value

        # -- BCD / Decimal --
        if abap_type in (RFCTYPE_BCD, RFCTYPE_DECF16, RFCTYPE_DECF34):
            s = self._get_string_value(container, name_uc)
            try:
                return Decimal(s) if s.strip() else Decimal(0)
            except Exception:
                return s

        # -- Date (YYYYMMDD) --
        if abap_type == RFCTYPE_DATE:
            buf = _create_uc_buffer(8)
            rc = self._sdk.RfcGetDate(container, name_uc, buf, byref(error_info))
            _raise_on_error(error_info, 'RfcGetDate')
            return _uc_to_str(buf, 8).rstrip()

        # -- Time (HHMMSS) --
        if abap_type == RFCTYPE_TIME:
            buf = _create_uc_buffer(6)
            rc = self._sdk.RfcGetTime(container, name_uc, buf, byref(error_info))
            _raise_on_error(error_info, 'RfcGetTime')
            return _uc_to_str(buf, 6).rstrip()

        # -- Raw bytes --
        if abap_type == RFCTYPE_BYTE:
            byte_len = uc_length  # ucLength for BYTE = actual byte count
            buf = (c_ubyte * byte_len)()
            rc = self._sdk.RfcGetBytes(
                container, name_uc, buf, byte_len, byref(error_info)
            )
            _raise_on_error(error_info, 'RfcGetBytes')
            return bytes(buf)

        if abap_type == RFCTYPE_XSTRING:
            # First get the length, then read
            str_len = c_uint(0)
            rc = self._sdk.RfcGetStringLength(
                container, name_uc, byref(str_len), byref(error_info)
            )
            _raise_on_error(error_info, 'RfcGetStringLength (xstring)')
            if str_len.value == 0:
                return b''
            buf = (c_ubyte * str_len.value)()
            actual_len = c_uint(0)
            rc = self._sdk.RfcGetXString(
                container, name_uc, buf, str_len.value,
                byref(actual_len), byref(error_info)
            )
            _raise_on_error(error_info, 'RfcGetXString')
            return bytes(buf[:actual_len.value])

        # -- CHAR, STRING, NUM, UTCLONG, and all other types → read as string --
        return self._get_string_value(container, name_uc)

    def _get_string_value(self, container, name_uc):
        """Read any parameter as a string using RfcGetString with dynamic buffer sizing."""
        error_info = RFC_ERROR_INFO()

        # First, get the required length
        str_len = c_uint(0)
        rc = self._sdk.RfcGetStringLength(
            container, name_uc, byref(str_len), byref(error_info)
        )
        if rc != RFC_OK:
            # Fallback: try a fixed buffer
            str_len.value = 512

        buf_size = max(str_len.value + 1, 2)
        buf = _create_uc_buffer(buf_size)
        actual_len = c_uint(0)

        rc = self._sdk.RfcGetString(
            container, name_uc, buf, buf_size,
            byref(actual_len), byref(error_info)
        )

        if rc == RFC_BUFFER_TOO_SMALL:
            # Retry with the SDK's reported required size
            buf_size = actual_len.value + 1
            buf = _create_uc_buffer(buf_size)
            rc = self._sdk.RfcGetString(
                container, name_uc, buf, buf_size,
                byref(actual_len), byref(error_info)
            )

        _raise_on_error(error_info, 'RfcGetString')
        return _uc_to_str(buf, actual_len.value).rstrip()

    # -- Internal: Table/Structure reading --

    def _read_table(self, table_handle, type_desc):
        """Read all rows from a table handle, returning a list of dicts.

        Uses metadata introspection to auto-discover field names and types.
        """
        error_info = RFC_ERROR_INFO()
        row_count = c_uint(0)
        rc = self._sdk.RfcGetRowCount(
            table_handle, byref(row_count), byref(error_info)
        )
        _raise_on_error(error_info, 'RfcGetRowCount')

        if row_count.value == 0:
            return []

        # Get field metadata once for the whole table
        fields = self._get_field_metadata(type_desc) if type_desc else []

        rows = []
        for i in range(row_count.value):
            # Position cursor
            rc = self._sdk.RfcMoveTo(table_handle, i, byref(error_info))
            _raise_on_error(error_info, f'RfcMoveTo({i})')

            if fields:
                row = self._read_fields(table_handle, fields)
            else:
                row = {}
            rows.append(row)

        return rows

    def _read_structure(self, struct_handle, type_desc):
        """Read all fields from a structure handle, returning a dict."""
        if not type_desc:
            return {}
        fields = self._get_field_metadata(type_desc)
        return self._read_fields(struct_handle, fields)

    def _read_fields(self, container, fields):
        """Read a set of fields from a container (table row or structure)."""
        row = {}
        for f in fields:
            try:
                value = self._get_value(
                    container, f['name_uc'],
                    f['type'], f['typeDescHandle'],
                    f['ucLength'], f['decimals']
                )
                row[f['name']] = value
            except RFCError:
                row[f['name']] = None
        return row

    def _get_field_metadata(self, type_desc):
        """Introspect a type description to get all field names and types."""
        error_info = RFC_ERROR_INFO()
        field_count = c_uint(0)
        rc = self._sdk.RfcGetFieldCount(
            type_desc, byref(field_count), byref(error_info)
        )
        if rc != RFC_OK:
            return []

        fields = []
        for i in range(field_count.value):
            field_desc = RFC_FIELD_DESC()
            rc = self._sdk.RfcGetFieldDescByIndex(
                type_desc, i, byref(field_desc), byref(error_info)
            )
            if rc != RFC_OK:
                continue

            field_name = _uc_to_str(field_desc.name).rstrip()
            if not field_name:
                continue

            # Store a reference to name_uc for use in getters
            # We need to create a fresh UC buffer that won't be overwritten
            name_uc = _str_to_uc(field_name)

            fields.append({
                'name': field_name,
                'name_uc': name_uc,
                'type': field_desc.type,
                'typeDescHandle': field_desc.typeDescHandle,
                'ucLength': field_desc.ucLength,
                'decimals': field_desc.decimals,
            })

        return fields

    # -- Internal: Utility --

    def _ensure_open(self):
        """Ensure the connection is open, raise if not."""
        if self._handle is None:
            raise RFCError('Connection is not open. Call open() or use as context manager.')


# ============================================================================
# Module-Level Convenience Functions
# ============================================================================

def get_sdk_version(sdk_path=None):
    """Get the SAP NW RFC SDK version string.

    Returns a tuple (major, minor, patch, version_string).
    """
    sdk = _SDKLibrary.get(sdk_path)
    major = c_uint(0)
    minor = c_uint(0)
    patch = c_uint(0)
    version_ptr = sdk.RfcGetVersion(byref(major), byref(minor), byref(patch))

    if version_ptr and _UC_NATIVE:
        version_str = ctypes.cast(version_ptr, ctypes.c_wchar_p).value
    elif version_ptr:
        # Read UTF-16 chars until null from the pointer
        arr_type = c_uint16 * 256
        arr = arr_type.from_address(version_ptr)
        version_str = _uc_to_str(arr)
    else:
        version_str = f'{major.value}.{minor.value}.{patch.value}'

    return major.value, minor.value, patch.value, version_str


# ============================================================================
# Usage Examples (when run directly)
# ============================================================================

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='SAP RFC call via ctypes — cross-platform SDK wrapper',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Get SDK version
  python sap_rfc_ctypes.py --sdk-version

  # Call a function module
  python sap_rfc_ctypes.py --host saphost --sysnr 00 --client 100 \\
      --user RFC_USER --password secret --func BAPI_COMPANY_GETLIST

  # Call RFC_READ_TABLE
  python sap_rfc_ctypes.py --host saphost --sysnr 00 --client 100 \\
      --user RFC_USER --password secret --func RFC_READ_TABLE \\
      --param QUERY_TABLE=USR02 --param DELIMITER="|" --param ROWCOUNT=5
""")
    parser.add_argument('--sdk-path', help='Path to SAP NW RFC SDK lib directory')
    parser.add_argument('--sdk-version', action='store_true', help='Print SDK version and exit')
    parser.add_argument('--host', help='SAP application server hostname')
    parser.add_argument('--sysnr', default='00', help='System number (default: 00)')
    parser.add_argument('--client', default='100', help='Client number (default: 100)')
    parser.add_argument('--user', help='SAP username')
    parser.add_argument('--password', help='SAP password')
    parser.add_argument('--lang', default='EN', help='Login language (default: EN)')
    parser.add_argument('--func', help='Function module to call')
    parser.add_argument('--param', action='append', default=[],
                        help='Import parameter as NAME=VALUE (repeatable)')
    parser.add_argument('-v', '--verbose', action='store_true')

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if args.sdk_version:
        try:
            major, minor, patch, version = get_sdk_version(args.sdk_path)
            print(f'SAP NW RFC SDK version: {version} ({major}.{minor}.{patch})')
        except RFCError as e:
            print(f'Error: {e}')
        sys.exit(0)

    if not args.host or not args.user or not args.password or not args.func:
        parser.error('--host, --user, --password, and --func are required for RFC calls')

    # Parse import parameters
    import_params = {}
    for p in args.param:
        if '=' in p:
            k, v = p.split('=', 1)
            # Try to convert numeric values
            try:
                v = int(v)
            except ValueError:
                pass
            import_params[k] = v

    try:
        with RFCConnection(
            sdk_path=args.sdk_path,
            ashost=args.host, sysnr=args.sysnr, client=args.client,
            user=args.user, passwd=args.password, lang=args.lang,
        ) as conn:
            print(f'Connected. Calling {args.func}...')
            result = conn.call(args.func, **import_params)

            import json

            def _serialize(obj):
                if isinstance(obj, Decimal):
                    return str(obj)
                if isinstance(obj, bytes):
                    return obj.hex()
                raise TypeError(f'Not serializable: {type(obj)}')

            print(json.dumps(result, indent=2, default=_serialize, ensure_ascii=False))

    except RFCError as e:
        print(f'RFC Error: {e}')
        if hasattr(e, 'key') and e.key:
            print(f'  Key: {e.key}')
        sys.exit(1)
