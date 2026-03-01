# Calling SAP Remote Function Modules from Python — Without PyRFC or the SAP NetWeaver RFC SDK

## Investigation Report

**Date:** March 2026
**Context:** PyRFC was archived by SAP on December 13, 2024. SAP stated they could no longer maintain the project due to changing priorities, and the latest version was built against an older, unsupported RFC SDK. This makes the question of alternatives urgent.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Approach 1: SOAP via /sap/bc/soap/rfc (Lowest Barrier)](#2-approach-1-soap-via-sapbcsoaprfc)
3. [Approach 2: OData via SEGW + pyodata](#3-approach-2-odata-via-segw--pyodata)
4. [Approach 3: Custom ICF REST Handler](#4-approach-3-custom-icf-rest-handler)
5. [Approach 4: SAP BTP / Integration Suite Middleware](#5-approach-4-sap-btp--integration-suite-middleware)
6. [Approach 5: JCo via JPype (Java Bridge)](#6-approach-5-jco-via-jpype-java-bridge)
7. [Approach 6: NCo via pythonnet (.NET Bridge)](#7-approach-6-nco-via-pythonnet-net-bridge)
8. [Approach 7: PyRFC Alternatives (Still Need the SDK)](#8-approach-7-pyrfc-alternatives-still-need-the-sdk)
9. [Approach 8: Raw Socket-Level RFC Protocol](#9-approach-8-raw-socket-level-rfc-protocol)
10. [Approach 9: gRPC / Modern RPC](#10-approach-9-grpc--modern-rpc)
11. [pysap Deep Dive — The RFC Protocol Foundation](#11-pysap-deep-dive--the-rfc-protocol-foundation)
12. [SAPology's Existing RFC Implementation](#12-sapologys-existing-rfc-implementation)
13. [What It Would Take to Build a Pure-Python RFC Client](#13-what-it-would-take-to-build-a-pure-python-rfc-client)
14. [Comparison Table](#14-comparison-table)
15. [Recommendations](#15-recommendations)
16. [References](#16-references)

---

## 1. Executive Summary

**Yes, it is possible to call SAP Remote Function Modules from Python without PyRFC or the SAP NetWeaver RFC SDK.** There are several viable approaches, each with different trade-offs:

| Approach | SDK Required? | SAP-Side Config | Effort | Production Ready? |
|----------|:---:|---|---|:---:|
| **SOAP via /sap/bc/soap/rfc** | No | Minimal (activate SICF) | Low | Yes |
| **OData via SEGW** | No | Medium (ABAP project) | Medium | Yes |
| **Custom ICF REST handler** | No | Medium (ABAP class) | Medium | Yes |
| **BTP / Integration Suite** | No | High (iFlow + Cloud Connector) | High | Yes |
| **JCo via JPype** | No (JCo has own native lib) | None | High | Experimental |
| **NCo via pythonnet** | No (NCo reimplements RFC in C#) | None | High | Experimental |
| **ctypes + NW RFC SDK (SAPology)** | **Yes** | None | Low | **Yes** |
| **Raw socket-level RFC** | No | None | Extreme | Research only |
| **gRPC** | N/A | N/A | N/A | Not SAP-supported |

**For direct RFC protocol access: `files/sap_rfc_ctypes.py`** — a cross-platform Python ctypes wrapper for the SAP NW RFC SDK. No Cython compilation needed, works on Windows/Linux/macOS, auto-discovers table fields, proper error handling. Requires the SDK download from SAP.

**For SDK-free access: SOAP via `/sap/bc/soap/rfc` + the Python `zeep` library.** This requires almost zero SAP-side configuration and lets you call any RFC-enabled function module immediately.

For a pure-Python, SDK-free, direct-protocol approach: **pysap (OWASP)** provides the best foundation, but significant development (~13-20 weeks) would be needed to add RFC function call capabilities on top of its existing transport layer.

---

## 2. Approach 1: SOAP via /sap/bc/soap/rfc

**Verdict: BEST option for quick, SDK-free RFC calls. Production-ready.**

SAP has a built-in ICF service at `/sap/bc/soap/rfc` that can serve **any** RFC-enabled function module as a SOAP web service. The WSDL is auto-generated. No Enterprise Service creation or SEGW project is needed.

### SAP-Side Prerequisites

1. Activate the ICF service `/sap/bc/soap/rfc` in transaction **SICF** (if not already active)
2. Standard SAP user with appropriate **S_RFC** authorization object
3. That's it. No ABAP development required.

### How It Works

- **WSDL URL:** `http://<host>:<port>/sap/bc/soap/wsdl11?services=<FUNCTION_MODULE_NAME>`
- **Endpoint:** `http://<host>:<port>/sap/bc/soap/rfc?sap-client=<client>`
- SAP auto-generates a WSDL from the function module's interface (imports, exports, tables)
- You call it via standard SOAP from Python

### Two Python Approaches

#### Option A: Using zeep (recommended — proper SOAP client)

```python
from zeep import Client
from zeep.transports import Transport
from requests import Session
from requests.auth import HTTPBasicAuth

session = Session()
session.auth = HTTPBasicAuth('SAP_USER', 'SAP_PASSWORD')
session.verify = False  # or path to SAP's TLS cert

wsdl_url = 'http://saphost:8000/sap/bc/soap/wsdl11?services=BAPI_COMPANY_GETLIST'
client = Client(wsdl_url, transport=Transport(session=session))

response = client.service.BapiCompanyGetlist()
for company in response.COMPANY_LIST:
    print(company.COMPANY, company.NAME1)
```

#### Option B: Raw SOAP with requests (no WSDL parsing)

```python
import requests
from requests.auth import HTTPBasicAuth

soap_body = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:urn="urn:sap-com:document:sap:rfc:functions">
  <soap:Body>
    <urn:RFC_READ_TABLE>
      <QUERY_TABLE>USR01</QUERY_TABLE>
      <DELIMITER>|</DELIMITER>
      <ROWCOUNT>10</ROWCOUNT>
    </urn:RFC_READ_TABLE>
  </soap:Body>
</soap:Envelope>"""

response = requests.post(
    'http://saphost:8000/sap/bc/soap/rfc?sap-client=100',
    data=soap_body,
    headers={
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': 'urn:sap-com:document:sap:rfc:functions'
    },
    auth=HTTPBasicAuth('user', 'password')
)
print(response.text)
```

### Alternative: SE80 + SOAMANAGER (Enterprise Service)

For more control, you can also create a formal Enterprise Service:
1. In **SE80**, create a Service Provider using "Existing ABAP Object (Inside Out)" → select your function module
2. Configure the service binding in **SOAMANAGER** (authentication, transport, etc.)
3. Export the WSDL from SOAMANAGER and use it with zeep

### Limitations

- SOAP/XML is verbose compared to JSON
- Some legacy SAP WSDLs may have validation issues with strict parsers (disable strict mode in zeep)
- Performance overhead from XML serialization/deserialization
- Not all complex RFC interfaces map cleanly to SOAP (deeply nested structures can be tricky)
- SAP Community advises this "should not be considered as an alternative to standard RFC processing" when SAP PI/PO is available (but it works fine for direct Python integration)

### Python Dependencies

```
pip install zeep requests
```

---

## 3. Approach 2: OData via SEGW + pyodata

**Verdict: SAP's strategic direction. Best for ongoing integration. Requires one-time ABAP setup.**

SAP can expose any RFC-enabled function module as an OData REST service through the SAP Gateway Service Builder (transaction **SEGW**). This is SAP's preferred modern integration path.

### SAP-Side Configuration

1. Open transaction **SEGW** and create a new project
2. Right-click **Data Model** → **Import** → **RFC/BOR Interface**
3. The wizard imports the RFC function module's interface and maps it to OData entity types
4. Check "Create Default Entity Set" to auto-create the Entity Set
5. Select fields and key fields from the RFC interface
6. Click **Generate** to create runtime artifacts
7. Map the data source under **Service Implementation** → **GetEntitySet** → **Map to Data Source**
8. Register and activate in transaction **/IWFND/MAINT_SERVICE**
9. Assign authorization via `S_SERVICE` authorization object and role in **PFCG** (object type `IWSV`)

### Python Example

```python
import requests
import pyodata

SERVICE_URL = 'http://<sap-host>:<port>/sap/opu/odata/sap/<YOUR_SERVICE_SRV>/'
session = requests.Session()
session.auth = ('username', 'password')

client = pyodata.Client(SERVICE_URL, session)
entity_set = client.entity_sets.YourEntitySet.get_entities().execute()
for entity in entity_set:
    print(entity.FieldName)
```

### Limitations

- Requires ABAP development to create the SEGW service (one-time per function module)
- OData is CRUD-oriented — complex multi-table RFMs don't always map cleanly
- OData V2 is most common in SAP; V4 support is growing (SAP Note 2322624)
- Not well suited for very large dataset extraction; data should be segmented

### Python Dependencies

```
pip install pyodata requests
```

---

## 4. Approach 3: Custom ICF REST Handler

**Verdict: Maximum flexibility. Requires ABAP development.**

Write a custom ABAP HTTP handler class that receives HTTP requests (e.g., JSON body with function module name + parameters), calls the RFC function module internally, and returns JSON.

### ABAP Side

```abap
CLASS zcl_rfc_rest_handler DEFINITION
  PUBLIC FINAL CREATE PUBLIC.
  PUBLIC SECTION.
    INTERFACES if_http_extension.
ENDCLASS.

CLASS zcl_rfc_rest_handler IMPLEMENTATION.
  METHOD if_http_extension~handle_request.
    " 1. Read JSON from request body
    " 2. Parse function module name and parameters
    " 3. CALL FUNCTION ... DESTINATION 'NONE'
    " 4. Serialize results to JSON
    " 5. Set response body
  ENDMETHOD.
ENDCLASS.
```

Register this class as an ICF service handler in **SICF** under a custom path like `/sap/bc/z_rfc_rest`.

### Python Side

```python
import requests

response = requests.post(
    'http://saphost:8000/sap/bc/z_rfc_rest?sap-client=100',
    json={
        'function': 'BAPI_COMPANY_GETLIST',
        'imports': {},
    },
    auth=('user', 'password')
)
result = response.json()
```

### Limitations

- Requires ABAP development
- Must handle security carefully (don't expose arbitrary FM execution without authorization checks)
- Each custom handler is a bespoke implementation

---

## 5. Approach 4: SAP BTP / Integration Suite Middleware

**Verdict: Enterprise-grade. High setup effort. Best for complex multi-system landscapes.**

Use SAP Integration Suite as middleware: create an iFlow with an RFC adapter to call on-premise function modules, expose it as a REST endpoint, and call that endpoint from Python.

### Architecture

```
Python  →  HTTPS  →  SAP Integration Suite (iFlow)
                              ↓ RFC adapter
                      SAP Cloud Connector (tunnel)
                              ↓
                      On-premise SAP system (RFC function module)
```

### Python Side

```python
import requests

response = requests.get(
    'https://<btp-host>/http/<your-iflow-endpoint>',
    auth=('user', 'password'),
    params={'QUERY_TABLE': 'MARA'}
)
data = response.json()
```

### Limitations

- Requires SAP BTP subscription (cost)
- Integration Suite iFlow development required
- Cloud Connector must be installed and maintained on-premise
- Added latency (Python → BTP → Cloud Connector → SAP → back)

---

## 6. Approach 5: JCo via JPype (Java Bridge)

**Verdict: Technically viable. Does NOT require the NW RFC SDK (JCo has its own native library). Experimental — no published production examples.**

JPype starts a JVM within the Python process. SAP JCo (`sapjco3.jar`) is a Java library for RFC communication. Combining them allows Python to call RFC function modules via JCo.

### Prerequisites

- Java JDK/JRE installed
- SAP JCo 3.x downloaded from SAP Support Portal (`sapjco3.jar` + native library `libsapjco3.so` / `sapjco3.dll`)
- JPype installed: `pip install JPype1`
- JVM bitness must match JCo bitness

### Python Example (Conceptual)

```python
import jpype
import jpype.imports

jpype.startJVM(
    jpype.getDefaultJVMPath(),
    "-Djava.class.path=/path/to/sapjco3.jar",
    "-Djava.library.path=/path/to/native/libs"
)

from com.sap.conn.jco import JCoDestinationManager
from com.sap.conn.jco.ext import DestinationDataProvider

# JCo requires a DestinationDataProvider or .jcoDestination config file
# Setting up a custom provider from Python via JPype requires implementing
# a Java interface, which JPype supports via @jpype.JImplements

destination = JCoDestinationManager.getDestination("SAP_SYSTEM")
repository = destination.getRepository()
function = repository.getFunction("RFC_READ_TABLE")
function.getImportParameterList().setValue("QUERY_TABLE", "MARA")
function.execute(destination)

table = function.getTableParameterList().getTable("DATA")
for i in range(table.getNumRows()):
    table.setRow(i)
    print(table.getString("WA"))

jpype.shutdownJVM()
```

### Advantages Over PyRFC

- JCo supports WebSocket RFC protocol (CPIC and WebSocket), basXML, xRfc, and cbRfc serialization
- JCo supports sRFC, tRFC, qRFC, bgRFC protocols
- JCo is actively maintained by SAP (unlike PyRFC)
- Does NOT require the SAP NW RFC SDK (JCo has its own native library)

### Limitations

- JVM overhead within the Python process
- No published examples of this specific combination
- JCo native library is still proprietary and requires SAP download
- JPype interface implementation for `DestinationDataProvider` adds complexity
- JVM shutdown means you cannot restart it in the same process

### Python Dependencies

```
pip install JPype1
```

---

## 7. Approach 6: NCo via pythonnet (.NET Bridge)

**Verdict: Technically viable. NCo re-implements RFC entirely in C# — does NOT depend on the NW RFC SDK. Windows-centric.**

SAP NCo 3.1 re-implements the RFC protocol entirely in managed C#. Using `pythonnet`, Python can load the NCo .NET assemblies and call RFC function modules.

### Prerequisites

- .NET Framework 4.6.2+ or .NET 8.0.x (NCo 3.1 patch level 3.1.5+)
- SAP NCo 3.1 DLLs (`sapnco.dll`, `sapnco_utils.dll`) from SAP Support Portal
- Microsoft C++ Runtime DLLs version 14.x
- pythonnet: `pip install pythonnet`
- Primarily Windows (Linux feasible with .NET 8 but unconfirmed for NCo)

### Python Example (Conceptual)

```python
import clr
import sys

sys.path.append(r"C:\path\to\sapnco\dlls")
clr.AddReference("sapnco")
clr.AddReference("sapnco_utils")

from SAP.Middleware.Connector import RfcDestinationManager, RfcConfigParameters

params = RfcConfigParameters()
params[RfcConfigParameters.AppServerHost] = "sap_host"
params[RfcConfigParameters.SystemNumber] = "00"
params[RfcConfigParameters.Client] = "100"
params[RfcConfigParameters.User] = "username"
params[RfcConfigParameters.Password] = "password"
params[RfcConfigParameters.Language] = "EN"

dest = RfcDestinationManager.GetDestination(params)
repo = dest.Repository
func = repo.CreateFunction("BAPI_COMPANY_GETLIST")
func.Invoke(dest)

table = func.GetTable("COMPANY_LIST")
for i in range(table.RowCount):
    table.CurrentIndex = i
    print(table.GetString("COMPANY"), table.GetString("NAME1"))
```

### Limitations

- Windows-centric (NCo compatibility on Linux via .NET 8 is unconfirmed)
- No widely published Python + pythonnet + NCo examples
- pythonnet can have DLL loading issues
- NCo 3.0 is out of support as of October 31, 2023; must use NCo 3.1
- SAP licensing: connectors may only be used for connecting external (non-SAP) apps to SAP systems

### Python Dependencies

```
pip install pythonnet
```

---

## 8. Approach 7: ctypes + SAP NW RFC SDK (Deep Dive)

**Verdict: BEST option for direct RFC protocol access from Python. Cross-platform. Requires the SAP NW RFC SDK C library but no Cython compilation.**

This is the recommended approach when you need direct RFC protocol access (not SOAP/OData) and want a pure-Python solution that works on Windows, Linux, and macOS without build tools.

### Why ctypes Over PyRFC's Cython?

| Aspect | PyRFC (Cython) | ctypes Wrapper |
|--------|:---:|:---:|
| Requires C compiler | **Yes** (Cython → C → .so/.pyd) | **No** |
| Requires SAP NW RFC SDK | Yes | Yes |
| Cross-platform | Yes (but must compile per platform) | Yes (pure Python, same code everywhere) |
| Installation | `pip install pyrfc` (often fails) | Copy one .py file |
| Maintenance status | **Archived** (Dec 2024) | Active alternative |
| Python version coupling | Tight (compiled extension) | None (pure Python) |
| Performance | Slightly faster (native code) | Negligible difference for RFC calls |

### The SAP NW RFC SDK C API

The SDK exposes ~100 C functions through a single shared library:

| Platform | Library File | Calling Convention |
|----------|-------------|-------------------|
| Windows | `sapnwrfc.dll` | `__stdcall` (WinDLL) |
| Linux | `libsapnwrfc.so` | `cdecl` (CDLL) |
| macOS | `libsapnwrfc.dylib` | `cdecl` (CDLL) |

All handles are opaque `void*` pointers. All strings use `SAP_UC` (UTF-16, 2 bytes per character).

#### Core SDK Functions

```
Connection:
  RfcOpenConnection(params[], count, &errorInfo) → connectionHandle
  RfcCloseConnection(handle, &errorInfo) → RFC_RC
  RfcPing(handle, &errorInfo) → RFC_RC
  RfcGetConnectionAttributes(handle, &attrs, &errorInfo) → RFC_RC

Function Invocation:
  RfcGetFunctionDesc(connHandle, funcName, &errorInfo) → funcDescHandle
  RfcCreateFunction(funcDescHandle, &errorInfo) → funcHandle
  RfcInvoke(connHandle, funcHandle, &errorInfo) → RFC_RC
  RfcDestroyFunction(funcHandle, &errorInfo) → RFC_RC

Metadata Introspection:
  RfcGetParameterCount(funcDescHandle, &count, &errorInfo) → RFC_RC
  RfcGetParameterDescByIndex(funcDescHandle, index, &paramDesc, &errorInfo) → RFC_RC
  RfcGetFieldCount(typeDescHandle, &count, &errorInfo) → RFC_RC
  RfcGetFieldDescByIndex(typeDescHandle, index, &fieldDesc, &errorInfo) → RFC_RC

Data Getters/Setters (work on any DATA_CONTAINER_HANDLE):
  RfcSetString / RfcGetString    — CHAR, STRING, NUM, BCD
  RfcSetInt / RfcGetInt          — INT, INT1, INT2
  RfcSetInt8 / RfcGetInt8        — INT8
  RfcSetFloat / RfcGetFloat      — FLOAT
  RfcSetDate / RfcGetDate        — DATE (SAP_UC[8] = YYYYMMDD)
  RfcSetTime / RfcGetTime        — TIME (SAP_UC[6] = HHMMSS)
  RfcSetBytes / RfcGetBytes      — BYTE (raw)
  RfcSetXString / RfcGetXString  — XSTRING (variable-length raw)

Table Operations:
  RfcGetTable(container, name, &tableHandle, &errorInfo)
  RfcGetRowCount(tableHandle, &count, &errorInfo)
  RfcMoveTo(tableHandle, index, &errorInfo)
  RfcGetCurrentRow(tableHandle, &errorInfo) → structHandle
  RfcAppendNewRow(tableHandle, &errorInfo) → structHandle

Structure Operations:
  RfcGetStructure(container, name, &structHandle, &errorInfo)
```

#### Key Data Structures

```c
// Connection parameters (name-value pairs)
typedef struct {
    const SAP_UC* name;     // e.g., "ASHOST", "USER", "PASSWD"
    const SAP_UC* value;
} RFC_CONNECTION_PARAMETER;

// Error information (filled by every SDK call)
typedef struct {
    RFC_RC code;            // 0 = OK, 1 = COMMUNICATION_FAILURE, 2 = LOGON_FAILURE, ...
    RFC_ERROR_GROUP group;  // Maps to exception type
    SAP_UC key[128];        // Error key string
    SAP_UC message[512];    // Human-readable error message
    SAP_UC abapMsgClass[21], abapMsgType[2], abapMsgNumber[4];
    SAP_UC abapMsgV1[51], abapMsgV2[51], abapMsgV3[51], abapMsgV4[51];
} RFC_ERROR_INFO;

// Parameter descriptor (from function metadata)
typedef struct {
    RFC_ABAP_NAME name;     // SAP_UC[31]
    RFC_DIRECTION direction; // 0x01=IMPORT, 0x02=EXPORT, 0x03=CHANGING, 0x07=TABLES
    RFCTYPE type;           // 0=CHAR, 1=DATE, 2=BCD, 5=TABLE, 7=FLOAT, 8=INT, 17=STRUCTURE, 29=STRING, ...
    unsigned nucLength, ucLength, decimals;
    RFC_TYPE_DESC_HANDLE typeDescHandle;  // For structures/tables: recurse into this
    ...
} RFC_PARAMETER_DESC;
```

### The Cross-Platform SAP_UC Challenge

**This is the single most critical issue for a cross-platform ctypes wrapper.**

`SAP_UC` is always `unsigned short` (UTF-16, 2 bytes per character), regardless of platform. But Python's `ctypes.c_wchar` differs:

| Platform | `c_wchar` size | Matches `SAP_UC`? | Consequence |
|----------|:-:|:-:|---|
| Windows | 2 bytes (UTF-16) | **Yes** | `c_wchar_p` works directly |
| Linux | 4 bytes (UCS-4) | **No** | Struct layouts corrupt, strings garble |
| macOS | 4 bytes (UCS-4) | **No** | Same as Linux |

**The jdsricardo/SAP-RFC-Python-without-PyRFC project uses `c_wchar` everywhere, making it Windows-only.** On Linux, every struct field after the first `c_wchar` array would be at the wrong offset, causing silent data corruption or segfaults.

**Solution**: Detect `c_wchar` size at import time. If 2 bytes, use `c_wchar`/`c_wchar_p` natively. If 4 bytes, use `c_uint16` arrays with manual UTF-16LE encoding/decoding:

```python
_UC_NATIVE = (ctypes.sizeof(ctypes.c_wchar) == 2)  # True on Windows

if _UC_NATIVE:
    _UC = ctypes.c_wchar          # Use c_wchar directly
    _UC_P = ctypes.c_wchar_p
    def _str_to_uc(s): return ctypes.c_wchar_p(s)
    def _uc_to_str(buf): return buf.value
else:
    _UC = ctypes.c_uint16         # UTF-16 as uint16 array
    def _str_to_uc(s):
        encoded = s.encode('utf-16-le')
        n = len(encoded) // 2
        buf = (c_uint16 * (n + 1))()
        ctypes.memmove(buf, encoded, len(encoded))
        buf[n] = 0
        return buf
    def _uc_to_str(buf, length=None):
        # ... scan for null, decode UTF-16LE
```

All struct definitions use `_UC` instead of `c_wchar`:

```python
class RFC_ERROR_INFO(Structure):
    _fields_ = [
        ('code', c_long),
        ('group', c_long),
        ('key', _UC * 128),        # Works on both platforms
        ('message', _UC * 512),
        ...
    ]
```

### SAPology's ctypes Implementation

The file `files/sap_rfc_ctypes.py` implements a complete cross-platform wrapper:

```python
from sap_rfc_ctypes import RFCConnection

# Context manager handles open/close automatically
with RFCConnection(
    ashost='saphost', sysnr='00', client='100',
    user='RFC_USER', passwd='secret'
) as conn:

    # Simple call — all export/table parameters auto-discovered
    result = conn.call('BAPI_COMPANY_GETLIST')
    for company in result['COMPANY_LIST']:
        print(company['COMPANY'], company['NAME1'])

    # Call with import parameters
    result = conn.call('RFC_READ_TABLE',
                       QUERY_TABLE='USR02',
                       DELIMITER='|',
                       ROWCOUNT=10)
    for row in result['DATA']:
        print(row['WA'])

    # Table input parameters (list of dicts)
    result = conn.call('RFC_READ_TABLE',
                       QUERY_TABLE='MARA',
                       FIELDS=[{'FIELDNAME': 'MATNR'}, {'FIELDNAME': 'MTART'}],
                       OPTIONS=[{'TEXT': "MTART = 'FERT'"}])

    # Connection check
    print(conn.ping())             # True/False
    print(conn.get_attributes())   # {'sysId': 'ABC', 'host': '...', ...}
```

#### Features

| Feature | Status |
|---------|:---:|
| Cross-platform (Windows/Linux/macOS) | **Yes** |
| No compilation required | **Yes** |
| No pip dependencies | **Yes** (stdlib only) |
| Auto-discovery of table/structure fields | **Yes** (via metadata introspection) |
| Type-aware getters/setters (INT, FLOAT, BCD, DATE, TIME, BYTE, XSTRING) | **Yes** |
| Context manager (`with` statement) | **Yes** |
| Error handling with typed exceptions | **Yes** |
| Dynamic string buffer sizing | **Yes** |
| Nested structure/table support | **Yes** |
| Direct connection (ASHOST) | **Yes** |
| Load-balanced connection (MSHOST/GROUP) | **Yes** (pass as connection params) |
| SNC/SSO authentication | **Yes** (pass SNC params) |
| SAProuter support | **Yes** (pass SAPROUTER param) |
| CLI mode for quick testing | **Yes** |

#### Comparison with Existing ctypes Implementation

| Aspect | jdsricardo/SAP-RFC-Python-without-PyRFC | SAPology ctypes wrapper |
|--------|---|---|
| Platform | Windows only (`windll`, `c_wchar`) | Windows, Linux, macOS |
| Error checking | Almost none (2 of ~15 calls checked) | Every SDK call checked |
| Field discovery | Manual (caller lists field names) | Automatic via metadata |
| Data types | Everything coerced to string | Native INT, FLOAT, BCD, DATE, TIME, BYTE, XSTRING |
| Buffer sizing | Fixed 512 chars (silent truncation) | Dynamic (query length first, retry on overflow) |
| Resource management | No context manager, no destructor | `with` statement, `__del__` fallback |
| Connection types | ASHOST only | Any SDK-supported connection type |
| License | Proprietary (no redistribution) | Open |

### SDK Installation

#### Windows

1. Download SAP NW RFC SDK from [SAP Support Portal](https://support.sap.com/en/product/connectors/nwrfcsdk.html) (SAP S-user required)
2. Extract to `C:\nwrfcsdk\` (or any path)
3. Set environment variable: `SAPNWRFC_HOME=C:\nwrfcsdk`
4. Ensure `C:\nwrfcsdk\lib` is in `PATH` or use `os.add_dll_directory()`

Required files in `lib/`: `sapnwrfc.dll`, `libsapucum.dll`, `icudt*.dll`, `icuin*.dll`, `icuuc*.dll`, `libicudecnumber.dll`

#### Linux

1. Download SAP NW RFC SDK for Linux x86_64
2. Extract to `/usr/local/sap/nwrfcsdk/`
3. Create `/etc/ld.so.conf.d/nwrfcsdk.conf` containing: `/usr/local/sap/nwrfcsdk/lib`
4. Run `sudo ldconfig`
5. Set environment variable: `export SAPNWRFC_HOME=/usr/local/sap/nwrfcsdk`

Required files in `lib/`: `libsapnwrfc.so`, `libsapucum.so`, `libicudata.so.50`, `libicui18n.so.50`, `libicuuc.so.50`, `libicudecnumber.so`

#### macOS

1. Download SAP NW RFC SDK for macOS (Darwin)
2. Extract to `/usr/local/sap/nwrfcsdk/`
3. Set: `export DYLD_LIBRARY_PATH=/usr/local/sap/nwrfcsdk/lib`
4. Set: `export SAPNWRFC_HOME=/usr/local/sap/nwrfcsdk`

Note: macOS SIP may restrict `DYLD_LIBRARY_PATH`. Use `install_name_tool` to fix rpath if needed.

### Other ctypes-Based Approaches (for reference)

#### pysaprfc (SourceForge)

Older wrapper around SAP's classic `librfc32.dll` / `librfccm.so` using `ctypes`.

- Still requires: SAP's classic RFC library (older than NW RFC SDK)
- Status: Legacy, not actively maintained

#### python-sapnwrfc (Piers Harding)

Python interface to SAP NetWeaver using the RFC protocol.

- **GitHub:** [piersharding/python-sapnwrfc](https://github.com/piersharding/python-sapnwrfc)
- Still requires: SAP NW RFC SDK
- Status: Legacy

#### dlthub SAP Connector (C++)

A new C++ connector under development to replace PyRFC for data ingestion workflows.

- Source: [dlthub.com blog](https://dlthub.com/blog/sap-data-ingestion-with-python-rfc)
- Still requires: Native code (C++ implementing the RFC protocol, likely using NW RFC SDK)
- Status: Under development

---

## 9. Approach 8: Raw Socket-Level RFC Protocol

**Verdict: Partially feasible for limited use cases (unauthenticated calls, security research). NOT production-ready for general-purpose authenticated RFC.**

The SAP RFC protocol has been partially reverse-engineered by security researchers. Two key implementations exist:

### OWASP pysap

Pure Python library for crafting/dissecting SAP protocol packets. See [Section 11](#11-pysap-deep-dive--the-rfc-protocol-foundation) for deep dive.

- **Does NOT require** the SAP NW RFC SDK
- Can establish gateway connections and send/receive RFC frames
- **Cannot** call arbitrary RFC function modules (missing item-level protocol, ABAP serialization, authentication)

### SAPology's Own Implementation

`files/sap_rfc_system_info.py` already implements raw socket-level RFC communication in pure Python 3:
- SAP NI framing (4-byte big-endian length prefix)
- V6 single-packet RFC call (template replay from pcap capture)
- V2 GW_NORMAL_CLIENT + F_SAP_INIT (gateway communication)
- Parsing of RFCSI_EXPORT fields (245 characters, 490 bytes in UTF-16LE)
- Unauthenticated `RFC_SYSTEM_INFO` calls

See [Section 12](#12-sapologys-existing-rfc-implementation) for details.

---

## 10. Approach 9: gRPC / Modern RPC

**Verdict: SAP does not natively support gRPC. Not viable as a direct approach.**

SAP's modernization strategy centers on OData (V2/V4) and RESTful APIs via SAP Gateway and SAP Integration Suite. There is no native gRPC support for calling function modules.

### WebSocket RFC (SAP's Modernized Transport)

SAP has introduced WebSocket RFC as a modernized transport layer for the RFC protocol. It tunnels through HTTP proxies and firewalls but is still RFC — same function module semantics, just over WebSocket instead of CPIC. Key features:
- Mandatory fast serialization (higher compression than classic/basXML)
- Automatic LAN/WAN compression optimization
- Connection multiplexing

Supported by JCo and NCo but has **no Python-specific support**.

### SAP Note 3255746 (February 2024)

SAP has explicitly stated that RFC modules of the ODP Data Replication API are no longer permitted for third-party use. SAP reserves the right to implement technical measures restricting unpermitted RFC module usage. The recommended replacements are OData via ODP and SAP-managed APIs.

---

## 11. pysap Deep Dive — The RFC Protocol Foundation

### Overview

- **Repository:** [github.com/OWASP/pysap](https://github.com/OWASP/pysap)
- **Author:** Martin Gallo (@martingalloar), originally at SecureAuth's Innovation Labs
- **Owner:** OWASP CBAS (Core Business Application Security) Project
- **License:** GPL-2.0
- **Foundation:** Built on Scapy packet manipulation library
- **Python:** Python 2 only on master (Python 3 port in progress on `master-0.2` branch, not yet merged)
- **Last Release:** v0.1.19 (April 2021)
- **Stars:** ~242 | **Forks:** ~65

### Supported SAP Protocols

| Protocol | Module | Description |
|---|---|---|
| SAP NI | `SAPNI.py` | Transport layer wrapping all SAP protocols |
| SAP Diag | `SAPDiag.py` | SAP GUI protocol |
| SAP Enqueue | `SAPEnqueue.py` | Lock server protocol |
| SAP Router | `SAPRouter.py` | Network routing/proxy |
| SAP Message Server | `SAPMS.py` | Application server coordination |
| SAP SNC | `SAPSNC.py` | Encryption layer |
| SAP IGS | `SAPIGS.py` | Graphics rendering service |
| **SAP RFC** | **`SAPRFC.py`** | **Remote Function Call protocol** |
| SAP HANA SQL | `SAPHDB.py` | HANA database protocol |

Additionally: SAR archives, PSE security files, SSO credentials, SSFS file formats, and LZH/LZC compression algorithms.

### What SAPRFC.py Actually Implements

The module is a **Scapy-based packet definition library**, not a high-level RFC client. It defines:

**Packet Classes:**
- `SAPRFC` — Main RFC packet with conditional fields for versions 2, 3, and 6
- `SAPCPIC` — Common Programming Interface for Communications (CPIC) layer, with 24+ conditional fields
- `SAPCPIC2` — CPIC variant for started programs and RFC_PING
- `SAPCPICSUFFIX` — Variable-length suffixes with kernel version info
- `SAPRFCDTStruct` — Started program setup with timeout, IPv6, kernel version, credentials
- `SAPRFCTHStruct` — Transaction header with system ID, user ID, action fields
- `SAPRFCEXTEND` — Extended info with LU/TP names and CPIC parameters
- `SAPRFXPG` / `SAPRFXPG_END` — Started program execution and termination packets

**Protocol Constants:**
- 18 RFC request types (`GW_NORMAL_CLIENT`, `GW_REGISTER_TP`, `CHECK_GATEWAY`, `GW_SEND_CMD`, etc.)
- 28+ function types (`F_SAP_ALLOCATE`, `F_SAP_INIT`, `F_SAP_SEND`, `F_SAP_RECEIVE`, etc.)
- 33 monitor commands (`NOOP`, `DELETE_CONN`, `READ_CONN_TBL`, `RELOAD_ACL`, etc.)
- 46 APPC return codes
- RFC connection types (`R_2_CONN`, `ABAP_CONN`, `TCP_CONN`, `SNA_CPIC_CONN`)

### What SAPRFC.py Does NOT Implement (Critical Gaps)

1. **No RFC Item-Level Protocol** — The actual function call payload uses an item-based TLV (Type-Length-Value) encoding. The Wireshark SAP dissector (`packet-saprfc.c`) documents this structure:
   - Item ID1=0x01, ID2=0x02: **function name**
   - Item ID1=0x02, ID2=0x01: **import parameter names**
   - Item ID1=0x02, ID2=0x05: **export parameter names**
   - Item ID1=0x03, ID2=0x01: **table names**
   - Item ID1=0x03, ID2=0x02: **table metadata** (row width + row count)
   - Item ID1=0x03, ID2=0x05: **compressed table content**
   - Item ID1=0xFF, ID2=0xFF: **end-of-message marker**

   **None of these item structures are defined in pysap.**

2. **No ABAP Data Type Serialization** — The Wireshark dissector recognizes 15 ABAP data types (TYPC through TYPDECF34). No code exists for marshaling Python types to/from ABAP binary wire format.

3. **No RFC Function Call API** — No `call_function()` or equivalent method.

4. **No Authentication Handshake** — While `SAPRFCDTStruct` contains username fields, there is no full RFC logon sequence with password hashing, ticket-based auth, or SNC negotiation.

5. **No Serialization Modes** — SAP uses three serialization formats:
   - Classic binary (flat/TABLES parameters)
   - xRFC (XML-based, deep structures)
   - basXML (newer unified format)

   None are implemented.

### What CAN Be Done with pysap's RFC Today

1. **Gateway monitoring** — Connecting as a gateway monitor using `GW_SEND_CMD`
2. **Gateway connectivity checks** — `CHECK_GATEWAY` packets
3. **External program execution via SAPXPG** — The SAP GW RCE exploit demonstrates the complete sequence: `GW_NORMAL_CLIENT` → `F_SAP_INIT` → `F_SAP_SEND` with `SAPRFXPG`
4. **Packet capture analysis / fuzzing** — Crafting and dissecting RFC protocol frames

### Notable Forks

| Fork | Author | Purpose |
|---|---|---|
| [gelim/pysap](https://github.com/gelim/pysap) | Mathieu Geli | SAPMS + SAPRFC patches for Gateway/MS research |
| [chipik/SAP_GW_RCE_exploit](https://github.com/chipik/SAP_GW_RCE_exploit) | Dmitry Chastuhin | Most complete RFC handshake using pysap (gateway RCE) |
| [usdAG/pysap_sncscan](https://github.com/usdAG/pysap_sncscan) | usd AG | SNC scanning capabilities |

**No fork adds actual RFC function module calling capability.**

### Key Conference Talks

| Year | Conference | Authors | Title |
|---|---|---|---|
| 2012 | DEF CON 20 | Martin Gallo | "Uncovering SAP Vulnerabilities: Reversing and Breaking the Diag Protocol" |
| 2014 | Troopers 14 | Martin Gallo | "SAP's Network Protocols Revisited" — RFC, Gateway, Diag, MS, Enqueue |
| 2017 | Troopers 17 | Martin Gallo | "Intercepting SAP SNC-protected Traffic" |
| 2019 | OPCDE Dubai | Chastuhin, Geli | "(SAP) Gateway to Heaven" — the 10KBLAZE research |
| 2023 | Troopers 23 | Fabian Hagg (SEC Consult) | "Everyone Knows SAP, Everyone Uses RFC, No One Knows RFC: From RFC to RCE" |

---

## 12. SAPology's Existing RFC Implementation

SAPology already implements raw socket-level RFC communication in `files/sap_rfc_system_info.py` (1,452 lines, pure Python 3, no external dependencies):

### What's Already Implemented

- **SAP NI framing** — 4-byte big-endian length prefix, keepalive handling
- **V6 single-packet RFC call** — Template replay from pcap capture, with dynamic field patching (connection ID, routing string, client IPs, timestamp, UUIDs)
- **V2 GW_NORMAL_CLIENT + F_SAP_INIT** — Gateway handshake with error message parsing
- **Chipik-style F_SAP_INIT** — External program type (sapxpg/T_75) for RFC_SYSTEM_INFO extraction
- **RFCSI_EXPORT parsing** — Full field definitions for the 245-character/490-byte response structure (RFCPROTO, RFCCHARTYP, RFCINTTYP, RFCFLOTYP, RFCDEST, RFCHOST, RFCSYSID, RFCDATABS, RFCDBHOST, RFCDBSYS, RFCSAPRL, RFCMACH, RFCOPSYS, RFCTZONE, RFCDATEFM, RFCIPADDR, RFCKERNRL, RFCHOST2, RFCSI_RESV, RFCIPV6ADDR)
- **Multiple probe methods** with fallback
- **JSON output** support

### Protocol Knowledge Already Captured

From the template packet analysis, the following item IDs are observable in the binary:

```
Item 05:14 — Binary UUID (16 bytes)
Item 01:11 — Unknown (possibly session/context)
Item 01:17 — Unknown
Item 01:30 — Function name ("RFC_SYSTEM_INFO" padded to 30 bytes + "FT" suffix)
Item 01:22 — Timestamp (14 bytes YYYYMMDDHHMMSS)
Item 01:23 — Unknown
Item 01:20 — Unknown (28 bytes, possibly hash/key)
Item 01:19 — Username ("SAPADM")
Item 05:01 — Unknown
Item 05:02 — Unknown
Item 01:02 — Function name (repeated, 15 bytes)
Item 05:03 — Unknown
Item 01:25 — UUID ASCII (32 bytes)
Item 01:31 — *TH* block (185 bytes, contains system name, SID, user, UUID)
Item 05:12 — Unknown
Item 02:05 — Export parameter names ("CURRENT_RESOURCES", "MAXIMAL_RESOURCES", "RECOMMENDED_DELAY", "RFCSI_EXPORT")
Item 01:04 — Unknown (possibly metadata/serialization info)
Item 04:FF — End marker (0xFFFF)
```

This is **extremely valuable** — it shows the item-level TLV encoding in practice, exactly what pysap is missing.

### Relationship to Gateway Protocol

`files/sap_gw_xpg_standalone.py` (1,052 lines) implements the gateway protocol flow for SAPXPG:
- `GW_NORMAL_CLIENT` → `F_SAP_INIT` → `F_SAP_SEND` (with CPIC/XPGW structures)
- Full connection lifecycle management
- Error handling and response parsing

---

## 13. What It Would Take to Build a Pure-Python RFC Client

Building on pysap's transport layer and SAPology's existing protocol knowledge:

### Required Components

| Component | Effort | Complexity | Notes |
|---|---|---|---|
| RFC Item Protocol Layer | 2-3 weeks | Medium | Structure known from Wireshark dissector (`packet-saprfc.c`) and SAPology's template analysis |
| Basic ABAP Type Serialization (flat types) | 2-3 weeks | Medium | Binary formats are deterministic: CHAR, INT1/2/4, FLOAT, NUMC, DATE, TIME, PACKED |
| ABAP Table Serialization (with compression) | 1-2 weeks | Medium | pysap already has LZH/LZC decompression |
| Deep Structure Serialization (xRFC/basXML) | 3-4 weeks | High | XML-based format, less publicly documented |
| Authentication Handshake | 2-3 weeks | High | Password hashing algorithms need reverse engineering |
| High-Level Client API | 1 week | Low | Wrapper around lower layers |
| Testing & Debugging | 2-4 weeks | High | Needs access to real SAP system |
| **Total** | **~13-20 weeks** | | **For a basic but functional implementation** |

### Pragmatic Shortcut: Template-Based Approach

Rather than building a full RFC protocol stack, a faster approach would be:

1. **Use Wireshark to capture** authenticated RFC calls for specific function modules
2. **Build binary templates** with placeholder fields (like SAPology already does for RFC_SYSTEM_INFO)
3. **Parameterize the templates** — patch function name, import parameters, credentials at known offsets
4. **Parse responses** using the known item-level TLV structure and ABAP type definitions
5. **Focus on classic binary format only** — skip xRFC and basXML initially

This is essentially what SAPology already does for RFC_SYSTEM_INFO, extended to authenticated calls with arbitrary function modules.

### The Wireshark SAP RFC Dissector as Rosetta Stone

The most valuable reference for building a pure-Python RFC client is the **Wireshark SAP RFC dissector** source code:

- **Repository:** [SecureAuthCorp/SAP-Dissection-plug-in-for-Wireshark](https://github.com/SecureAuthCorp/SAP-Dissection-plug-in-for-Wireshark)
- **Key file:** `src/packet-saprfc.c`
- Documents: item-based TLV encoding, ABAP type identifiers, table compression structures, function name encoding, parameter marshaling

This dissector is the closest thing to public documentation of the RFC wire protocol.

---

## 14. Comparison Table

| # | Approach | Requires SAP SDK? | SAP-Side Config? | Python Libraries | Production Ready? | Complexity |
|---|----------|:---:|---|---|:---:|---|
| 1 | **SOAP /sap/bc/soap/rfc** | No | Minimal (SICF) | `zeep`, `requests` | **Yes** | Low |
| 2 | **OData via SEGW** | No | Medium (ABAP) | `pyodata`, `requests` | **Yes** | Medium |
| 3 | **Custom ICF REST handler** | No | Medium (ABAP) | `requests` | **Yes** | Medium |
| 4 | **BTP / Integration Suite** | No | High | `requests` | **Yes** | High |
| 5 | **JCo via JPype** | No* | None | `JPype1` | Experimental | High |
| 6 | **NCo via pythonnet** | No* | None | `pythonnet` | Experimental | High |
| 7 | **ctypes + NW RFC SDK** | **Yes** | None | ctypes (stdlib) | **Yes** | Low |
| 8 | **Raw socket-level RFC** | No | None | `socket`, `struct` | Research only | Extreme |
| 9 | **gRPC** | N/A | N/A | N/A | No | N/A |

\* JCo and NCo have their own proprietary native libraries (separate from the NW RFC SDK), still requiring SAP download.

---

## 15. Recommendations

### For Direct RFC Protocol Access (Requires SDK)

**Rank 1: ctypes + SAP NW RFC SDK (`sap_rfc_ctypes.py`)**
- Cross-platform (Windows, Linux, macOS) — pure Python, no compilation
- Drop-in PyRFC replacement with the same call semantics
- Auto-discovers table/structure fields via SDK metadata introspection
- Type-aware: native INT, FLOAT, BCD, DATE, TIME, BYTE, XSTRING handling
- Proper error handling with typed exceptions
- No pip dependencies (stdlib only)
- Only requires: SAP NW RFC SDK download + `SAPNWRFC_HOME` env var

### For SDK-Free Access (No SAP Download Required)

**Rank 2: SOAP via `/sap/bc/soap/rfc` + zeep**
- Lowest barrier to entry, no SAP download needed
- The SAP ICF service exists by default — just activate it in SICF
- Call ANY RFC-enabled function module via SOAP from Python
- Auto-generated WSDL at `http://<host>:<port>/sap/bc/soap/wsdl11?services=<FM_NAME>`
- Only requires `pip install zeep requests`

**Rank 3: OData via SEGW + pyodata/requests**
- SAP's strategic direction
- Clean REST/JSON interface
- Requires one-time ABAP-side SEGW project creation per function module

**Rank 4: SAP Integration Suite middleware**
- Best for complex enterprise scenarios with multiple systems
- Abstracts RFC behind standard REST APIs

### For Direct Protocol Access (SDK-Free)

**Rank 5: JCo via JPype** or **NCo via pythonnet**
- Viable if you need direct RFC protocol access without the NW RFC SDK specifically
- Both JCo and NCo are independently maintained by SAP
- Experimental/niche with limited community examples

### For Security Research

**Rank 6: Raw socket-level RFC (pysap + SAPology)**
- SAPology already demonstrates unauthenticated RFC_SYSTEM_INFO calls
- pysap provides the transport layer foundation
- The Wireshark dissector (`packet-saprfc.c`) is the Rosetta Stone for the wire protocol
- Viable for specific unauthenticated calls; building authenticated support would take 13-20 weeks

---

## 16. References

### SAP Official Documentation
- [SAP RFC Protocol — ABAP Keyword Documentation](https://help.sap.com/doc/abapdocu_751_index_htm/7.51/en-US/abenrfc_protocol.htm)
- [SAP JCo Official Page](https://support.sap.com/en/product/connectors/jco.html)
- [SAP NCo Official Page](https://support.sap.com/en/product/connectors/msnet.html)
- [SAP ICF Documentation](https://help.sap.com/doc/abapdocu_751_index_htm/7.51/en-US/abenicf.htm)
- [SAP WebSocket RFC](https://help.sap.com/docs/ABAP_PLATFORM_NEW/753088fc00704d0a80e7fbd6803c8adb/51f1edadb2754e539f6e6335dd1eb4cc.html)

### SAP Community / Blogs
- [Step-by-step OData from RFC (SAP Blog)](https://community.sap.com/t5/technology-blog-posts-by-sap/step-by-step-guide-to-build-an-odata-service-based-on-rfcs-part-1/ba-p/12989993)
- [Calling RFC over HTTP (SAP Blog)](https://blogs.sap.com/2012/02/13/calling-rfc-enabled-function-modules-over-http-from-external-application/)
- [Consume FM as Web Service (SAP Blog)](https://community.sap.com/t5/technology-blog-posts-by-sap/how-easy-it-is-to-consume-function-module-as-web-service-and-connect-it/ba-p/13317991)
- [Generate SOAP Services for Legacy RFCs (SAP Blog)](https://community.sap.com/t5/technology-blog-posts-by-members/generate-soap-services-for-your-legacy-rfcs-to-simplify-integration-out-of/ba-p/13557764)
- [PyRFC Unmaintained Discussion](https://community.sap.com/t5/technology-q-a/pyrfc-is-unmaintained-calling-sap-rfc-directly-from-python-using-nwrfcsdk/qaq-p/14305984)
- [PyRFC Archive Notice — GitHub Issue #372](https://github.com/SAP-archive/PyRFC/issues/372)
- [ABAP RFC from BTP Python Buildpack](https://community.sap.com/t5/technology-blog-posts-by-sap/abap-rfc-connectivity-from-btp-python-buildpack/ba-p/13575348)
- [Modernizing RFC/BAPI-based Integrations for Clean Core](https://community.sap.com/t5/technology-blog-posts-by-sap/modernizing-rfc-bapi-based-integrations-for-a-clean-core-with-sap/ba-p/14240582)
- [WebSocket RFC Blog](https://community.sap.com/t5/technology-blog-posts-by-sap/websocket-rfc-rfc-for-the-internet/ba-p/13502531)

### Open Source Projects
- [OWASP/pysap](https://github.com/OWASP/pysap) — SAP protocol dissection (Martin Gallo)
- [pysap SAPRFC API Reference](https://pysap.readthedocs.io/en/latest/api/pysap.SAPRFC.html)
- [gelim/pysap fork](https://github.com/gelim/pysap) — Gateway/MS patches (Mathieu Geli)
- [chipik/SAP_GW_RCE_exploit](https://github.com/chipik/SAP_GW_RCE_exploit) — Gateway RCE (Dmitry Chastuhin)
- [SAP-archive/PyRFC](https://github.com/SAP-archive/PyRFC) — Archived
- [jdsricardo/SAP-RFC-Python-without-PyRFC](https://github.com/jdsricardo/SAP-RFC-Python-without-PyRFC) — ctypes approach (Windows-only)
- `files/sap_rfc_ctypes.py` — SAPology's cross-platform ctypes wrapper (this project)
- [piersharding/python-sapnwrfc](https://github.com/piersharding/python-sapnwrfc) — Legacy
- [SAP/python-pyodata](https://github.com/SAP/python-pyodata) — SAP's official OData client
- [SecureAuthCorp/SAP-Dissection-plug-in-for-Wireshark](https://github.com/SecureAuthCorp/SAP-Dissection-plug-in-for-Wireshark) — Wireshark SAP dissector (key file: `src/packet-saprfc.c`)

### Security Research / Conference Talks
- Martin Gallo — DEF CON 20 (2012): "Uncovering SAP Vulnerabilities: Reversing and Breaking the Diag Protocol"
- Martin Gallo — Troopers 14 (2014): "SAP's Network Protocols Revisited"
- Martin Gallo — Troopers 17 (2017): "Intercepting SAP SNC-protected Traffic"
- Chastuhin & Geli — OPCDE 2019: "(SAP) Gateway to Heaven" (10KBLAZE)
- Fabian Hagg — Troopers 23 (2023): "Everyone Knows SAP, Everyone Uses RFC, No One Knows RFC: From RFC to RCE"

### Other
- [Zeep SOAP Library](https://docs.python-zeep.org/)
- [JPype Documentation](https://jpype.readthedocs.io/en/latest/userguide.html)
- [pythonnet on GitHub](https://github.com/pythonnet/pythonnet)
- [SAP Note 3255746 — RFC Usage Restrictions](https://theobald-software.com/en/blog/sap-note-325574)
- [SAP OData from RFC (saplearners.com)](https://saplearners.com/build-odata-service-using-rfc-bapi-in-sap-netweaver-gateway/)
- [How to Call SAP OData Services with Python](https://ourcodeworld.com/articles/read/2684/how-to-call-sap-odata-services-with-python)
