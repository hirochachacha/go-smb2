[< Back to MS-FSCC Index](../INDEX.md)

---

# 2 Structures

The structures specified in this document have no transport requirements
of their own. Instead, they are packaged and transported in accordance
with the protocol that makes use of them, such as the Server Message
Block (SMB) Protocol, as specified in
[\[MS-SMB\]](%5bMS-SMB%5d.pdf#Section_f210069c70864dc2885e861d837df688).
A server receiving one of these structures passes the structure to an
implementation-defined function that performs the indicated operation on
a file, a file system, or a
[**volume**](#gt_9a876829-33a1-4f0b-8b81-8552b7e5561c).

The following sections specify how File System Control Codes messages
are encapsulated on the wire and common File System Control Codes data
types.

This document references commonly used data types as defined in
[\[MS-DTYP\]](%5bMS-DTYP%5d.pdf#Section_cca2742956894a16b2b49325d93e4ba2).

Unless otherwise qualified, instances of **GUID** in this section refer
to \[MS-DTYP\] section 2.3.4.

