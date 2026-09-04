[< Back to MS-SMB2 Index](../INDEX.md)

---

# 6 Appendix A: Product Behavior

The information in this specification is applicable to the following
Microsoft products or supplemental software. References to product
versions include updates to those products.

The terms "earlier" and "later", when used with a product version, refer
to either all preceding versions or all subsequent versions,
respectively. The term "through" refers to the inclusive range of
versions. Applicable Microsoft products are listed chronologically in
this section.

**Windows Client**

- Windows Vista operating system

- Windows 7 operating system

- Windows 8 operating system

- Windows 8.1 operating system

- Windows 10 operating system

- Windows 11 operating system

**Windows Server**

- Windows Server 2008 operating system

- Windows Server 2008 R2 operating system

- Windows Server 2012 operating system

- Windows Server 2012 R2 operating system

- Windows Server 2016 operating system

- Windows Server operating system

- Windows Server 2019 operating system

- Windows Server 2022 operating system

- Windows Server 2025 operating system

Exceptions, if any, are noted in this section. If an update version,
service pack or Knowledge Base (KB) number appears with a product name,
the behavior changed in that update. The new behavior also applies to
subsequent updates unless otherwise specified. If a product edition
appears with the product version, behavior is different in that product
edition.

Unless otherwise specified, any statement of optional behavior in this
specification that is prescribed using the terms "SHOULD" or "SHOULD
NOT" implies product behavior in accordance with the SHOULD or SHOULD
NOT prescription. Unless otherwise specified, the term "MAY" implies
that the product does not follow the prescription.

[\<1\> Section 1.6](#Appendix_A_Target_1): The following table
illustrates the support of SMB 2 protocol on various Windows operating
system versions.

| Operating System | SMB 2 dialects supported |
|----|----|
| Windows 10, Windows Server 2016, Windows Server operating system, Windows Server 2019, Windows Server 2022, Windows 11 | SMB 3.1.1, SMB 3.0.2, SMB 3.0, SMB 2.1, SMB 2.0.2 |
| Windows 8.1, Windows Server 2012 R2 | SMB 3.0.2, SMB 3.0, SMB 2.1, SMB 2.0.2 |
| Windows 8, Windows Server 2012 | SMB 3.0, SMB 2.1, SMB 2.0.2 |
| Windows 7, Windows Server 2008 R2 | SMB 2.1, SMB 2.0.2 |
| Windows Vista operating system with Service Pack 1 (SP1), Windows Server 2008 | SMB 2.0.2 |
| Previous versions of Windows | None. They support the SMB Protocol, as specified in [\[MS-SMB\]](%5bMS-SMB%5d.pdf#Section_f210069c70864dc2885e861d837df688) |

Windows Vista RTM implemented dialect 2.000, which was not interoperable
and was obsoleted by Windows Vista SP1.

[\<2\> Section 2.1](#Appendix_A_Target_2): Windows 11, version 24H2
operating system and later and Windows Server 2025 and later SMB2
servers allow listening on any configured port only when the transport
is QUIC.

Windows 11, version 24H2 and later and Windows Server 2025 and later
SMB2 clients can connect to an SMB2 server that allows listening on any
configured port over TCP, RDMA and QUIC transports.

By default, Windows SMB2 clients and servers always use a single stream
per QUIC connection. Sending or receiving more than one stream per
connection will be blocked by the underlying transport QUIC.

[\<3\> Section 2.2.1.2](#Appendix_A_Target_3): Windows clients set this
field to 0xFEFF.

[\<4\> Section 2.2.1.2](#Appendix_A_Target_4): Windows servers do not
use this field in the request processing and return the value received
in the request.

[\<5\> Section 2.2.2](#Appendix_A_Target_5): Windows 10 v1703 operating
system and prior and Windows Server 2016 and prior set **ErrorData** to
one uninitialized byte when **ByteCount** is zero.

[\<6\> Section 2.2.2.2.1](#Appendix_A_Target_6): Windows-based servers
will never follow a symlink. It is the client's responsibility to
evaluate the symlink and access the actual file using the symlink.
Windows-based servers only return STATUS_STOPPED_ON_SYMLINK when the
open fails due to presence of a symlink.

[\<7\> Section 2.2.2.2.1](#Appendix_A_Target_7): Windows-based servers
will return an absolute target to a local resource in the format of
"\\?\C:\\.." where C: is the drive mount point on the local system and
... is replaced by the remainder of the path to the target.

[\<8\> Section 2.2.3](#Appendix_A_Target_8): Windows-based SMB2 servers
fail the request and return STATUS_INVALID_PARAMETER, if the
**DialectCount** field is greater than 64.

[\<9\> Section 2.2.3](#Appendix_A_Target_9): Windows 8.1 operating
system and later and Windows Server 2012 R2 operating system and later
fail the request with STATUS_NOT_SUPPORTED if the **Reserved** field is
set to a nonzero value.

[\<10\> Section 2.2.3](#Appendix_A_Target_10): Windows Vista SP1 and
Windows Server 2008 do not support this dialect revision.

[\<11\> Section 2.2.3](#Appendix_A_Target_11): Windows Vista SP1,
Windows Server 2008, Windows 7, and Windows Server 2008 R2 do not
support this dialect revision.

[\<12\> Section 2.2.3](#Appendix_A_Target_12): Windows Vista SP1,
Windows Server 2008, Windows 7, Windows Server 2008 R2, Windows 8, and
Windows Server 2012 do not support the SMB 3.0.2 dialect.

[\<13\> Section 2.2.3](#Appendix_A_Target_13): Windows Vista SP1,
Windows Server 2008, Windows 7, Windows Server 2008 R2, Windows 8,
Windows Server 2012, Windows 8.1, and Windows Server 2012 R2 do not
support the SMB 3.1.1 dialect.

[\<14\> Section 2.2.3.1](#Appendix_A_Target_14): Windows 10 v1809
operating system operating system and prior and Windows Server v1809
operating system operating system and prior do not send or process
SMB2_COMPRESSION_CAPABILITIES.

[\<15\> Section 2.2.3.1](#Appendix_A_Target_15): Windows 10 v1809
operating system and prior and Windows Server v1809 operating system and
prior do not send or process SMB2_NETNAME_NEGOTIATE_CONTEXT_ID.

[\<16\> Section 2.2.3.1](#Appendix_A_Target_16): Windows 10 v1909
operating system and prior and Windows Server v1909 operating system and
prior do not send or process SMB2_TRANSPORT_CAPABILITIES.

[\<17\> Section 2.2.3.1](#Appendix_A_Target_17): Windows 10 operating
system and prior and Windows Server v20H2 operating system and prior do
not send or process SMB2_RDMA_TRANSFORM_CAPABILITIES.

[\<18\> Section 2.2.3.1](#Appendix_A_Target_18): Windows 10 operating
system and prior and Windows Server v20H2 operating system and prior do
not send or process SMB2_SIGNING_CAPABILITIES.

[\<19\> Section 2.2.3.1.5](#Appendix_A_Target_19): Windows 10 v2004
operating system, Windows 10 v20H2 operating system, Windows Server
v2004 operating system, and Windows Server v20H2 do not send or process
SMB2_ACCEPT_TRANSPORT_LEVEL_SECURITY.

[\<20\> Section 2.2.4](#Appendix_A_Target_20): Windows Vista SP1 and
Windows Server 2008 do not support this dialect revision.

[\<21\> Section 2.2.4](#Appendix_A_Target_21): Windows Vista SP1,
Windows Server 2008, Windows 7 and Windows Server 2008 R2 do not support
this dialect revision.

[\<22\> Section 2.2.4](#Appendix_A_Target_22): Windows Vista SP1,
Windows Server 2008, Windows 7, Windows Server 2008 R2, Windows 8, and
Windows Server 2012 do not support this dialect revision.

[\<23\> Section 2.2.4](#Appendix_A_Target_23): Windows Vista SP1,
Windows Server 2008, Windows 7, Windows Server 2008 R2, Windows 8,
Windows Server 2012, Windows 8.1, and Windows Server 2012 R2 do not
support the SMB 3.1.1 dialect.

[\<24\> Section 2.2.4](#Appendix_A_Target_24): The "SMB 2.???" dialect
string is not supported by SMB2 clients and servers in Windows Vista SP1
and Windows Server 2008.

[\<25\> Section 2.2.4](#Appendix_A_Target_25): Windows-based SMB2
servers can set this field to any value.

[\<26\> Section 2.2.4](#Appendix_A_Target_26): Windows–based SMB2
servers generate a new **ServerGuid** each time they are started.

[\<27\> Section 2.2.4](#Appendix_A_Target_27): Windows clients do not
enforce the **MaxTransactSize** value.

[\<28\> Section 2.2.5](#Appendix_A_Target_28): Windows-based clients
always set the **Capabilities** field to SMB2_GLOBAL_CAP_DFS(0x00000001)
and the server will ignore them on receipt.

[\<29\> Section 2.2.5](#Appendix_A_Target_29): Windows clients set the
**Buffer** with a token as produced by the NTLM authentication protocol
in the case, see
[\[MS-NLMP\]](%5bMS-NLMP%5d.pdf#Section_b38c36ed28044868a9ff8dd3182128e4)
section 3.1.5.1.

[\<30\> Section 2.2.6](#Appendix_A_Target_30): Windows clients set the
**Buffer** with a token as produced by the NTLM authentication protocol
in the case, see \[MS-NLMP\] section 3.1.5.1.

[\<31\> Section 2.2.9](#Appendix_A_Target_31): Windows 10 v1703 and
prior and Windows Server 2016 and prior do not support the
SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER flag.

[\<32\> Section 2.2.9](#Appendix_A_Target_32): The Windows SMB 2
Protocol client translates any names of the form \\server\pipe to
\\server\IPC\$ before sending a request on the network.

[\<33\> Section 2.2.10](#Appendix_A_Target_33):
SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK is not supported on Windows Vista
SP1 and Windows Server 2008.

[\<34\> Section 2.2.10](#Appendix_A_Target_34): Windows 10 v1703 and
prior and Windows Server 2016 and prior do not send or process this
flag.

[\<35\> Section 2.2.10](#Appendix_A_Target_35): Windows 10 operating
system and prior and Windows Server v20H2 operating system and prior do
not send or process this flag.

[\<36\> Section 2.2.13](#Appendix_A_Target_36): Windows-based clients
never use exclusive oplocks. Because there are no situations where the
client would require an exclusive oplock where it would not also require
an SMB2_OPLOCK_LEVEL_BATCH, it always requests an
SMB2_OPLOCK_LEVEL_BATCH.

[\<37\> Section 2.2.13](#Appendix_A_Target_37): When opening a printer
file or a named pipe, Windows-based servers ignore these **ShareAccess**
values.

[\<38\> Section 2.2.13](#Appendix_A_Target_38): When opening a printer
object, Windows-based servers ignore this value.

[\<39\> Section 2.2.13](#Appendix_A_Target_39): When opening a printer
object, Windows-based servers ignore this value.

[\<40\> Section 2.2.13](#Appendix_A_Target_40): When opening a printer
object, Windows-based servers ignore this value.

[\<41\> Section 2.2.13](#Appendix_A_Target_41): Windows-based servers
reserve all bits that are not specified in the table. If any of the
reserved bits are set, STATUS_NOT_SUPPORTED is returned.

[\<42\> Section 2.2.13](#Appendix_A_Target_42): Windows SMB2 clients do
not initialize this bit. The bit contains the value specified by the
caller when requesting the open.

[\<43\> Section 2.2.13](#Appendix_A_Target_43): Windows SMB2 clients do
not initialize this bit. The bit contains the value specified by the
caller when requesting the open.

[\<44\> Section 2.2.13](#Appendix_A_Target_44): Windows SMB2 clients do
not initialize this bit. The bit contains the value specified by the
caller when requesting the open.

[\<45\> Section 2.2.13](#Appendix_A_Target_45): Windows SMB2 clients do
not initialize this bit. The bit contains the value specified by the
caller when requesting the open.

[\<46\> Section 2.2.13](#Appendix_A_Target_46): Windows SMB2 clients do
not initialize this bit. The bit contains the value specified by the
caller when requesting the open.

[\<47\> Section 2.2.13](#Appendix_A_Target_47): Windows Vista SP1,
Windows Server 2008, Windows 7, Windows 8, and Windows 8.1-based clients
will set this bit when it is requested by the application.

[\<48\> Section 2.2.13.1.1](#Appendix_A_Target_48): Windows sets this
flag to the value passed in by the higher-level application.

[\<49\> Section 2.2.13.1.1](#Appendix_A_Target_49): Windows 7 operating
system and later and Windows Server 2008 R2 operating system and later
do not ignore the SYNCHRONIZE bit, and pass it to the underlying object
store. If the caller requests SYNCHRONIZE in the *DesiredAccess*
parameter, but the SYNCHRONIZE access is not granted to the caller for
the object being created or opened, the underlying object store fails
the request and returns STATUS_ACCESS_DENIED. When SYNCHRONIZE access is
granted, the SYNCHRONIZE bit is returned in **MaximalAccess** field of
SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE with no other behavior.

[\<50\> Section 2.2.13.1.1](#Appendix_A_Target_50): Windows fails the
create request with STATUS_ACCESS_DENIED if the caller does not have the
SeSecurityPrivilege, as specified in
[\[MS-LSAD\]](%5bMS-LSAD%5d.pdf#Section_1b5471ef4c334a91b079dfcbb82f05cc)
section 3.1.1.2.1.

[\<51\> Section 2.2.13.1.2](#Appendix_A_Target_51): Windows sets this
flag to the value passed in by the higher-level application.

[\<52\> Section 2.2.13.1.2](#Appendix_A_Target_52): Windows 7 operating
system and later and Windows Server 2008 R2 operating system and later
do not ignore the SYNCHRONIZE bit, and pass it to the underlying object
store. If the caller requests SYNCHRONIZE in the **DesiredAccess**
parameter, but the SYNCHRONIZE access is not granted to the caller for
the object being created or opened, the underlying object store fails
the request and returns STATUS_ACCESS_DENIED. When SYNCHRONIZE access is
granted, the SYNCHRONIZE bit is returned in **MaximalAccess** field of
[SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE (section 2.2.14.2.5)](#Section_0fe6be153a7640329a4456f846ac6244)
with no other behavior.

[\<53\> Section 2.2.13.1.2](#Appendix_A_Target_53): Windows fails the
create request with STATUS_ACCESS_DENIED if the caller does not have the
SeSecurityPrivilege, as specified in \[MS-LSAD\] section 3.1.1.2.1.

[\<54\> Section 2.2.13.2](#Appendix_A_Target_54): If DataLength is 0,
Windows-based clients set this field to any value.

[\<55\> Section 2.2.13.2.8](#Appendix_A_Target_55): Windows 7 operating
system and later and Windows Server 2008 R2 operating system and later
acting as SMB servers support the following combinations of values: 0,
READ, READ \| WRITE, READ \| HANDLE, READ \| WRITE \| HANDLE.

[\<56\> Section 2.2.13.2.10](#Appendix_A_Target_56): Windows Server 2012
operating system and later support the following combinations of values:
0, READ, READ \| WRITE, READ \| HANDLE, READ \| WRITE \| HANDLE.

[\<57\> Section 2.2.14](#Appendix_A_Target_57): Windows-based SMB2
servers always return FILE_OPENED for pipes with successful opens.

[\<58\> Section 2.2.14](#Appendix_A_Target_58): Windows-based SMB2
servers can set this field to any value.

[\<59\> Section 2.2.14.2.11](#Appendix_A_Target_59): Windows 8 operating
system and later and Windows Server 2012 operating system and later set
this field to an arbitrary value.

[\<60\> Section 2.2.19](#Appendix_A_Target_60): Windows 10 v1809 and
prior and Windows Server v1809 and prior do not send or process
SMB2_READFLAG_REQUEST_COMPRESSED flag.

[\<61\> Section 2.2.20](#Appendix_A_Target_61): Windows 10 operating
system and prior and Windows Server v20H2 operating system and prior do
not send or process SMB2_READFLAG_RESPONSE_RDMA_TRANSFORM flag.

[\<62\> Section 2.2.21](#Appendix_A_Target_62): Windows 10 operating
system and prior and Windows Server v20H2 operating system and prior do
not send or process SMB2_CHANNEL_RDMA_TRANSFORM flag.

[\<63\> Section 2.2.24.2](#Appendix_A_Target_63): Windows clients always
set the LeaseState in the Lease Break Acknowledgment to be equal to the
LeaseState in the [Lease Break
Notification](#Section_9abe6f73f32f4a23998dee9da2b90e2e) from the
server.

[\<64\> Section 2.2.31](#Appendix_A_Target_64): Windows clients set the
**OutputOffset** field equal to the **InputOffset** field.

[\<65\> Section 2.2.31.1.1](#Appendix_A_Target_65): Windows clients set
this field to an arbitrary value.

[\<66\> Section 2.2.32](#Appendix_A_Target_66): Windows–based SMB2
servers set **InputCount** to the same value as the value received in
the IOCTL request for the following FSCTLs.

- FSCTL_FIND_FILES_BY_SID

- FSCTL_GET_RETRIEVAL_POINTERS

- FSCTL_QUERY_ALLOCATED_RANGES

- FSCTL_READ_FILE_USN_DATA

- FSCTL_RECALL_FILE

- FSCTL_WRITE_USN_CLOSE_RECORD

Windows clients ignore the **InputCount** field.

[\<67\> Section 2.2.32](#Appendix_A_Target_67): Windows–based SMB2
servers set **OutputOffset** to **InputOffset** + **InputCount**,
rounded up to a multiple of 8.

[\<68\> Section 2.2.32.2](#Appendix_A_Target_68): Windows-based SMB2
server will place 2 extra bytes set to zero in the SRV_SNAPSHOT_ARRAY
response, if **NumberOfSnapShotsReturned** is zero.

[\<69\> Section 2.2.32.3](#Appendix_A_Target_69): Windows-based servers
always send 4 bytes of zero for the **Context** field.

[\<70\> Section 2.2.32.4.1](#Appendix_A_Target_70): Windows–based SMB2
servers and clients do not check **SourceFileName**. It is ignored.

[\<71\> Section 2.2.32.5.1.2](#Appendix_A_Target_71): Windows 10 v1709
operating system through Windows 10 v1909 and Windows Server v1709
operating system through Windows Server v1909 set this field to any
value.

[\<72\> Section 2.2.33](#Appendix_A_Target_72): Windows 10 operating
system and prior and Windows Server 2022 operating system and prior do
not send or process this information class.

[\<73\> Section 2.2.33](#Appendix_A_Target_73): Windows 11, version 23H2
operating system and prior and Windows Server 2022 and prior do not send
or process FileId64ExtdDirectoryInformation information class.

[\<74\> Section 2.2.33](#Appendix_A_Target_74): Windows 11, version 23H2
and prior and Windows Server 2022 and prior do not send or process
FileId64ExtdBothDirectoryInformation information class.

[\<75\> Section 2.2.33](#Appendix_A_Target_75): Windows 11, version 23H2
and prior and Windows Server 2022 and prior do not send or process
FileIdAllExtdDirectoryInformation information class.

[\<76\> Section 2.2.33](#Appendix_A_Target_76): Windows 11, version 23H2
and prior and Windows Server 2022 and prior do not send or process
FileIdAllExtdBothDirectoryInformation information class.

[\<77\> Section 2.2.33](#Appendix_A_Target_77): SMB2 wildcard characters
are based on Windows wildcard characters, as described in
[\[MS-FSA\]](%5bMS-FSA%5d.pdf#Section_860b1516c45247b4bdbc625d344e2041)
section 2.1.4.4, Algorithm for Determining if a FileName Is in an
Expression. For more information on wildcard behavior in Windows, see
[\[FSBO\]](https://go.microsoft.com/fwlink/?LinkId=140636) section 7.

[\<78\> Section 2.2.37](#Appendix_A_Target_78): Windows SMB2 servers
ignore the **FileInfoClass** field for quota queries. Windows SMB2
clients set the **FileInfoClass** field to 0x20 for quota queries.

[\<79\> Section 2.2.37](#Appendix_A_Target_79): Windows clients set this
value to the offset from the start of the [SMB2
header](#Section_5cd6452260b34f3ea157fe66f1228052) to the beginning of
the **Buffer** field.

[\<80\> Section 2.2.37](#Appendix_A_Target_80): Windows clients send a
1-byte buffer of 0 when **InputBufferLength** is set to 0.

[\<81\> Section 2.2.37.1](#Appendix_A_Target_81): Windows-based clients
never send a request using the **SidBuffer** format 2.

[\<82\> Section 2.2.39](#Appendix_A_Target_82): Windows-based servers
will fail the request with STATUS_INVALID_PARAMETER if **BufferOffset**
is less than 0x60 or greater than 0xA0.

[\<83\> Section 2.2.41](#Appendix_A_Target_83): Windows 8 operating
system and later and Windows Server 2012 operating system and later set
this field to an arbitrary value.

[\<84\> Section 2.2.42.1](#Appendix_A_Target_84): Windows 10 v1809 and
prior and Windows Server v1809 and prior do not send or process SMB2
COMPRESSION_TRANSFORM_HEADER_UNCHAINED.

[\<85\> Section 2.2.42.2](#Appendix_A_Target_85): Windows 10 v1909 and
prior and Windows Server v1909 and prior do not send or process
SMB2_COMPRESSION_TRANSFORM_HEADER_CHAINED.

[\<86\> Section 2.2.42.2.1](#Appendix_A_Target_86): Windows 10 v1909 and
prior and Windows Server v1909 and prior do not send or process
SMB2_COMPRESSION_CHAINED_PAYLOAD_HEADER.

[\<87\> Section 2.2.42.2.2](#Appendix_A_Target_87): Windows 10 v1909 and
prior and Windows Server v1909 and prior do not send or process
SMB2_COMPRESSION_PATTERN_PAYLOAD_V1.

[\<88\> Section 2.2.43](#Appendix_A_Target_88): Windows 10 operating
system and prior and Windows Server v20H2 operating system and prior do
not send or process RDMA transforms.

[\<89\> Section 2.2.43.1](#Appendix_A_Target_89): Windows 10 operating
system and prior and Windows Server v20H2 operating system and prior do
not send or process RDMA transforms.

[\<90\> Section 3.1.3](#Appendix_A_Target_90): By default, Windows-based
servers set the
[RequireMessageSigning](#Section_95a74d9693a742eaaf1a688c17c522ee) value
to TRUE for domain controllers and FALSE for all other machines.

[\<91\> Section 3.1.3](#Appendix_A_Target_91): Windows 8 and later and
Windows Server 2012 and later set **IsEncryptionSupported** to TRUE.

[\<92\> Section 3.1.3](#Appendix_A_Target_92): Windows 10 v1903
operating system and later and Windows Server v1903 operating system and
later set **IsCompressionSupported** to TRUE.

[\<93\> Section 3.1.3](#Appendix_A_Target_93): Windows 10 v2004 and
later and Windows Server v2004 and later operating systems set
**IsChainedCompressionSupported** to TRUE.

[\<94\> Section 3.1.3](#Appendix_A_Target_94): Windows 11 operating
system and later and Windows Server 2022 operating system and later set
**IsRDMATransformSupported** to TRUE.

[\<95\> Section 3.1.3](#Appendix_A_Target_95): Windows 11 operating
system and later and Windows Server 2022 operating system and later set
this to TRUE.

[\<96\> Section 3.1.3](#Appendix_A_Target_96): Windows 11 and later and
Windows Server 2022 and later set **IsSigningCapabilitiesSupported** to
TRUE.

[\<97\> Section 3.1.3](#Appendix_A_Target_97): Windows 10 v2004 and
later and Windows Server v2004 and later set
**IsTransportCapabilitiesSupported** to TRUE.

[\<98\> Section 3.1.3](#Appendix_A_Target_98): Windows 11, version 24H2
and later and Windows Server 2022, 23H2 operating system and later set
**IsServerToClientNotificationsSupported** to TRUE.

[\<99\> Section 3.1.4.3](#Appendix_A_Target_99): Windows-based clients
and servers do not encrypt the message if the connection is NetBIOS over
TCP.

[\<100\> Section 3.1.4.4](#Appendix_A_Target_100): Windows-based clients
and servers do not compress the message if the connection is over RDMA.

[\<101\> Section 3.1.4.4](#Appendix_A_Target_101): Windows-based clients
choose to selectively compress only segments of SMB2 requests with large
payloads, whose size is greater than 4096 bytes.

[\<102\> Section 3.2.1.2](#Appendix_A_Target_102): Windows clients do
not enforce the **MaxTransactSize** value.

[\<103\> Section 3.2.2.1](#Appendix_A_Target_103): The Windows-based
client implements this timer with a default value of 60 seconds. The
client does not enforce this timer for the following commands:

- Named Pipe Read

- Named Pipe Write

- Directory Change Notifications

- Blocking byte range lock requests

- FSCTLs: FSCTL_PIPE_PEEK, FSCTL_PIPE_TRANSCEIVE, FSCTL_PIPE_WAIT

[\<104\> Section 3.2.2.2](#Appendix_A_Target_104): The Windows-based
clients scan existing connections every 10 seconds and disconnect idle
connects that have no open files and that have had no activity for 10 or
more seconds.

[\<105\> Section 3.2.2.3](#Appendix_A_Target_105): Windows clients set
this timer to 600 seconds, except Windows Vista, Windows Server 2008,
Windows 7, and Windows Server 2008 R2 clients, which do not implement
this timer.

[\<106\> Section 3.2.3](#Appendix_A_Target_106): Windows clients set
**RejectGuestAccess** to TRUE by default.

[\<107\> Section 3.2.3](#Appendix_A_Target_107): Windows clients set
**AllowInsecureGuestAccess** to FALSE by default.

[\<108\> Section 3.2.3](#Appendix_A_Target_108): Windows 8 operating
system and later and Windows Server 2012 operating system and later
clients set this based on a stored value in the registry.

[\<109\> Section 3.2.3](#Appendix_A_Target_109): Windows 10 v1903 and
later, and Windows Server v1903 and later set this to FALSE.

[\<110\> Section 3.2.3](#Appendix_A_Target_110): Windows 11 with
[\[MSKB-5035854\]](https://go.microsoft.com/fwlink/?linkid=2260955),
Windows 11, version 22H2 operating system with
[\[MSKB-5035942\]](https://go.microsoft.com/fwlink/?linkid=2261409),
Windows Server 2022 with
[\[MSKB-5035857\]](https://go.microsoft.com/fwlink/?linkid=2281610),
Windows Server 2022, 23H2, Windows 11, version 24H2 and later, and
Windows Server 2025 and later set **IsMutualAuthOverQUICSupported** to
TRUE.

[\<111\> Section 3.2.4.1.1](#Appendix_A_Target_111): A client can
selectively sign requests, and the server will sign the corresponding
responses.

[\<112\> Section 3.2.4.1.2](#Appendix_A_Target_112): Windows-based
clients require a minimum of 4
[**credits**](#gt_99b28556-d321-4a40-a062-65b5a49870e3).

[\<113\> Section 3.2.4.1.2](#Appendix_A_Target_113): The Windows-based
client will request credits up to a configurable maximum of 128 by
default. A Windows-based client sends a **CreditRequest** value of 0 for
an [SMB2 NEGOTIATE Request](#Section_e14db7ff763a42638b100c3944f52fc5)
and expects the server to grant at least 1 credit. In subsequent
requests, the client will request credits sufficient to maintain its
total outstanding limit at the configured maximum.

[\<114\> Section 3.2.4.1.3](#Appendix_A_Target_114): Windows 7 operating
system and later and Windows Server 2008 R2 operating system and later
SMB2 clients will block any newly initiated multi-credit requests that
exceed the shortage, but will send out other requests that can be
satisfied using the available credits.

[\<115\> Section 3.2.4.1.3](#Appendix_A_Target_115): Windows-based
clients set the **MessageId** field to 0, when the **AsyncId** field is
set to an asynchronous identifier of the request.

[\<116\> Section 3.2.4.1.4](#Appendix_A_Target_116): Windows-based
clients do not send compounded CREATE + READ/WRITE requests when the
payload size of the WRITE request or the anticipated response of the
READ request is greater than 65536.

[\<117\> Section 3.2.4.1.4](#Appendix_A_Target_117): Windows SMB2 Server
allows a mix of related and unrelated compound requests in the same
transport send. Upon encountering a request with
SMB2_FLAGS_RELATED_OPERATIONS not set Windows SMB2 Server treats it as
the start of a chain.

[\<118\> Section 3.2.4.1.4](#Appendix_A_Target_118): The Windows-based
client does not send unrelated [**compounded
requests**](#gt_3d5b08e2-38da-4cee-93d8-7e9a32f14670).

[\<119\> Section 3.2.4.1.4](#Appendix_A_Target_119): Windows-based
clients will compound certain related requests to improve performance,
by combining a Create with another operation, such as an attribute
query.

[\<120\> Section 3.2.4.1.5](#Appendix_A_Target_120): Windows 7 and
Windows Server 2008 R2 SMB2 clients set **CreditCharge** to 1 for IOCTL
requests.

[\<121\> Section 3.2.4.1.5](#Appendix_A_Target_121): Windows 7 operating
system and later and Windows Server 2012 operating system and later
based SMB2 clients set the **CreditCharge** field to 1 if
**Connection.SupportsMultiCredit** is FALSE.

[\<122\> Section 3.2.4.1.7](#Appendix_A_Target_122): Windows-based
clients choose the **Channel** with the least value of
**Channel.Connection.OutstandingRequests**.

[\<123\> Section 3.2.4.1.8](#Appendix_A_Target_123): Windows 10 v20H2
operating system and prior and Windows Server v20H2 operating system and
prior encrypt the message as specified in section
[3.1.4.3](#Section_24d74c0c3de140d9a949d169ad84361d) before sending.

[\<124\> Section 3.2.4.1.9](#Appendix_A_Target_124): Windows 10 v1903
and later, and Windows Server v1903 and later do not compress SMB2
NEGOTIATE request and SMB2 OPLOCK_BREAK Acknowledgment.

[\<125\> Section 3.2.4.2](#Appendix_A_Target_125): Windows-based clients
always set up a new transport connection when establishing a new session
to a server.

[\<126\> Section 3.2.4.2](#Appendix_A_Target_126): Windows will reuse an
existing session only if the access is by the same logged-on user and
the **Connection.ServerName** matches the application-supplied
**ServerName**.

[\<127\> Section 3.2.4.2](#Appendix_A_Target_127): Windows will reuse
the connection to establish a new session, if a connection is available
and **Connection.ServerName** matches the application-supplied
**ServerName**

[\<128\> Section 3.2.4.2.1](#Appendix_A_Target_128): Windows clients
initiate new transport connections to the server with Direct TCP and
NetBIOS over TCP. Windows 10 v1511 Enterprise operating system and
Windows Server 2012 operating system and later do not initiate a new
transport connection with RDMA, but do after a multichannel exchange if
a suitable interface is available.

[\<129\> Section 3.2.4.2.1](#Appendix_A_Target_129): Windows Vista SP1
and Windows Server 2008 clients enumerate all transports, send a Direct
TCP connection request, and then, after 500 milliseconds, send
connection requests to all other eligible addresses and all other
NetBIOS over TCP transports.

Windows 7 and Windows Server 2008 R2 clients enumerate all transports,
send a Direct TCP connection request, and then, after 1,000
milliseconds, send connection requests to all other eligible addresses
and all other NetBIOS over TCP transports.

Windows 8 operating system and later and Windows Server 2012 operating
system and later clients look up a server entry in **ServerList** where
**Server.ServerName** matches the **ServerName** to which the connection
is established. If no entry is found, the clients enumerate all
transports, send a Direct TCP connection request, and then, after 1,000
milliseconds, send connection requests to all other eligible addresses
over Direct TCP and NetBIOS over TCP transports. If an entry is found,
the clients send a Direct TCP connection request, and then, after 1,000
milliseconds, enumerate all transports and send connection requests to
all Direct TCP addresses.

In each case, the first successful connection is used and all others are
closed.

[\<130\> Section 3.2.4.2.2](#Appendix_A_Target_130): The Windows-based
client will initiate a multi-protocol negotiation unless it has
previously negotiated with this server and the negotiated server's
**DialectRevision** is equal to 0x0202, 0x0210, 0x0300, 0x0302, or
0x0311. In the latter case, it will initiate an [SMB2-Only
negotiate](#Section_77f696b89aa04ed1abb2c097c0ccb05a).

[\<131\> Section 3.2.4.2.2.2](#Appendix_A_Target_131): Windows 8,
Windows Server 2012, Windows 8.1, and Windows Server 2012 R2 set
**Dialects** array to all the dialects the client implements and
**DialectCount** to the number of dialects in **Dialects** array.

[\<132\> Section 3.2.4.2.2.2](#Appendix_A_Target_132): Windows 8
operating system, Windows 8.1, Windows Server 2012 operating system and
Windows Server 2012 R2 always set SMB2_GLOBAL_CAP_ENCRYPTION in the
**Capabilities** field if **IsEncryptionSupported** is TRUE.

[\<133\> Section 3.2.4.2.2.2](#Appendix_A_Target_133): Windows 10,
Windows 11 without
[\[MSKB-5036894\]](https://go.microsoft.com/fwlink/?linkid=2264227),
Windows 11 v22H2 without
[\[MSKB-5036980\]](https://go.microsoft.com/fwlink/?linkid=2264653),
Windows 11, version 23H2 without \[MSKB-5036980\], Windows Server 2016,
Windows Server 2022 without
[\[MSKB-5036909\]](https://go.microsoft.com/fwlink/?linkid=2264304) and
Windows Server 2022, 23H2 without
[\[MSKB-5036910\]](https://go.microsoft.com/fwlink/?linkid=2263465)
always set SMB2_GLOBAL_CAP_ENCRYPTION in the **Capabilities** field if
**IsEncryptionSupported** is TRUE.

[\<134\> Section 3.2.4.2.2.2](#Appendix_A_Target_134): Windows 10, and
Windows Server 2016 operating system and later use 32 bytes of Salt.

[\<135\> Section 3.2.4.2.2.2](#Appendix_A_Target_135): Windows 10 and
Windows Server 2016 through Windows Server v20H2 initialize with
AES-128-GCM(0x0002), followed by AES-128-CCM(0x0001).

Windows 11 operating system and later and Windows Server 2022 operating
system and later initialize with AES-128-GCM(0x0002), followed by
AES-128-CCM(0x0001), followed by AES-256-GCM(0x0004), followed by
AES-256-CCM(0x0003).

[\<136\> Section 3.2.4.2.2.2](#Appendix_A_Target_136): Windows 10 v1903,
Windows 10 v1909, Windows Server v1903, and Windows Server v1909
operating systems initialize with LZ77(0x0002) followed by
LZ77+Huffman(0x0003) followed by LZNT1(0x0001).

Windows 10 v2004 through Windows 11, version 23H2 and Windows Server
v2004 through Windows Server 2022, 23H2 initialize with
Pattern_V1(0x0004), followed by LZ77(0x0002), followed by
LZ77+Huffman(0x0003), followed by LZNT1(0x0001).

Windows 11, version 24H2 and later and Windows Server 2025 and later
initialize with Pattern_V1(0x0004), followed by LZ77(0x0002), followed
by LZ77+Huffman(0x0003), followed by LZNT1(0x0001), followed by
LZ4(0x0005).

[\<137\> Section 3.2.4.2.2.2](#Appendix_A_Target_137): Windows 11
operating system and later and Windows Server 2022 operating system and
later set **RDMATransformIds** to SMB2_RDMA_TRANSFORM_ENCRYPTION
(0x0001) and SMB2_RDMA_TRANSFORM_SIGNING (0x0002).

[\<138\> Section 3.2.4.2.2.2](#Appendix_A_Target_138): Windows 10 v1809
and prior and Windows Server v1809 and prior do not support
SMB2_NETNAME_NEGOTIATE_CONTEXT_ID.

[\<139\> Section 3.2.4.2.2.2](#Appendix_A_Target_139): Windows 11
operating system and later and Windows Server 2022 operating system and
later initialize with AES-GMAC(0x0002), followed by AES-CMAC(0x0001),
followed by HMAC-SHA256(0x0000).

[\<140\> Section 3.2.4.2.3](#Appendix_A_Target_140): Windows-based
clients implement the first option that is specified.

[\<141\> Section 3.2.4.2.3](#Appendix_A_Target_141): All the GSS-API
tokens used by Windows SMB2 clients are up to 4Kbytes in size. SMB2
servers always instruct the GSS_API server to expect the
*GSS_C_FRAGMENT_TO_FIT*.

[\<142\> Section 3.2.4.2.3.1](#Appendix_A_Target_142): Windows-based
clients implement the first option that is specified.

[\<143\> Section 3.2.4.2.3.1](#Appendix_A_Target_143): All the GSS-API
tokens used by Windows SMB2 clients are up to 4Kbytes in size. SMB2
servers always instruct the GSS_API server to expect the
*GSS_C_FRAGMENT_TO_FIT*.

[\<144\> Section 3.2.4.2.4](#Appendix_A_Target_144): Windows 11 v22H2
without
[\[MSKB-5037853\]](https://go.microsoft.com/fwlink/?linkid=2270126),
Windows 11, version 23H2 without \[MSKB-5037853\] and Windows Server
2022, 23H2 without
[\[MSKB-5037781\]](https://go.microsoft.com/fwlink/?linkid=2267687) set
SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER bit in the **Flags** field of
SMB2 TREE_CONNECT request if the share previously connected includes
either SMB2_SHAREFLAG_ISOLATED_TRANSPORT flag or
SMB2_SHARE_CAP_ASYMMETRIC capability.

[\<145\> Section 3.2.4.3](#Appendix_A_Target_145): Windows clients set
**File.LeaseKey** to a newly generated GUID as specified in
[\[MS-DTYP\]](%5bMS-DTYP%5d.pdf#Section_cca2742956894a16b2b49325d93e4ba2)
section 2.3.4.2.

[\<146\> Section 3.2.4.3](#Appendix_A_Target_146): On Windows 7
operating system and Windows Server 2008 R2, a 128-bit **ClientLeaseId**
is generated by an arithmetic combination of **LeaseKey** and
**ClientGuid**, which is passed to the object store at open/create time.
On Windows 8 operating system and later and Windows Server 2012
operating system and later, the **LeaseKey** in the request is used as
the **ClientLeaseId**.

[\<147\> Section 3.2.4.3](#Appendix_A_Target_147): Although not
required, failure to include the lease context can result in a lease
break.

[\<148\> Section 3.2.4.3](#Appendix_A_Target_148): On Windows 8, Windows
Server 2012, Windows 8.1, and Windows Server 2012 R2, the
**Lease.ClientLeaseId** and **Lease.ParentLeaseKey** are passed to the
object store in the form of **TargetOplockKey** and **ParentOplockKey**.
A new or existing lease is thereby associated with the resulting open.

To acquire or promote the lease as dictated by the
SMB2_CREATE_REQUEST_LEASE_V2 Create Context, a subsequent object store
call is invoked as described in. \[MS-FSA\] section 2.1.5.18 Server
Requests an Oplock. The *Open* parameter passed is the Open result from
the above operation, and the Type parameter is LEVEL_GRANULAR to
indicate a Lease request. The **RequestedOplockLevel** field is
constructed to include zero or more bits as follows.

| Object Store RequestedOplockLevel bit to be set | SMB2 Lease.LeaseState bit requested |
|----|----|
| READ_CACHING | SMB2_LEASE_READ_CACHING |
| WRITE_CACHING | SMB2_LEASE_WRITE_CACHING |
| HANDLE_CACHING | SMB2_LEASE_HANDLE_CACHING |

The Status code returned indicates whether the requested lease was
granted.

[\<149\> Section 3.2.4.3](#Appendix_A_Target_149): Windows clients set
**File.LeaseKey** to a newly generated GUID as specified in \[MS-DTYP\]
section 2.3.4.2.

[\<150\> Section 3.2.4.3](#Appendix_A_Target_150): Microsoft Windows
lease-aware clients always include SMB2_OPLOCK_LEVEL_LEASE if the open
can potentially cause a lease break.

[\<151\> Section 3.2.4.3](#Appendix_A_Target_151): Windows-based clients
will request a batch oplock for file creates when application does not
provide a requested oplock level, or an exclusive oplock is specified,
or a lease is requested.

[\<152\> Section 3.2.4.3.5](#Appendix_A_Target_152): Windows 8 operating
system and later and Windows Server 2012 operating system and later
clients set this to zero.

[\<153\> Section 3.2.4.3.8](#Appendix_A_Target_153): A Windows client
application requestsSMB2_LEASE_READ_CACHING and
SMB2_LEASE_HANDLE_CACHING when a file is opened for read access. In
addition, a Windows client application requests SMB2_LEASE_WRITE_CACHING
if the file is being opened for write access.

[\<154\> Section 3.2.4.6](#Appendix_A_Target_154): Windows-based clients
set **MinimumCount** field to 0.

[\<155\> Section 3.2.4.6](#Appendix_A_Target_155): Windows-based clients
will try to send multiple read commands at the same time, starting at
the lowest offset and working to the highest.

[\<156\> Section 3.2.4.6](#Appendix_A_Target_156): Windows-based clients
default to 4 KB.

[\<157\> Section 3.2.4.7](#Appendix_A_Target_157): Windows-based clients
set the **DataOffset** field to 0x70, which indicates that the payload
is always placed at the beginning of the **Buffer** field.

[\<158\> Section 3.2.4.7](#Appendix_A_Target_158): Windows-based clients
will try to send multiple write commands at the same time, starting at
the lowest offset and working to the highest.

[\<159\> Section 3.2.4.7](#Appendix_A_Target_159): Windows-based clients
default to 4 KB.

[\<160\> Section 3.2.4.8](#Appendix_A_Target_160): Windows clients set
this value to the offset from the start of the SMB2 header to the
beginning of the **Buffer** field.

[\<161\> Section 3.2.4.9](#Appendix_A_Target_161): In a SET_INFO request
where **FileInfoClass** is set to FileRenameInformation, Windows Vista
SP1, Windows Server 2008, Windows 7, and Windows Server 2008 R2 clients
append up to 4 additional padding bytes set to arbitrary values.

[\<162\> Section 3.2.4.10](#Appendix_A_Target_162): Windows clients set
this value to the offset from the start of the SMB2 header to the
beginning of the **Buffer** field.

[\<163\> Section 3.2.4.12](#Appendix_A_Target_163): Windows clients set
this value to the offset from the start of the SMB2 header to the
beginning of the **Buffer** field.

[\<164\> Section 3.2.4.14](#Appendix_A_Target_164): Windows-based
clients will set **StartSidLength** and **StartSidOffset** to any value.

[\<165\> Section 3.2.4.17](#Appendix_A_Target_165): The Windows SMB2
server implementation closes and reopens the directory handle in order
to "reset" the enumeration state. So any outstanding operations on the
directory handle will be failed with a STATUS_FILE_CLOSED error.

[\<166\> Section 3.2.4.20](#Appendix_A_Target_166): Windows 7 and
Windows Server 2008 R2 SMB2 clients set **CreditCharge** to 1 for IOCTL
requests.

[\<167\> Section 3.2.4.20.2.1](#Appendix_A_Target_167): Windows clients
set this field to **InputOffset** + **InputCount**, rounded up to a
multiple of 8 bytes.

[\<168\> Section 3.2.4.20.2.2](#Appendix_A_Target_168): Windows
applications use FSCTL_SRV_COPYCHUNK if the target file handle has
FILE_READ_DATA access. Otherwise, they use the
FSCTL_SRV_COPYCHUNK_WRITE.

[\<169\> Section 3.2.4.20.2.2](#Appendix_A_Target_169): Windows clients
set the **OutputOffset** field to **InputOffset** + **InputCount**,
rounded up to a multiple of 8 bytes.

[\<170\> Section 3.2.4.20.3](#Appendix_A_Target_170): Windows clients
set the **OutputOffset** field to **InputOffset** + **InputCount**,
rounded up to a multiple of 8 bytes.

[\<171\> Section 3.2.4.20.4](#Appendix_A_Target_171): Windows clients
set the **OutputOffset** field to **InputOffset** + **InputCount**,
rounded up to a multiple of 8 bytes.

[\<172\> Section 3.2.4.20.5](#Appendix_A_Target_172): Windows clients
set the **OutputOffset** field to **InputOffset** + **InputCount**,
rounded up to a multiple of 8 bytes.

[\<173\> Section 3.2.4.20.6](#Appendix_A_Target_173): Windows-based SMB2
servers pass File System Control requests through to the [**local object
store**](#gt_e8cc17be-a4d2-4bde-aa8a-08935e47255e) but do not support
I/O Control requests and fail such requests with STATUS_NOT_SUPPORTED.

[\<174\> Section 3.2.4.20.6](#Appendix_A_Target_174): Windows clients
set the **OutputOffset** field to **InputOffset** + **InputCount**,
rounded up to a multiple of 8 bytes.

[\<175\> Section 3.2.4.20.7](#Appendix_A_Target_175): Windows clients
set the **OutputOffset** field to the sum of the values of the
**InputOffset** and the **InputCount** fields, rounded up to a multiple
of 8 bytes.

[\<176\> Section 3.2.4.20.8](#Appendix_A_Target_176): Windows clients
set the **OutputOffset** field to **InputOffset** + **InputCount**,
rounded up to a multiple of 8 bytes.

[\<177\> Section 3.2.4.20.10](#Appendix_A_Target_177): Windows clients
set this to 64 kilobytes.

[\<178\> Section 3.2.4.20.11](#Appendix_A_Target_178): Windows clients
set the **OutputOffset** field to **InputOffset**.

[\<179\> Section 3.2.4.24](#Appendix_A_Target_179): Windows based
clients set the **MessageId** field to 0, when the **AsyncId** field is
set to an asynchronous identifier of the request.

[\<180\> Section 3.2.5.1](#Appendix_A_Target_180): For the following
error codes, Windows-based clients will retry the operation up to three
times and then retry the operation every 5 seconds until the count of
milliseconds specified by **Open.ResilientTimeout** is exceeded:

- STATUS_SERVER_UNAVAILABLE

- STATUS_FILE_NOT_AVAILABLE

- STATUS_SHARE_UNAVAILABLE

[\<181\> Section 3.2.5.1.1.1](#Appendix_A_Target_181): Windows-based
clients discard the message if it is encrypted and the connection is
NetBIOS over TCP.

[\<182\> Section 3.2.5.1.1.1](#Appendix_A_Target_182): Windows 8.1 and
Windows Server 2012 R2 continue to process the entire compound response
if SMB2_FLAGS_RELATED_OPERATIONS is set in the Flags field of the SMB2
header of the response.

[\<183\> Section 3.2.5.1.1.2](#Appendix_A_Target_183): Windows-based
clients discard the message if it is compressed and the connection is
over RDMA.

[\<184\> Section 3.2.5.1.5](#Appendix_A_Target_184): Windows clients
extend the Request Expiration Timer for requests being processed
asynchronously as follows:

If the registry value ExtendedSessTimeout in
HKLM\System\CurrentControlSet\Services\LanmanWorkStation\Parameters\\ is
set, the clients use the same value. Otherwise, the clients extend the
expiration time to four times the value of default session timeout.

Windows Vista SP1, Windows Server 2008, Windows 7 and Windows Server
2008 R2 never enforce a timeout on SMB2 CHANGE_NOTIFY requests, SMB2
LOCK requests without the SMB2_LOCKFLAG_FAIL_IMMEDIATELY flag, SMB2 READ
requests on named pipes, SMB2 WRITE requests on named pipes, and the
FSCTL_PIPE_PEEK, FSCTL_PIPE_TRANSCEIVE and FSCTL_PIPE_WAIT named pipe
FSCTLs.

[\<185\> Section 3.2.5.1.7](#Appendix_A_Target_185): Windows-based
clients will not disconnect the
[**connection**](#gt_866b0055-ceba-4acf-a692-98452943b981), but will
simply fail the request.

[\<186\> Section 3.2.5.1.8](#Appendix_A_Target_186): Windows-based SMB 2
Protocol clients do not check the validity of the command in the
response.

[\<187\> Section 3.2.5.1.9](#Appendix_A_Target_187): Windows-based
clients ignore 8-byte alignment boundary checking in a compounded chain.

[\<188\> Section 3.2.5.2](#Appendix_A_Target_188): Windows-based clients
will not use the **MaxTransactSize** and will use the **ServerGuid** to
determine if the client and server are the same machine.

[\<189\> Section 3.2.5.2](#Appendix_A_Target_189): Windows Vista SP1,
Windows Server 2008, Windows 7, Windows Server 2008 R2, Windows 8,
Windows Server 2012, Windows 8.1, and Windows Server 2012 R2 disconnect
the connection if **MaxTransactSize**, **MaxReadSize**, or
**MaxWriteSize** is less than 4096.

[\<190\> Section 3.2.5.2](#Appendix_A_Target_190): Windows 10 v1903
through Windows 10 v20H2 and Windows Server v1903 through Windows Server
v20H2 will disconnect the connection.

[\<191\> Section 3.2.5.3.3](#Appendix_A_Target_191): Windows 8, Windows
8.1, Windows Server 2012, and Windows Server 2012 R2 operating system do
not perform this verification.

[\<192\> Section 3.2.5.5](#Appendix_A_Target_192): Windows 10 v1507
operating system through Windows 10 v1909, Windows Server 2016 operating
system and later set **Dialects** array to all the dialects the client
implements.

[\<193\> Section 3.2.5.7](#Appendix_A_Target_193): Windows 8 operating
system and later and Windows Server 2012 operating system and later
replay the create operation up to three times or until all channels in
the session are disconnected.

[\<194\> Section 3.2.5.12](#Appendix_A_Target_194): Windows 8 operating
system and later and Windows Server 2012 operating system and later
replay the write operation up to three times or until all channels in
the session are disconnected.

[\<195\> Section 3.2.5.14](#Appendix_A_Target_195): Windows 8 operating
system and later and Windows Server 2012 operating system and later
replay the IOCTL operation up to three times or until all of the
channels in the session are disconnected.

[\<196\> Section 3.2.5.14](#Appendix_A_Target_196): If the
**OutputCount** field in an [SMB2 IOCTL
Response](#Section_f70eccb6e1be4db89c479ac86ef18dbb) is 0 and the
**OutputOffset** exceeds the size of the SMB2 response, Windows clients
will return STATUS_INVALID_NETWORK_RESPONSE to the application.

[\<197\> Section 3.2.5.14.9](#Appendix_A_Target_197): Windows clients
enable TCP keepalives to detect broken connections.

[\<198\> Section 3.2.5.14.11](#Appendix_A_Target_198): Windows-based
SMB2 clients will choose the interfaces using the following criteria:

1.  Skip the interfaces in NETWORK_INTERFACE_INFO Response where
    **IfIndex** is 0.

2.  For each interface returned in NETWORK_INTERFACE_INFO Response, if
    the interface has both link-local and non-link-local IP addresses,
    skip the link-local IP address.

3.  If there is one or more multiple link-local addresses (suppose there
    are Y such interfaces), select local interfaces which have only
    link-local addresses (suppose there are X such local interfaces).

4.  Build a destination address list, include all server non-link-local
    addresses and X\*Y server link-local addresses.

5.  For each RDMA capable address pair, duplicate the address pair, one
    for RDMA and one for Direct TCP.

6.  Sort address pairs by which address pair is best suited for
    connection between client and server.

7.  For each address pair, compute

    - Link speed of the pair = min( link speed of local interface, link
      speed of remote interface)

    - RSS capable = RSS capable of local interface and RSS capable of
      remote interface

8.  If there are RDMA capable address pairs, select them.

    - Otherwise if there are RSS capable address pairs, select them.

    - Otherwise select remaining address pairs.

9.  Select the pairs with the highest link speed from the selected
    address pairs.

10. Select local/remote address pairs so that all eligible local/remote
    interfaces are used and the connections are distributed among local
    and remote interfaces.

11. By default, Windows clients create four connections per RSS-capable
    address pair or two connections per RDMA-capable address pair or
    only a single connection when the address pair is neither
    RSS-capable nor RDMA-capable.

[\<199\> Section 3.2.5.14.11](#Appendix_A_Target_199): By default,
Windows 8 and later will try to establish alternate channels if
**Connection.OutstandingRequests** exceeds 8. By default, Windows Server
2012 operating system and later will try to establish alternate channels
if **Connection.OutstandingRequests** exceeds 1.

[\<200\> Section 3.2.5.16](#Appendix_A_Target_200): Windows SMB2 clients
without
[\[MSFT-CVE-2025-29956\]](https://go.microsoft.com/fwlink/?linkid=2341306)
do not perform this validation.

[\<201\> Section 3.2.5.18](#Appendix_A_Target_201): Windows 8 operating
system and later and Windows Server 2012 operating system and later
replay the SetInfo operation up to three times or until all of the
channels in the session are disconnected.

[\<202\> Section 3.2.5.19.2](#Appendix_A_Target_202): Windows clients do
not send a Lease Break Acknowledgement when they have an outstanding
SMB2 CREATE Request on the same **File**.

[\<203\> Section 3.2.6.1](#Appendix_A_Target_203): Windows clients use a
default time-out of 60 seconds.

[\<204\> Section 3.2.6.1](#Appendix_A_Target_204): Windows-based clients
return a STATUS_CONNECTION_DISCONNECTED error code to the calling
application.

[\<205\> Section 3.2.6.1](#Appendix_A_Target_205): The Windows-based
clients will disconnect the connection.

[\<206\> Section 3.2.7.1](#Appendix_A_Target_206): When the
reestablishment of the durable handle fails with a network error,
Windows clients retry the reestablishment three times.

[\<207\> Section 3.3.1.1](#Appendix_A_Target_207): Windows-based servers
will limit the maximum range of [**sequence
numbers**](#gt_9c2d7dfc-4958-48b1-bbab-f23e97e71ff3). If a client has
been granted 10 credits, the server will not allow the difference
between the smallest available sequence number and the largest available
sequence number to exceed 2\*10 = 20. Therefore, if the client has
sequence number 10 available and does not send it, the server will stop
granting credits as the client nears sequence number 30, and eventually
will grant no further credits until the client sends sequence number 10.

[\<208\> Section 3.3.1.2](#Appendix_A_Target_208): A Windows-based
server will grant some portion of the client request based on available
resources and the number of credits the client is currently taking
advantage of. A Windows–based server grants credits based on usage but
will attempt to enforce fairness if there are insufficient credits.

[\<209\> Section 3.3.1.2](#Appendix_A_Target_209): Windows-based SMB2
servers support a configurable minimum credit limit below which the
client is unconditionally granted all credits it requests, and a
configurable maximum credit limit above which credits are never granted,
as follows:

| SMB2 server | Default minimum | Default maximum |
|----|----|----|
| Windows Vista SP1, Windows 7, Windows 8, Windows 8.1, Windows 10, and Windows 11 | 128 | 2048 |
| Windows Server 2008, Windows Server 2008 R2, Windows Server 2012, Windows Server 2012 R2, Windows Server 2016, Windows Server operating system, Windows Server 2019 and Windows Server 2022 | 512 | 8192 |

[\<210\> Section 3.3.1.2](#Appendix_A_Target_210): A Windows–based
server does not currently scale credits based on quality of service
features.

[\<211\> Section 3.3.1.4](#Appendix_A_Target_211): On Windows 7 and
Windows Server 2008 R2, a 128-bit **ClientLeaseId** is generated by an
arithmetic combination of **LeaseKey** and **ClientGuid**, which is
passed to the object store at open/create time. On Windows 8 operating
system and later and Windows Server 2012 operating system and later, the
**LeaseKey** in the request is used as the **ClientLeaseId**.

[\<212\> Section 3.3.1.4](#Appendix_A_Target_212): Windows 7 operating
system and later and Windows Server 2008 R2 operating system and later
based SMB2 servers support only the levels described above, and Windows
7 operating system and later and Windows Server 2008 R2 operating system
and later based SMB2 clients request only those levels.

[\<213\> Section 3.3.1.6](#Appendix_A_Target_213): Windows-based servers
allow the sharing of both printers and traditional file shares.

[\<214\> Section 3.3.1.6](#Appendix_A_Target_214): In Windows, this
abstract state element contains the security descriptor for the share.

[\<215\> Section 3.3.1.6](#Appendix_A_Target_215): Windows-based SMB2
clients do not cache directory enumeration results.

[\<216\> Section 3.3.1.13](#Appendix_A_Target_216): The Windows SMB2
server allocates an I/O request (IRP) structure which it uses to locally
request action from the object store. The **Request.CancelRequestId** is
set to the unique address of this structure.

[\<217\> Section 3.3.2.1](#Appendix_A_Target_217): Windows SMB2 servers
set this timer to 35 seconds.

[\<218\> Section 3.3.2.2](#Appendix_A_Target_218): Windows-based SMB2
servers set this timer to a constant value of 16 minutes.

[\<219\> Section 3.3.2.3](#Appendix_A_Target_219): Windows-based servers
implement this timer with a constant value of 45 seconds.

[\<220\> Section 3.3.2.5](#Appendix_A_Target_220): Windows SMB2 servers
set this timer to 35 seconds.

[\<221\> Section 3.3.3](#Appendix_A_Target_221): Windows Vista SP1,
Windows Server 2008, Windows 7, Windows Server 2008 R2, Windows 8,
Windows Server 2012, Windows 8.1, Windows Server 2012 R2, Windows 10
v1507 through Windows 10 v1703, and Windows Server 2016 set the
**ServerStartTime** to the time at which the SMB2 server was started.

[\<222\> Section 3.3.3](#Appendix_A_Target_222): Windows-based SMB2
servers set this value to 256.

[\<223\> Section 3.3.3](#Appendix_A_Target_223): Windows-based SMB2
servers set this value to 1 MB.

[\<224\> Section 3.3.3](#Appendix_A_Target_224): Windows-based SMB2
servers set this value to 16 MB.

[\<225\> Section 3.3.3](#Appendix_A_Target_225): Windows-based servers
initialize **ServerHashLevel** based on a stored value in the registry.

[\<226\> Section 3.3.3](#Appendix_A_Target_226): Windows 7 operating
system and later and Windows Server 2008 R2 operating system and later
SMB2 servers provide a constant maximum resiliency time-out of 300000
milliseconds.

[\<227\> Section 3.3.3](#Appendix_A_Target_227): Windows 8 operating
system and later and Windows Server 2012 operating system and later by
default, set **RejectUnencryptedAccess** to TRUE. If the registry value
**RejectUnencryptedAccess** under
HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\\ is set
to zero, **RejectUnencryptedAccess** is set to FALSE.

[\<228\> Section 3.3.3](#Appendix_A_Target_228): Windows 8 operating
system and later and Windows Server 2012 operating system and later set
**IsMultiChannelCapable** to TRUE.

[\<229\> Section 3.3.3](#Appendix_A_Target_229): Windows 8 operating
system and later and Windows Server 2012 operating system and later
initialize **AllowAnonymousAccess** based on a stored value in the
registry.

[\<230\> Section 3.3.3](#Appendix_A_Target_230): Windows 10 v1709,
Windows Server operating system operating system and later set this
value to TRUE.

[\<231\> Section 3.3.3](#Appendix_A_Target_231): By default, Windows 11
operating system and later and Windows Server 2022 operating system and
later set **AllowNamedPipeAccessOverQUIC** to FALSE.

[\<232\> Section 3.3.3](#Appendix_A_Target_232): Windows 11 with
\[MSKB-5035854\], Windows 11 v22H2 with \[MSKB-5035942\], Windows Server
2022 with \[MSKB-5035857\], Windows Server 2022, 23H2, Windows 11,
version 24H2 and later, and Windows Server 2025 and later set
**IsMutualAuthOverQUICSupported** to TRUE.

Windows 11 with \[MSKB-5035854\], Windows 11 v22H2 with
\[MSKB-5035942\], Windows Server 2022 with \[MSKB-5035857\], Windows
Server 2022, 23H2 with
[\[MSKB-5035856\]](https://go.microsoft.com/fwlink/?linkid=2261319),
Windows 11, version 24H2 and later, and Windows Server 2025 and later
support Client Access Control capability over QUIC.

[\<233\> Section 3.3.4.1.1](#Appendix_A_Target_233): Windows-based
servers always sign the final session setup response when the user is
neither anonymous nor guest.

Windows 8, Windows Server 2012, Windows 8.1 without
[\[MSKB-2976995\]](https://go.microsoft.com/fwlink/?LinkId=509960) and
Windows Server 2012 R2 without \[MSKB-2976995\] servers fail to sign
responses other than SMB2_NEGOTIATE, SMB2_SESSION_SETUP, and
SMB2_TREE_CONNECT when **Session.SigningRequired** is TRUE, global
**EncryptData** is TRUE, **RejectUnencryptedAccess** is FALSE and either
**Connection.Dialect** is "2.0.2" or "2.1" or
**Connection.ClientCapabilities** does not include
SMB2_GLOBAL_CAP_ENCRYPTION.

[\<234\> Section 3.3.4.1.2](#Appendix_A_Target_234): For an
asynchronously processed request, Windows-based servers grant credits on
the interim response and do not grant credits on the final response. The
interim response grants credits to keep the transaction from stalling in
case the client is out of credits.

[\<235\> Section 3.3.4.1.3](#Appendix_A_Target_235): The Windows-based
server compounds responses for any received compounded operations.
Otherwise, it does not compound responses.

[\<236\> Section 3.3.4.1.3](#Appendix_A_Target_236): When there are not
enough credits to process a subsequent compounded request, Windows SMB2
servers set the **NextCommand** field to the size of the last SMB2
response message including the SMB2 header.

[\<237\> Section 3.3.4.1.3](#Appendix_A_Target_237): Windows-based
servers grant all credits in the final response of the compounded chain,
and grant 0 credits in all responses other than the final response.

[\<238\> Section 3.3.4.1.3](#Appendix_A_Target_238): Windows-based
servers do not calculate the size of the response message; servers
depend on the transport to send the response message.

[\<239\> Section 3.3.4.1.5](#Appendix_A_Target_239): Windows 10 v2004,
Windows 10 v20H2, Windows Server v2004, and Windows Server v20H2 do not
compress the message if **Connection.CompressionIds** does not include
LZNT1, LZ77 and LZ77+Huffman algorithms.

[\<240\> Section 3.3.4.2](#Appendix_A_Target_240): Windows-based servers
send interim responses for the following operations if they cannot be
completed immediately:

- [SMB2_CREATE](#Section_e8fb45c1a03d44cab7ae47385cfd7997), if the
  underlying object store indicates an Oplock/Lease Break Notification
  or if access/sharing modes are incompatible with another existing open

- [SMB2_CHANGE_NOTIFY](#Section_598f395ae7a24cc8afb3ccb30dd2df7c)

- Byte Range Lock

- Named Pipe Read on a blocking named pipe

- Named Pipe Write on a blocking named pipe

- Large file write

- FSCTL_PIPE_TRANSCEIVE

- FSCTL_SRV_COPYCHUNK or FSCTL_SRV_COPYCHUNK_WRITE, when oplock break
  happens

- [SMB2 FLUSH](#Section_e494678bb1fc44a0b86e8195acf74ad7) on a named
  pipe

- FSCTL_GET_DFS_REFERRALS

[\<241\> Section 3.3.4.2](#Appendix_A_Target_241): Windows-based servers
incorrectly process the FSCTL_PIPE_WAIT request on named pipes
synchronously.

[\<242\> Section 3.3.4.2](#Appendix_A_Target_242): Windows-based servers
enforce a configurable blocking operation credit, which defaults to 64
on Windows Vista SP1 operating system and later, and defaults to 512 on
Windows Server 2008 operating system and later.

[\<243\> Section 3.3.4.4](#Appendix_A_Target_243): For Windows 7
operating system and later and Windows Server 2008 R2 operating system
and later, STATUS_BUFFER_OVERFLOW will be returned for
FSCTL_GET_RETRIEVAL_POINTERS and FSCTL_GET_REPARSE_POINT, along with the
ones mentioned in section
[3.3.4.4](#Section_41295064be3f41dc9aa5f68545f945f0).

[\<244\> Section 3.3.4.6](#Appendix_A_Target_244): In Windows-based SMB2
servers, underlying object store never breaks opportunistic lock to
SMB2_OPLOCK_LEVEL_EXCLUSIVE oplock level.

[\<245\> Section 3.3.4.6](#Appendix_A_Target_245): Windows Vista SP1,
Windows Server 2008, Windows 7, Windows Server 2008 R2, Windows 8,
Windows Server 2012, Windows 8.1, and Windows Server 2012 R2 set the
SessionId in the SMB2 header to zero.

[\<246\> Section 3.3.4.6](#Appendix_A_Target_246): Windows-based SMB2
servers set **Open.OplockTimeout** to the current time plus 35000
milliseconds. If **Open.IsPersistent** is TRUE, **Open.OplockTimeout**
is set to the current time plus 60000 milliseconds.

[\<247\> Section 3.3.4.7](#Appendix_A_Target_247): Windows-based SMB2
servers set **Lease.LeaseBreakTimeout** to the current time plus 35000
milliseconds. If **Open.IsPersistent** is TRUE, Windows 8 and Windows
Server 2012 set **Lease.LeaseBreakTimeout** to the current time plus
60000 milliseconds. If **Open.IsPersistent** is TRUE, Windows 8.1
operating system and later and Windows Server 2012 R2 operating system
and later set **Lease.LeaseBreakTimeout** to the current time plus
180000 milliseconds.

[\<248\> Section 3.3.4.7](#Appendix_A_Target_248): Windows 8 through
Windows 10 v1909, Windows Server 2012 through Windows Server v1909,
Windows 10 v2004 through Windows 10, version 22H2 operating system
without
[\[MSKB-5037849\]](https://go.microsoft.com/fwlink/?linkid=2270125),
Windows Server v2004 through Windows Server v20H2 without
\[MSKB-5037849\], Windows 11 without
[\[MSKB-5039213\]](https://go.microsoft.com/fwlink/?linkid=2271958),
Windows 11 v22H2 without \[MSKB-5037853\], Windows 11, version 23H2
without \[MSKB-5037853\], Windows 11, version 24H2 without
[\[MSKB-5040529\]](https://go.microsoft.com/fwlink/?linkid=2277306),
Windows Server 2022 without
[\[MSKB-5039227\]](https://go.microsoft.com/fwlink/?linkid=2271959) and
Windows Server 2022, 23H2 without
[\[MSKB-5039236\]](https://go.microsoft.com/fwlink/?linkid=2272069) and
later do not increment **Lease.Epoch** when setting **NewEpoch** in
Lease Break Notification in the following cases:

- On the server initiated close of an open which is the last open in
  **Open.Lease.LeaseOpens**, the server sends a Lease Break Notification
  to break the lease by setting **NewLeaseState** to SMB2_LEASE_NONE and
  **Status** field in the SMB2 Header to STATUS_FILE_CLOSED.

- While handling a Lease Break Acknowledgment, due to a conflicting
  open, if the object store does not grant WRITE_CACHING or
  HANDLE_CACHING, as specified in \[MS-FSA\] section 2.1.5.19, the
  server sends another Lease Break Notification to further downgrade the
  lease state.

[\<249\> Section 3.3.4.13](#Appendix_A_Target_249): Windows Server 2012
and Windows Server 2012 R2 set these bits as appropriate for shared
volume configurations.

[\<250\> Section 3.3.4.13](#Appendix_A_Target_250): By default, Windows
8 operating system and later and Windows Server 2012 operating system
and later set **Share.CATimeout** to zero.

[\<251\> Section 3.3.4.17](#Appendix_A_Target_251): Windows Lease break
is described in \[MS-FSA\] section 2.1.5.18. The *Open* parameter passed
is the **Open.Local** value from the current close operation, the *Type*
parameter is LEVEL_GRANULAR to indicate a Lease request, and the
*RequestedOplockLevel* parameter is zero.

Windows servers never send SMB2 Lease Break Notification to the client
when the **Open** is being closed.

[\<252\> Section 3.3.4.21](#Appendix_A_Target_252): For each supported
transport type as listed in section
[2.1](#Section_1dfacde4b5c744948a14a09d3ab4cc83), the Windows SMB2
server attempts to form an association with the specified device with
local calls specific to each supported transport type and rejects the
entry if none of the associations succeed.

[\<253\> Section 3.3.4.21](#Appendix_A_Target_253): On Windows,
**ServerName** is used only when the transport is
[**NetBIOS**](#gt_b86c44e6-57df-4c48-8163-5e3fa7bdcff4) over TCP.

[\<254\> Section 3.3.5.1](#Appendix_A_Target_254): Possible
Windows-specific values for **Connection.TransportName** are listed in a
product behavior note attached to
[\[MS-SRVS\]](%5bMS-SRVS%5d.pdf#Section_accf23b00f57441c918543041f1b0ee9)
section 2.2.4.96.

[\<255\> Section 3.3.5.2](#Appendix_A_Target_255): Windows performs
cancellation of in-progress requests via the interface in \[MS-FSA\]
section 2.1.5.20, Server Requests Canceling an Operation, passing
**Request.CancelRequestId** as an input parameter.

[\<256\> Section 3.3.5.2](#Appendix_A_Target_256): Windows 10 v1903 and
later, and Windows Server v1903 and later set this to TRUE.

[\<257\> Section 3.3.5.2](#Appendix_A_Target_257): Windows 7 without
[\[MSKB-2536275\]](https://go.microsoft.com/fwlink/?LinkId=294564), and
Windows Server 2008 R2 without \[MSKB-2536275\] terminate the connection
when the size of the request is greater than 64\*1024 bytes.

Windows Vista SP1 and Windows Server 2008 on Direct TCP transport
disconnect the connection if the size of the message exceeds 128\*1024
bytes, and Windows Vista SP1 and Windows Server 2008 on NetBIOS over TCP
transport will disconnect the connection if the size of the message
exceeds 64\*1024 bytes.

[\<258\> Section 3.3.5.2.1.1](#Appendix_A_Target_258): Windows-based
servers will discard the message if it is encrypted and the connection
is NetBIOS over TCP.

[\<259\> Section 3.3.5.2.1.1](#Appendix_A_Target_259): Windows-based
servers will not disconnect the connection.

[\<260\> Section 3.3.5.2.1.1](#Appendix_A_Target_260): Windows 8,
Windows Server 2012, Windows 8.1, and Windows Server 2012 R2 disconnect
the connection if **OriginalMessageSize** is greater than 1028
kilobytes.

[\<261\> Section 3.3.5.2.1.2](#Appendix_A_Target_261): Windows-based
servers discard the message if it is compressed and the connection is
over RDMA.

[\<262\> Section 3.3.5.2.3](#Appendix_A_Target_262): For an SMB2 Write
request with an invalid **MessageId**, Windows 8 and Windows Server 2012
will stop processing the request and any further requests on that
connection.

[\<263\> Section 3.3.5.2.4](#Appendix_A_Target_263): Windows-based
servers will not disconnect the connection due to a mismatched
signature.

[\<264\> Section 3.3.5.2.4](#Appendix_A_Target_264): Windows-based
servers will not disconnect the connection due to an unsigned packet.

[\<265\> Section 3.3.5.2.6](#Appendix_A_Target_265): Windows-based
servers will disconnect the connection when it processes packets that
are smaller than the SMB2 header or packets that contain an invalid SMB2
command. For all other validations, it will not disconnect the
connection but simply return the error.

[\<266\> Section 3.3.5.2.7](#Appendix_A_Target_266): In Windows Vista
and later, and Windows Server 2008 and later, when an operation in a
compound request requires asynchronous processing, Windows-based servers
fail them with STATUS_INTERNAL_ERROR except for the following two cases:
when a create request in the compound request triggers an oplock break,
or when the operation is last in the compound request.

In all SMB2 servers, if a create request in a compound chain is
processed asynchronously due to an oplock break, Windows-based servers
send an interim response to the client. If there are one or more
conflicting create operations in a compounded request, Windows-based
servers send an oplock break notification for the completed create prior
to sending any response, and the level of the broken oplock is not
updated in all prior create responses in the compound response.

[\<267\> Section 3.3.5.2.7](#Appendix_A_Target_267): Windows-based
servers ignore 8-byte alignment boundary checking in a compounded chain.

[\<268\> Section 3.3.5.2.7](#Appendix_A_Target_268): Windows-based SMB2
servers allow a mix of related and unrelated compound requests in the
same transport send. Upon encountering a request with
SMB2_FLAGS_RELATED_OPERATIONS not set, a Windows-based SMB2 server
treats it as the start of a chain.

[\<269\> Section 3.3.5.2.7.2](#Appendix_A_Target_269): If
SMB2_FLAGS_RELATED_OPERATIONS is present in the first request,
Windows-based servers fail all related requests in the compounded chain
with error STATUS_INVALID_PARAMETER.

[\<270\> Section 3.3.5.2.7.2](#Appendix_A_Target_270): If the previous
session expired, Windows Vista SP1, Windows Server 2008, Windows 7, and
Windows Server 2008 R2 servers fail the next request in the compounded
chain with STATUS_NETWORK_SESSION_EXPIRED, and the subsequent requests
in the compounded chain will be failed with STATUS_INVALID_PARAMETER.

If the previous operation is QUERY_DIRECTORY, QUERY_INFO, SET_INFO,
READ, WRITE, LOCK or CHANGE_NOTIFY and the operation failed and
SMB2_FLAGS_RELATED_OPERATIONS is set on all subsequent operations,
Windows SMB2 servers fail current and all subsequent operations in the
compounded chain with STATUS_INVALID_PARAMETER.

[\<271\> Section 3.3.5.2.9](#Appendix_A_Target_271): Windows Vista SP1,
Windows Server 2008, Windows 7, and Windows Server 2008 R2 servers do
not fail the request if the SMB2 header of the request has
SMB2_FLAGS_SIGNED set in the **Flags** field and the request is not an
SMB2 LOCK request as specified in section
[2.2.26](#Section_6178b96048b64999b589669f88e9017d).

[\<272\> Section 3.3.5.2.9](#Appendix_A_Target_272): Windows-based
servers fail the request with 0x80090302 when the authentication method
is GSS-API.

[\<273\> Section 3.3.5.2.10](#Appendix_A_Target_273): Windows 8 and
Windows Server 2012 perform the following:

If **Open.OutstandingPreRequestCount** is equal to zero,

- Set **Open.ChannelSequence** to **ChannelSequence** in the SMB2
  Header.

- Increment **Open.OutstandingPreRequestCount** by
  **Open.OutstandingRequestCount**.

- Set **Open.OutstandingRequestCount** to 1.

Otherwise, fail the request with STATUS_FILE_NOT_AVAILABLE.

[\<274\> Section 3.3.5.3.1](#Appendix_A_Target_274): If the underlying
transport is NETBIOS over TCP, Windows-based servers set
**MaxTransactSize** to 65536. Otherwise, **MaxTransactSize** is set
based on the following table.

| Windows version\Connection.Dialect | MaxTransactSize |
|----|----|
| Windows 7\Windows Server 2008 R2 | 1048576 |
| Windows 8 without [\[MSKB-2934016\]](https://go.microsoft.com/fwlink/?LinkId=403955)\Windows Server 2012 without \[MSKB-2934016\] | 1048576 |
| All other SMB2 servers | 8388608 |

[\<275\> Section 3.3.5.3.1](#Appendix_A_Target_275): If the underlying
transport is NETBIOS over TCP, Windows-based servers set **MaxReadSize**
to 65536. Otherwise, **MaxReadSize** is set based on the following
table.

| Windows version\Connection.Dialect | MaxReadSize |
|----|----|
| Windows 7\Windows Server 2008 R2 | 1048576 |
| Windows 8 without \[MSKB-2934016\]\Windows Server 2012 without \[MSKB-2934016\] | 1048576 |
| All other SMB2 servers | 8388608 |

[\<276\> Section 3.3.5.3.1](#Appendix_A_Target_276): If the underlying
transport is NETBIOS over TCP, Windows-based servers set
**MaxWriteSize** to 65536. Otherwise, **MaxWriteSize** is based on the
following table.

| Windows version\Connection.Dialect | MaxWriteSize |
|----|----|
| Windows 7\Windows Server 2008 R2 | 1048576 |
| Windows 8 without \[MSKB-2934016\]\Windows Server 2012 without \[MSKB-2934016\] | 1048576 |
| All other SMB2 servers | 8388608 |

[\<277\> Section 3.3.5.3.1](#Appendix_A_Target_277): Windows Vista SP1,
Windows Server 2008, Windows 7, Windows Server 2008 R2, Windows 8,
Windows Server 2012, Windows 8.1, Windows Server 2012 R2, Windows 10
v1507 through Windows 10 v1703, and Windows Server 2016 set the
**ServerStartTime** to the global **ServerStartTime** value.

[\<278\> Section 3.3.5.3.2](#Appendix_A_Target_278): Windows-based
servers set this to a default value of 65536.

[\<279\> Section 3.3.5.3.2](#Appendix_A_Target_279): Windows-based
servers set **MaxReadSize** to a default value of 65536.

[\<280\> Section 3.3.5.3.2](#Appendix_A_Target_280): Windows-based
servers set **MaxWriteSize** to a default value of 65536.

[\<281\> Section 3.3.5.3.2](#Appendix_A_Target_281): Windows Vista SP1,
Windows Server 2008, Windows 7, Windows Server 2008 R2, Windows 8,
Windows Server 2012, Windows 8.1, Windows Server 2012 R2, Windows 10
v1507 through Windows 10 v1703, and Windows Server 2016 set the
**ServerStartTime** to the global **ServerStartTime** value.

[\<282\> Section 3.3.5.4](#Appendix_A_Target_282): Windows 10 v1903,
Windows 10 v1909, Windows Server v1903, and Windows Server v1909 only
set **CompressionAlgorithms** to the first common algorithm supported by
the client and server.

Windows 10 v2004 and Windows Server v2004 select a common pattern
scanning algorithm and the first common compression algorithm, specified
in section [2.2.3.1.3](#Section_78e0c942ab41472bb1174a95ebe88271),
supported by the client and server.

[\<283\> Section 3.3.5.4](#Appendix_A_Target_283): If the underlying
transport is NETBIOS over TCP, Windows-based servers set
**MaxTransactSize** to 65536. Otherwise, **MaxTransactSize** is set
based on the following table.

| Windows version\Connection.Dialect | 2.0.2 | All other SMB2 dialects |
|----|----|----|
| Windows Vista SP1\Windows Server 2008 | 65536 | N/A |
| Windows 7\Windows Server 2008 R2 | 65536 | 1048576 |
| Windows 8 without \[MSKB-2934016\]\Windows Server 2012 without \[MSKB-2934016\] | 65536 | 1048576 |
| All other SMB2 servers | 65536 | 8388608 |

[\<284\> Section 3.3.5.4](#Appendix_A_Target_284): If the underlying
transport is NETBIOS over TCP, Windows-based servers set **MaxReadSize**
to 65536. Otherwise, **MaxReadSize** is set based on the following
table.

| Windows version\Connection.Dialect | 2.0.2 | All other SMB2 dialects |
|----|----|----|
| Windows Vista SP1\Windows Server 2008 | 65536 | N/A |
| Windows 7\Windows Server 2008 R2 | 65536 | 1048576 |
| Windows 8 without \[MSKB-2934016\]\Windows Server 2012 without \[MSKB-2934016\] | 65536 | 1048576 |
| All other SMB2 servers | 65536 | 8388608 |

[\<285\> Section 3.3.5.4](#Appendix_A_Target_285): If the underlying
transport is NETBIOS over TCP, Windows-based servers set
**MaxWriteSize** to 65536. Otherwise, **MaxWriteSize** is set based on
the following table.

| Windows version\Connection.Dialect | 2.0.2 | All other SMB2 dialects |
|----|----|----|
| Windows Vista SP1\Windows Server 2008 | 65536 | N/A |
| Windows 7\Windows Server 2008 R2 | 65536 | 1048576 |
| Windows 8 without \[MSKB-2934016\]\Windows Server 2012 without \[MSKB-2934016\] | 65536 | 1048576 |
| All other SMB2 servers | 65536 | 8388608 |

[\<286\> Section 3.3.5.4](#Appendix_A_Target_286): Windows Vista SP1,
Windows Server 2008, Windows 7, Windows Server 2008 R2, Windows 8,
Windows Server 2012, Windows 8.1, Windows Server 2012 R2, Windows 10
v1507 through Windows 10 v1703, and Windows Server 2016 set the
**ServerStartTime** to the global **ServerStartTime** value.

[\<287\> Section 3.3.5.4](#Appendix_A_Target_287): Windows 10, and
Windows Server 2016 operating system and later use 32 bytes of Salt.

[\<288\> Section 3.3.5.4](#Appendix_A_Target_288): Windows 10 v2004,
Windows Server v2004, Windows 10 v20H2, Windows Server v20H2, and
Windows 10 v21H1 operating system operating systems without
[\[MSKB-5001391\]](https://go.microsoft.com/fwlink/?linkid=2172882) set
**CompressionAlgorithmCount** to 0.

[\<289\> Section 3.3.5.4](#Appendix_A_Target_289): Windows 10 v2004,
Windows Server v2004, Windows 10 v20H2, Windows Server v20H2, and
Windows 10 v21H1 operating systems without \[MSKB-5001391\] set
**CompressionAlgorithms** to empty.

[\<290\> Section 3.3.5.5](#Appendix_A_Target_290): Windows 8 and Windows
Server 2012 look up the session in **GlobalSessionTable** using the
**SessionId** from the SMB2 header if the SMB2_SESSION_FLAG_BINDING bit
is set in the **Flags** field of the request. If the session is found,
the server fails the request with STATUS_REQUEST_NOT_ACCEPTED. If the
session is not found, the server fails the request with
STATUS_USER_SESSION_DELETED.

[\<291\> Section 3.3.5.5](#Appendix_A_Target_291): Windows Vista SP1 and
Windows Server 2008 servers fail the session setup request with
STATUS_REQUEST_NOT_ACCEPTED.

[\<292\> Section 3.3.5.5.3](#Appendix_A_Target_292): Windows Vista SP1
operating system and later and Windows Server 2008 operating system and
later will also accept raw Kerberos messages and implicit NTLM messages
as part of GSS authentication.

[\<293\> Section 3.3.5.5.3](#Appendix_A_Target_293): Windows by default
uses the [**guest account**](#gt_0377d4d6-d45e-4121-8f20-cba8f7fbb7a4)
to represent guest users. Alternatively, any user account that is a
member of the well-known BUILTIN_GUESTS or DOMAIN_GUESTS group (see
\[MS-DTYP\] section 2.4.2.4) is considered a guest account.

[\<294\> Section 3.3.5.5.3](#Appendix_A_Target_294): Windows 7 and
Windows Server 2008 R2 remove the current session from
**GlobalSessionTable** and **Connection.SessionTable** but the
SESSION_SETUP request succeeds, if the **PreviousSessionId** and
**SessionId** values in the SMB2 header of the request are equal and the
authentications were for the same user. Further requests using this
**SessionId** will fail with STATUS_USER_SESSION_DELETED.

[\<295\> Section 3.3.5.6](#Appendix_A_Target_295): Windows 7, Windows
Server 2008 R2, Windows 8, Windows Server 2012, Windows 8.1, and Windows
Server 2012 R2 servers will not reset
**ResilientOpenScavengerExpiryTime**.

[\<296\> Section 3.3.5.7](#Appendix_A_Target_296): Windows-based SMB2
servers do not set this bit in the **ShareFlags** field.

[\<297\> Section 3.3.5.7](#Appendix_A_Target_297): Windows-based SMB2
servers do not set this bit in the **ShareFlags** field.

[\<298\> Section 3.3.5.7](#Appendix_A_Target_298): Windows Server 2012
and Windows Server 2012 R2 set these two bits based on group policy
settings.

[\<299\> Section 3.3.5.7](#Appendix_A_Target_299): Windows Vista SP1 and
Windows Server 2008 do not support the SMB2_SHAREFLAG_ENABLE_HASH_V1
bit.

[\<300\> Section 3.3.5.7](#Appendix_A_Target_300): Windows Server v1709
and later support the SMB2_SHARE_CAP_REDIRECT_TO_OWNER bit.

[\<301\> Section 3.3.5.9](#Appendix_A_Target_301): If
**Open.ClientGuid** is not equal to the **ClientGuid** of the connection
that received this request, **Open.Lease.LeaseState** is equal to RWH,
or **Open.OplockLevel** is equal to SMB2_OPLOCK_LEVEL_BATCH,
Windows-based servers will attempt to break the lease/oplock and return
STATUS_PENDING to process the create request asynchronously. Otherwise,
if **Open.Lease.LeaseState** does not include SMB2_LEASE_HANDLE_CACHING
and **Open.OplockLevel** is not equal to SMB2_OPLOCK_LEVEL_BATCH,
Windows-based servers return STATUS_FILE_NOT_AVAILABLE.

[\<302\> Section 3.3.5.9](#Appendix_A_Target_302): Windows Vista and
Windows Server 2008 validate the create requests before session
verification as described in the "Create Context Validation" phase in
section [3.3.5.9](#Section_8c61e928924244ed96a098d1032d0d39).

[\<303\> Section 3.3.5.9](#Appendix_A_Target_303): Windows-based servers
accept the path names containing Dot Directory Names specified in
[\[MS-FSCC\]](%5bMS-FSCC%5d.pdf#Section_efbfe12773ad41409967ec6500e66d5e)
section 2.1.5.1 and attempt to normalize the path name by removing the
pathname components of "." and "..". Windows-based servers fail the
CREATE request with STATUS_INVALID_PARAMETER if the file name in the
**Buffer** field of the request begins in the form "subfolder\\.\\, for
example "x\\.\y.txt".

[\<304\> Section 3.3.5.9](#Appendix_A_Target_304): Windows-based SMB2
servers fail an SMB2 CREATE request with STATUS_ACCESS_DENIED if the
file name in the request is one of the following: "LPT1", "LPT2",
"LPT3","LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "COM1", "COM2",
"COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "PRN", "AUX",
"NUL", "CON", and "CLOCK\$".

[\<305\> Section 3.3.5.9](#Appendix_A_Target_305): Windows-based servers
ignore **DesiredAccess** values other than FILE_WRITE_DATA,
FILE_APPEND_DATA and GENERIC_WRITE if any one of these values is
specified.

[\<306\> Section 3.3.5.9](#Appendix_A_Target_306): Windows-based servers
fail requests having a **CreateDisposition** of FILE_OPEN or
FILE_OVERWRITE, but ignore values of FILE_SUPERSEDE, FILE_OPEN_IF and
FILE_OVERWRITE_IF.

[\<307\> Section 3.3.5.9](#Appendix_A_Target_307): Windows 8, Windows
Server 2012, Windows 8.1, and Windows Server 2012 R2 do not perform this
verification and continue to process the request.

[\<308\> Section 3.3.5.9](#Appendix_A_Target_308): Windows Vista SP1,
Windows Server 2008, Windows 7, Windows Server 2008 R2, Windows 8, and
Windows Server 2012 do not perform this verification.

[\<309\> Section 3.3.5.9](#Appendix_A_Target_309): Windows Vista,
Windows Server 2008, Windows 7, and Windows Server 2008 R2 operating
systems do not perform this verification and continue to process the
request.

[\<310\> Section 3.3.5.9](#Appendix_A_Target_310): Windows-based SMB2
servers check only for FILE_WRITE_DATA, FILE_WRITE_ATTRIBUTES,
FILE_WRITE_EA, and FILE_APPEND_DATA in the **DesiredAccess** field.

[\<311\> Section 3.3.5.9](#Appendix_A_Target_311): Windows performs the
access check by mapping SMB2 parameters to the object store parameters
as described in \[MS-FSA\] section 2.1.4.14 AccessCheck -- Algorithm to
Perform a General Access Check.

| Object Store parameter | SMB2 parameter                    |
|------------------------|-----------------------------------|
| SecurityContext        | Session.SecurityContext           |
| SecurityDescriptor     | TreeConnect.Share.ConnectSecurity |
| DesiredAccess          | DesiredAccess                     |

[\<312\> Section 3.3.5.9](#Appendix_A_Target_312): Windows Vista SP1 and
Windows Server 2008 do not support the
SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK flag and ignore the
**TreeConnect.Share.ForceLevel2Oplock** value.

[\<313\> Section 3.3.5.9](#Appendix_A_Target_313): Windows performs the
following open/create mappings from SMB2 parameters to the object store
as described in \[MS-FSA\] section 2.1.5.1 Server Requests an Open of a
File.

<table>
<colgroup>
<col style="width: 20%" />
<col style="width: 23%" />
<col style="width: 56%" />
</colgroup>
<thead>
<tr>
<th>Object Store parameter</th>
<th>SMB2 parameter</th>
<th>Notes</th>
</tr>
</thead>
<tbody>
<tr>
<td>DesiredAccess</td>
<td>DesiredAccess</td>
<td></td>
</tr>
<tr>
<td>DesiredFileAttributes</td>
<td>FileAttributes</td>
<td></td>
</tr>
<tr>
<td>ShareAccess</td>
<td>ShareAccess</td>
<td></td>
</tr>
<tr>
<td>CreateDisposition</td>
<td>CreateDisposition</td>
<td></td>
</tr>
<tr>
<td>CreateOptions</td>
<td>CreateOptions</td>
<td></td>
</tr>
<tr>
<td>SecurityContext</td>
<td><p>Session.SecurityContext</p>
<p>SecurityFlags</p>
<p>ImpersonationLevel</p></td>
<td>SecurityFlags and ImpersonationLevel are not passed to the object
store</td>
</tr>
<tr>
<td>PathName</td>
<td>PathName</td>
<td>Relative to TreeConnect.Share.LocalPath</td>
</tr>
<tr>
<td>RootOpen</td>
<td>TreeConnect.Share</td>
<td>A <strong>LocalOpen</strong> representing
<strong>TreeConnect.Share.LocalPath</strong>. Windows SMB2 servers
maintain such a <strong>LocalOpen</strong> for each active Share.</td>
</tr>
<tr>
<td>IsCaseInsensitive</td>
<td>TRUE</td>
<td>Windows-based SMB2 servers always handle path names as
case-insensitive.</td>
</tr>
<tr>
<td>TargetOplockKey</td>
<td>ClientLeaseId</td>
<td><p>Only passed when RequestedOplockLevel is set to
SMB2_OPLOCK_LEVEL_LEASE.</p>
<p>Otherwise, TargetOplockKey is set to NULL.</p></td>
</tr>
<tr>
<td>ParentOplockKey</td>
<td>ParentLeaseKey</td>
<td><p>ParentLeaseKey is obtained from the SMB2_CREATE_REQUEST_LEASE_V2
create context request.</p>
<p>Only passed when RequestedOplockLevel is set to
SMB2_OPLOCK_LEVEL_LEASE and SMB2_LEASE_FLAG_PARENT_LEASE_KEY_SET flag is
set in the Flags field of create context request.</p>
<p>Otherwise, ParentOplockKey is set to NULL.</p></td>
</tr>
</tbody>
</table>

Windows performs the following mappings from object store results to
SMB2 response.

| Object Store result | SMB2 response | Notes |
|----|----|----|
| CreateAction | CreateAction |  |
| Open | FileId | The FileId to Open mapping is computed and maintained by the server |

If **TreeConnect.Share.Type** is STYPE_DISKTREE, **CreateDisposition**
is FILE_SUPERSEDE, FILE_OVERWRITE or FILE_OVERWRITE_IF,
**DesiredAccess** does not include FILE_WRITE_DATA, FILE_APPEND_DATA or
GENERIC_WRITE, and there is an existing **Open** in **GlobalOpenTable**
where **Open.FileName** matches the **FileName** in the request,
**Open.TreeConnect.Share.IsCA** is TRUE, **Open.ShareAccess** does not
include FILE_SHARE_WRITE, Windows 8 and later and Windows Server 2012
and later fail the request with STATUS_OBJECT_NAME_NOT_FOUND.

[\<314\> Section 3.3.5.9](#Appendix_A_Target_314): Windows-based servers
will receive the data from the local create operation for constructing
the error response when a [**symbolic
link**](#gt_04f1ed93-15cb-4090-8204-c43bec8c7398) is present in the
target path name.

[\<315\> Section 3.3.5.9](#Appendix_A_Target_315):
If **TreeConnect.Share.Type** is
STYPE_DISKTREE, **CreateDisposition** is FILE_SUPERSEDE, FILE_OVERWRITE
or FILE_OVERWRITE_IF, **DesiredAccess** does not include
FILE_WRITE_DATA, FILE_APPEND_DATA or GENERIC_WRITE, and there is an
existing **Open** in **GlobalOpenTable** where **Open.FileName** matches
the **FileName** in the request, **Open.TreeConnect.Share.IsCA** is
TRUE, **Open.ShareAccess** does not include FILE_SHARE_WRITE, Windows 8
and later and Windows Server 2012 and later will retry the create with
disposition FILE_OPEN.

[\<316\> Section 3.3.5.9](#Appendix_A_Target_316): Windows Oplock
acquisition is described in \[MS-FSA\] section 2.1.5.18. Oplock
acquisition is an optional step in open/create processing; the *Open*
parameter passed is the **Open.Local** result from the open or create
operation, and the Type parameter is mapped as follows.

| Object Store oplock Type | SMB2 oplock level           |
|--------------------------|-----------------------------|
| LEVEL_BATCH              | SMB2_OPLOCK_LEVEL_BATCH     |
| LEVEL_ONE                | SMB2_OPLOCK_LEVEL_EXCLUSIVE |
| LEVEL_TWO                | SMB2_OPLOCK_LEVEL_II        |

The **Status** code returned indicates whether the requested oplock was
granted.

[\<317\> Section 3.3.5.9](#Appendix_A_Target_317): Windows obtains
**CreationTime** from the object store FileBasicInformation \[MS-FSA\]
section 2.1.5.12.6 and \[MS-FSCC\] section 2.4.7.

[\<318\> Section 3.3.5.9](#Appendix_A_Target_318): Windows obtains
**LastAccessTime** from the object store FileBasicInformation \[MS-FSA\]
section 2.1.5.12.6 and \[MS-FSCC\] section 2.4.7.

[\<319\> Section 3.3.5.9](#Appendix_A_Target_319): Windows obtains
**LastWriteTime** from the object store FileBasicInformation \[MS-FSA\]
section 2.1.5.12.6 and \[MS-FSCC\] section 2.4.7.

[\<320\> Section 3.3.5.9](#Appendix_A_Target_320): Windows obtains
**ChangeTime** from the object store FileBasicInformation \[MS-FSA\]
section 2.1.5.12.6 and \[MS-FSCC\] section 2.4.7.

[\<321\> Section 3.3.5.9](#Appendix_A_Target_321): Windows obtains
**AllocationSize** from the object store FileStandardInformation
\[MS-FSA\] section 2.1.5.12.27 and \[MS-FSCC\] section 2.4.47.

[\<322\> Section 3.3.5.9](#Appendix_A_Target_322): Windows-based SMB2
servers will set AllocationSize to any value for the named pipe.

[\<323\> Section 3.3.5.9](#Appendix_A_Target_323): Windows obtains
**EndOfFile** from the object store FileStandardInformation \[MS-FSA\]
section 2.1.5.12.27 and \[MS-FSCC\] section 2.4.47.

[\<324\> Section 3.3.5.9](#Appendix_A_Target_324): Windows-based SMB2
servers will set EndofFile to any value for the named pipe.

[\<325\> Section 3.3.5.9](#Appendix_A_Target_325): Windows obtains
**FileAttributes** from the object store FileBasicInformation \[MS-FSA\]
section 2.1.5.12.6 and \[MS-FSCC\] section 2.4.7.

[\<326\> Section 3.3.5.9.1](#Appendix_A_Target_326): Windows sets
extended attributes on a newly created file with the
**FSCTL_SET_OBJECT_ID_EXTENDED FSCTL** \[MS-FSA\] section 2.1.5.10.36
and \[MS-FSCC\] section 2.3.81.

[\<327\> Section 3.3.5.9.2](#Appendix_A_Target_327): Windows sets
security attributes on a newly created file with the Application
requests setting of security information \[MS-FSA\] section 2.1.5.17.

[\<328\> Section 3.3.5.9.2](#Appendix_A_Target_328): Windows will ignore
security descriptors if the underlying object store does not support
them.

[\<329\> Section 3.3.5.9.3](#Appendix_A_Target_329): Windows-based
servers support this request.

[\<330\> Section 3.3.5.9.3](#Appendix_A_Target_330): Windows sets
allocation size on a newly created file with the
FileAllocationInformation \[MS-FSA\] section 2.1.5.15.1 and \[MS-FSCC\]
section 2.4.4, after converting bytes to volume cluster size.

[\<331\> Section 3.3.5.9.4](#Appendix_A_Target_331): Windows validates
that a snapshot with the time stamp provided exists by forming a
**FileBothDirectoryInformation** object store request for the file
including the provided [**@GMT
token**](#gt_9fb4d987-6d9a-4ef5-81be-eeae393afb40) in the path, as
described in \[MS-SMB\] section 2.2.1.1.1 and \[MS-FSA\] section
2.1.5.6.3.1.

[\<332\> Section 3.3.5.9.4](#Appendix_A_Target_332): Windows opens a
file on a snapshot with the time stamp provided by the file including
the provided @GMT token in the path, as described in \[MS-SMB\] section
2.2.1.1.1 and \[MS-FSA\] section 2.1.5.1.

[\<333\> Section 3.3.5.9.5](#Appendix_A_Target_333): Windows computes
the MaximalAccess to return by querying the security attributes of the
file with \[MS-FSA\] section 2.1.5.14, and performing an access check
against the credentials provided by the request. **QueryStatus** is set
to the **Status** returned in that operation.

[\<334\> Section 3.3.5.9.6](#Appendix_A_Target_334): Windows Vista SP1,
Windows 7, Windows Server 2008, and Windows Server 2008 R2 ignore
undefined create contexts.

[\<335\> Section 3.3.5.9.6](#Appendix_A_Target_335): Windows Vista,
Windows Server 2008, Windows 7, and Windows Server 2008 R2 set
**Open.DurableOpenTimeout** to 16 minutes. Windows 8, Windows Server
2012, Windows 8.1, Windows Server 2012 R2, Windows 10, Windows Server
2016, and Windows Server set **Open.DurableOpenTimeout** to 2 minutes.

[\<336\> Section 3.3.5.9.7](#Appendix_A_Target_336): Windows Vista SP1,
Windows Server 2008, Windows 7 and Windows Server 2008 R2 ignore
undefined create contexts.

[\<337\> Section 3.3.5.9.7](#Appendix_A_Target_337): If the **Session**
was established by invalidating the previous session by specifying
**PreviousSessionId** in the SMB2 SESSION_SETUP request, Windows 8.1 and
Windows Server 2012 R2 close the durable opens established on the
previous session.

[\<338\> Section 3.3.5.9.7](#Appendix_A_Target_338): Windows 8, Windows
Server 2012, Windows 8.1 and Windows Server 2012 R2 do not perform lease
version verification.

[\<339\> Section 3.3.5.9.7](#Appendix_A_Target_339): Windows Vista SP1,
Windows Server 2008, Windows 7, and Windows Server 2008 R2 servers
respond with the SMB2_CREATE_DURABLE_HANDLE_RESPONSE create context
after a successful reconnect of a durable open.

[\<340\> Section 3.3.5.9.8](#Appendix_A_Target_340): Windows 7, Windows
Server 2008 R2, Windows 8, Windows Server 2012, Windows 8.1, and Windows
Server 2012 R2 do not ignore the SMB2_CREATE_REQUEST_LEASE create
context when **RequestedOplockLevel** is not equal to
SMB2_OPLOCK_LEVEL_LEASE.

[\<341\> Section 3.3.5.9.8](#Appendix_A_Target_341): On Windows 7,
Windows Server 2008 R2, Windows 8, Windows Server 2012, Windows 8.1, and
Windows Server 2012 R2, the **Lease.ClientLeaseId** is passed to the
object store when processing continues at open/create time. A new or
existing lease is thereby associated with the resulting open.

To acquire or promote the lease as dictated by the
SMB2_CREATE_REQUEST_LEASE Create Context, a subsequent object store call
is invoked as described in \[MS-FSA\] section 2.1.5.18. The *Open*
parameter passed is an internally-managed open that refers to the same
file, stream, and oplock key as **Open.LocalOpen** but is otherwise
distinct from **Open.LocalOpen**, and the *Type* parameter is
LEVEL_GRANULAR to indicate a Lease request. The **RequestedOplockLevel**
parameter is constructed to include zero or more bits as follows.

| Object Store RequestedOplockLevel bit to be set | SMB2 Lease.LeaseState bit requested |
|----|----|
| READ_CACHING | SMB2_LEASE_READ_CACHING |
| WRITE_CACHING | SMB2_LEASE_WRITE_CACHING |
| HANDLE_CACHING | SMB2_LEASE_HANDLE_CACHING |

The Status code returned indicates whether the requested lease was
granted.

[\<342\> Section 3.3.5.9.10](#Appendix_A_Target_342): Windows-based
servers send the SMB2_CREATE_DURABLE_HANDLE_RESPONSE_V2 response create
context to the client if any of the following conditions is satisfied:

- **Open.IsPersistent** is TRUE

- **Open.OplockLevel** is equal to SMB2_OPLOCK_LEVEL_BATCH

- **Open.Lease.LeaseState** contains SMB2_LEASE_HANDLE_CACHING

[\<343\> Section 3.3.5.9.10](#Appendix_A_Target_343): If the **Timeout**
value in the request is not zero, Windows 8, Windows Server 2012,
Windows 8.1, and Windows Server 2012 R2 SMB2 servers set **Timeout** to
the **Timeout** value in the request.

[\<344\> Section 3.3.5.9.10](#Appendix_A_Target_344): If the **Timeout**
value in the request is zero and **Share.CATimeout** is not zero,
Windows 8, Windows Server 2012, Windows 8.1, Windows Server 2012 R2,
Windows 10, Windows Server 2016, and Windows Server SMB2 servers set
**Timeout** to **Share.CATimeout**. If the **Timeout** value in the
request is zero and **Share.CATimeout** is zero, Windows 8 and Windows
Server 2012 SMB2 servers set **Timeout** to 60 seconds.

[\<345\> Section 3.3.5.9.11](#Appendix_A_Target_345): Windows 8, Windows
Server 2012, Windows 8.1, and Windows Server 2012 R2 servers do not
ignore the SMB2_CREATE_REQUEST_LEASE_V2 create context when
**Connection.Dialect** is equal to "2.1" or if **RequestedOplockLevel**
is not equal to SMB2_OPLOCK_LEVEL_LEASE.

[\<346\> Section 3.3.5.9.11](#Appendix_A_Target_346): On Windows 8,
Windows Server 2012, Windows 8.1, and Windows Server 2012 R2, the
**Lease.ClientLeaseId** and **Lease.ParentLeaseKey** are passed to the
object store in the form of **TargetOplockKey** and **ParentOplockKey**.
A new or existing lease is thereby associated with the resulting open.

To acquire or promote the lease as dictated by the
SMB2_CREATE_REQUEST_LEASE_V2 Create Context, a subsequent object store
call is invoked as described in \[MS-FSA\] section 2.1.5.18 Server
Requests an Oplock. The *Open* parameter passed is an internally-managed
open that refers to the same file, stream, and oplock key as
**Open.LocalOpen** but is otherwise distinct from **Open.LocalOpen**,
and the Type parameter is LEVEL_GRANULAR to indicate a Lease request.
The **RequestedOplockLevel** field is constructed to include zero or
more bits as follows.

| Object Store RequestedOplockLevel bit to be set | SMB2 Lease.LeaseState bit requested |
|----|----|
| READ_CACHING | SMB2_LEASE_READ_CACHING |
| WRITE_CACHING | SMB2_LEASE_WRITE_CACHING |
| HANDLE_CACHING | SMB2_LEASE_HANDLE_CACHING |

The Status code returned indicates whether the requested lease was
granted.

[\<347\> Section 3.3.5.9.12](#Appendix_A_Target_347): If
**Open.OplockLevel** is equal to SMB2_OPLOCK_LEVEL_BATCH or
**Open.Lease.LeaseState** includes SMB2_LEASE_HANDLE_CACHING, Windows 8,
Windows Server 2012, Windows 8.1, and Windows Server 2012 R2 continue to
process the request.

[\<348\> Section 3.3.5.9.12](#Appendix_A_Target_348): If
**Open.IsPersistent** is TRUE, **Open.Lease.LeaseState** does not
contain SMB2_LEASE_HANDLE_CACHING, **Open.OplockLevel** is not equal to
SMB2_OPLOCK_LEVEL_BATCH, SMB2_DHANDLE_FLAG_PERSISTENT bit is set in the
**Flags** field of the SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2 Create
Context and there is another existing **Open** in the
**GlobalOpenTable** on the same file with same **LeaseKey** and
**Open.IsPersistent** is TRUE, Windows 8 and later and Windows Server
2012 and later fail the request with STATUS_FILE_NOT_AVAILABLE.

[\<349\> Section 3.3.5.9.12](#Appendix_A_Target_349): Windows 8, Windows
Server 2012, Windows 8.1, and Windows Server 2012 R2 do not perform
Lease version verification.

[\<350\> Section 3.3.5.9.12](#Appendix_A_Target_350): Windows 8, Windows
Server 2012, Windows 8.1, and Windows Server 2012 R2 do not perform this
verification and continue to process the request.

[\<351\> Section 3.3.5.9.12](#Appendix_A_Target_351): If the **Session**
was established by specifying **PreviousSessionId** in the SMB2
SESSION_SETUP request, therefore invalidating the previous session,
Windows 8.1 and Windows Server 2012 R2 close the durable opens
established on the previous session.

[\<352\> Section 3.3.5.9.12](#Appendix_A_Target_352): If the **Session**
was established by specifying **PreviousSessionId** in the SMB2
SESSION_SETUP request, therefore invalidating the previous session,
Windows 8.1 and Windows Server 2012 R2 close the durable opens
established on the previous session.

[\<353\> Section 3.3.5.9.12](#Appendix_A_Target_353): When an open, with
**Open.IsPersistent** set to TRUE, is being reconnected due to server
failover, Windows 8 through Windows 11, version 23H2 and Windows Server
2012 through Windows Server 2022, 23H2 perform the following:

- If **Lease.LeaseState** includes SMB2_LEASE_WRITE_CACHING, **Epoch**
  and **Lease.Epoch** are set to **Epoch** field in the Create Context
  request.

- If **Lease.LeaseState** does not include SMB2_LEASE_WRITE_CACHING,
  **Epoch** and **Lease.Epoch** are set to **Epoch** field in the Create
  Context request incremented by 1.

When an open, with **Open.IsPersistent** set to TRUE, is being
reconnected due to server failover, Windows 11, version 24H2 and Windows
Server 2025 perform the following:

- If **LeaseState** in the Create Context request is 0, **Epoch** is set
  to **Lease.Epoch**.

- If **LeaseState** in the Create Context request includes
  SMB2_LEASE_WRITE_CACHING and is successfully restored to
  **Lease.LeaseState**, **Epoch** is set to **Lease.Epoch**.

- If **LeaseState** in the Create Context request does not include
  SMB2_LEASE_WRITE_CACHING and **Lease.LeaseState** is not 0,
  **Lease.LeaseEpoch** is incremented by 1 and **Epoch** is set to
  **Lease.Epoch**.

[\<354\> Section 3.3.5.9.13](#Appendix_A_Target_354): Windows SMB3
servers compute the maximal access to return by querying the security
attributes of the file with \[MS-FSA\] section 2.1.5.14, and performing
an access check against the credentials provided by the request.

[\<355\> Section 3.3.5.9.13](#Appendix_A_Target_355): Windows Server
2012 and Windows Server 2012 R2 servers do not close the open.

[\<356\> Section 3.3.5.10](#Appendix_A_Target_356): Windows Vista,
Windows Server 2008, Windows 7, and Windows Server 2008 R2 validate the
open before verifying the session.

[\<357\> Section 3.3.5.10](#Appendix_A_Target_357): Windows obtains
FileNetworkOpenInformation from the object store as described in
\[MS-FSA\] section 2.1.5.12.21 and \[MS-FSCC\] section 2.4.34.

Windows-based servers do not return an updated ChangeTime unless
**Open.GrantedAccess** includes FILE_WRITE_DATA, FILE_WRITE_ATTRIBUTES,
FILE_WRITE_EA, or FILE_APPEND_DATA and any prior WRITE/SET_INFO
operations were performed on that **Open**.

[\<358\> Section 3.3.5.11](#Appendix_A_Target_358): Windows flushes any
cached data to the file with Server Requests Flushing Cached Data
\[MS-FSA\] section 2.1.5.7.

[\<359\> Section 3.3.5.11](#Appendix_A_Target_359): If the request
target is a named pipe or file, Windows-based servers handle this
request asynchronously.

[\<360\> Section 3.3.5.12](#Appendix_A_Target_360): Windows 7 and
Windows Server 2008 R2 fail the request with STATUS_BUFFER_OVERFLOW if
the **Length** field is greater than **Connection.MaxReadSize**. Windows
Vista SP1 and Windows Server 2008 will fail the request with
STATUS_BUFFER_OVERFLOW if the **Length** field is greater than 524288.

[\<361\> Section 3.3.5.12](#Appendix_A_Target_361): Windows reads from a
file with Server Requests a Read \[MS-FSA\] section 2.1.5.3.

| Object Store parameter | SMB2 parameter |
|----|----|
| ByteOffset | Offset |
| ByteCount | Length |
| Open | Open.Local |
| Key | 0 |
| Unbuffered | Set to TRUE if SMB2_READFLAG_READ_UNBUFFERED is set in the **Flags** field of the request, otherwise set to FALSE. |

[\<362\> Section 3.3.5.12](#Appendix_A_Target_362): Windows SMB2 servers
send an interim response to the client and handle the read
asynchronously if the read is not finished in 0.5 milliseconds.

[\<363\> Section 3.3.5.12](#Appendix_A_Target_363): Windows-based
servers handle the following commands asynchronously: SMB2
Create (section 2.2.13) when this create would result in an oplock
break, [SMB2 IOCTL
Request (section 2.2.31)](#Section_5c03c9d615de48a298358fb37f8a79d8) for
FSCTL_PIPE_TRANSCEIVE if it blocks for more than 1 millisecond, SMB2
IOCTL Request for FSCTL_SRV_COPYCHUNK or FSCTL_SRV_COPYCHUNK_WRITE
(section 2.2.31) when oplock break happens, SMB2 Change_Notify
Request (section 2.2.35) if it blocks for more than 0.5 milliseconds,
[SMB2 Read
request (section 2.2.19)](#Section_320f04f31b2845cdaaa19e5aed810dca) for
named pipes if it blocks for more than 0.5 milliseconds, [SMB2 Write
request (section 2.2.21)](#Section_e704696133184350be2aa8d69bb59ce8) for
named pipes if it blocks for more than 0.5 milliseconds, SMB2 Write
Request (section 2.2.21) for large file write, SMB2 lock
request (section 2.2.26) if the SMB2_LOCKFLAG_FAIL_IMMEDIATELY flag is
not set, and SMB2 FLUSH Request (section 2.2.17) for named pipes.

[\<364\> Section 3.3.5.13](#Appendix_A_Target_364): Windows SMB2 servers
allow the operation when either FILE_APPEND_DATA or FILE_WRITE_DATA is
set in **Open.GrantedAccess**.

[\<365\> Section 3.3.5.13](#Appendix_A_Target_365): Windows 7 and
Windows Server 2008 R2 fail the request with STATUS_BUFFER_OVERFLOW
instead of STATUS_INVALID_PARAMETER if the **Length** field is greater
than **Connection.MaxWriteSize**. Windows Vista SP1 and Windows Server
2008 do not validate the Length field in SMB2 Write Request.

[\<366\> Section 3.3.5.13](#Appendix_A_Target_366): If the **Flags**
field contains any bit values other than those specified in section
2.2.21, Windows Vista SP1, Windows Server 2008, Windows 7, Windows
Server 2008 R2, Windows 8, and Windows Server 2012 fail the request with
STATUS_INVALID_PARAMETER.

[\<367\> Section 3.3.5.13](#Appendix_A_Target_367): Windows writes to a
file with Server Requests a Write \[MS-FSA\] section 2.1.5.4.

| Object Store parameter | SMB2 parameter |
|----|----|
| ByteOffset | ByteOffset |
| ByteCount | ByteCount |
| InputBuffer | Buffer |
| Open | Open.Local |
| Key | 0 |
| Unbuffered | Set to TRUE if SMB2_WRITEFLAG_WRITE_UNBUFFERED is set in the Flags field of the request, otherwise set to FALSE. |

[\<368\> Section 3.3.5.13](#Appendix_A_Target_368): Windows-based
servers handle the following commands asynchronously:

- SMB2 CREATE Request (section 3.3.5.9) when this create would result in
  an oplock break.

- SMB2 IOCTL Request (section
  [3.3.5.15](#Section_c348a671775049f89e61cc59fa1a5701)) for
  FSCTL_PIPE_TRANSCEIVE if it blocks for more than 1 millisecond. For
  FSCTL_SRV_COPYCHUNK or FSCTL_SRV_COPYCHUNK_WRITE, when an oplock break
  happens.

- SMB2 CHANGE_NOTIFY Request (section
  [3.3.5.19](#Section_05869c3239f04726afc9671b76ae5ca7)) if it blocks
  for more than 0.5 milliseconds.

- SMB2 READ Request (section
  [3.3.5.12](#Section_21e8b34334e94fca8d9303dd2d3e961e)) for named pipes
  if it blocks for more than 0.5 milliseconds.

- SMB2 WRITE Request (section
  [3.3.5.13](#Section_829f93f5ed104f12834742d235019459)) for named pipes
  if it blocks for more than 0.5 milliseconds.

- SMB2 WRITE Request (section 3.3.5.13) for large file write.

- SMB2 LOCK Request (section
  [3.3.5.14](#Section_a2f8b1ccebe043789da94e25de5c628f)) if the
  SMB2_LOCKFLAG_FAIL_IMMEDIATELY flag is not set.

- SMB2 FLUSH Request (section
  [3.3.5.11](#Section_026984f638af4408820050557eb0a286)) for named
  pipes.

[\<369\> Section 3.3.5.14](#Appendix_A_Target_369): Windows Vista,
Windows Server 2008, Windows 7, and Windows Server 2008 R2 validate the
open before verifying the session.

[\<370\> Section 3.3.5.14](#Appendix_A_Target_370): Windows 7 and
Windows Server 2008 R2 perform lock sequence verification only when
**Open.IsResilient** is TRUE.

Windows 8 through Windows 10 v1909 and Windows Server 2012 through
Windows Server v1909 perform lock sequence verification only when
**Open.IsResilient** or **Open.IsPersistent** is TRUE.

[\<371\> Section 3.3.5.14.1](#Appendix_A_Target_371): Windows-based
servers ignore this value while processing Unlocks.

[\<372\> Section 3.3.5.14.1](#Appendix_A_Target_372): Windows processes
unlock with Server Requests unlock of a Byte-Range \[MS-FSA\] section
2.1.5.9.

| Object Store parameter | SMB2 parameter |
|------------------------|----------------|
| FileOffset             | Offset         |
| Length                 | Length         |
| Open                   | Open.Local     |
| LockKey                | 0              |

[\<373\> Section 3.3.5.14.2](#Appendix_A_Target_373): Windows-based
servers check for SMB2_LOCKFLAG_FAIL_IMMEDIATELY only for the first
element of the **Locks** array.

[\<374\> Section 3.3.5.14.2](#Appendix_A_Target_374): Refer to \[FSBO\]
for implementation-specific details of how byte range locks can be
implemented.

[\<375\> Section 3.3.5.14.2](#Appendix_A_Target_375): Windows processes
lock with Server Requests a Byte-Range Lock \[MS-FSA\] section 2.1.5.8.

| Object Store parameter | SMB2 parameter |
|----|----|
| FileOffset | Offset |
| Length | Length |
| ExclusiveLock | FALSE if SMB2_LOCKFLAG_SHARED_LOCK set, or TRUE if SMB2_LOCKFLAG_EXCLUSIVE_LOCK set |
| FailImmediately | TRUE if SMB2_LOCKFLAG_FAIL_IMMEDIATELY set |
| Open | Open.Local |
| LockKey | 0 |

[\<376\> Section 3.3.5.15](#Appendix_A_Target_376): Windows Vista SP1
and Windows Server 2008 SMB2 servers fail an IOCTL request with
STATUS_INVALID_PARAMETER if \[ max(**InputCount**,
**MaxInputResponse**) + max(**OutputCount**, **MaxOutputResponse**) \]
is greater than 262144.

[\<377\> Section 3.3.5.15](#Appendix_A_Target_377): Windows 8 and later
and Windows Server 2012 and later do not fail the request.

[\<378\> Section 3.3.5.15](#Appendix_A_Target_378): Windows Vista,
Windows Server 2008, Windows 7, and Windows Server 2008 R2 fail the
request with STATUS_INVALID_PARAMETER in the following cases:

- If **OutputCount** is not equal to zero and **OutputOffset** is
  greater than zero but less than (size of SMB2 header + size of the
  SMB2 IOCTL request not including **Buffer**).

- If **OutputCount** is not equal to zero and **OutputOffset** is
  greater than size of SMB2 Message.

- If **OutputCount** is not equal to zero and **OutputOffset** is not
  rounded up to a multiple of 8 bytes.

- If (**OutputOffset** + **OutputCount**) is greater than size of SMB2
  Message.

- If **OutputCount** is greater than zero and **OutputOffset** is less
  than (**InputOffset** + **InputCount**).

Windows 7 and Windows Server 2008 R2 fail the request with
STATUS_INVALID_PARAMETER if **OutputOffset** or **OutputCount** is
greater than size of SMB2 Message.

[\<379\> Section 3.3.5.15](#Appendix_A_Target_379): Windows 7, Windows
Server 2008 R2, Windows 8, Windows Server 2012, Windows 8.1, and Windows
Server 2012 R2 SMB2 servers copy the **OutputCount** bytes into the
output buffer for the following
[**FSCTLs**](#gt_4ffb96a7-5fad-488e-9438-b7707d2e4226):

- FSCTL_GET_RETRIEVAL_POINTERS

- FSCTL_GET_REPARSE_POINT

- FSCTL_PIPE_TRANSCEIVE

- FSCTL_PIPE_PEEK

- FSCTL_DFS_GET_REFERRALS

Windows Vista SP1 and Windows Server 2008 SMB2 servers copy the
**OutputCount** bytes into the output buffer for the following FSCTLs:

- FSCTL_PIPE_TRANSCEIVE

- FSCTL_PIPE_PEEK

- FSCTL_DFS_GET_REFERRALS

All other FSCTL commands will be failed with error
STATUS_BUFFER_OVERFLOW through error response specified in section
[2.2.2](#Section_d4da8b67c18047e3ba7ad24214ac4aaa).

[\<380\> Section 3.3.5.15](#Appendix_A_Target_380): Windows 8 and later
and Windows Server 2012 and later allow only the **CtlCode** values, as
specified in section 2.2.31, and the following **CtlCode** values, as
specified in \[MS-FSCC\] section 2.3.

| FSCTL name                              | FSCTL function number |
|-----------------------------------------|-----------------------|
| FSCTL_CREATE_OR_GET_OBJECT_ID           | 0x900c0               |
| FSCTL_DELETE_OBJECT_ID                  | 0x900a0               |
| FSCTL_DELETE_REPARSE_POINT              | 0x900ac               |
| FSCTL_FILESYSTEM_GET_STATISTICS         | 0x90060               |
| FSCTL_FIND_FILES_BY_SID                 | 0x9008f               |
| FSCTL_GET_COMPRESSION                   | 0x9003c               |
| FSCTL_GET_NTFS_VOLUME_DATA              | 0x90064               |
| FSCTL_GET_OBJECT_ID                     | 0x9009c               |
| FSCTL_GET_REPARSE_POINT                 | 0x900a8               |
| FSCTL_GET_RETRIEVAL_POINTERS            | 0x90073               |
| FSCTL_IS_PATHNAME_VALID                 | 0x9002c               |
| FSCTL_LMR_SET_LINK_TRACKING_INFORMATION | 0x1400ec              |
| FSCTL_OFFLOAD_READ                      | 0x94264               |
| FSCTL_OFFLOAD_WRITE                     | 0x98268               |
| FSCTL_QUERY_FAT_BPB                     | 0x90058               |
| FSCTL_QUERY_FILE_REGIONS                | 0x90284               |
| FSCTL_QUERY_ALLOCATED_RANGES            | 0x940cf               |
| FSCTL_QUERY_ON_DISK_VOLUME_INFO         | 0x9013c               |
| FSCTL_QUERY_SPARING_INFO                | 0x90138               |
| FSCTL_READ_FILE_USN_DATA                | 0x900eb               |
| FSCTL_SET_COMPRESSION                   | 0x9c040               |
| FSCTL_SET_DEFECT_MANAGEMENT             | 0x98134               |
| FSCTL_SET_INTEGRITY_INFORMATION         | 0x9c280               |
| FSCTL_SET_OBJECT_ID                     | 0x90098               |
| FSCTL_SET_OBJECT_ID_EXTENDED            | 0x900bc               |
| FSCTL_SET_REPARSE_POINT                 | 0x900a4               |
| FSCTL_SET_SPARSE                        | 0x900c4               |
| FSCTL_SET_ZERO_DATA                     | 0x980c8               |
| FSCTL_SET_ZERO_ON_DEALLOCATION          | 0x90194               |
| FSCTL_WRITE_USN_CLOSE_RECORD            | 0x900ef               |

Windows 8.1 and later and Windows Server 2012 R2 and later allow these
additional **CtlCode** values, as specified in
[\[MS-RSVD\]](%5bMS-RSVD%5d.pdf#Section_c865c32647d64a91a62d0e8f26007d15).

| FSCTL name                              | FSCTL function number |
|-----------------------------------------|-----------------------|
| FSCTL_SVHDX_SYNC_TUNNEL_REQUEST         | 0x90304               |
| FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT | 0x90300               |

Windows 10 and later and Windows Server 2016 and later allow the
additional **CtlCode** value, as specified in \[MS-RSVD\].

| FSCTL name                       | FSCTL function number |
|----------------------------------|-----------------------|
| FSCTL_SVHDX_ASYNC_TUNNEL_REQUEST | 0x90364               |

Windows 10 and later and Windows Server 2016 and later allow the
additional **CtlCode** value, as specified in \[MS-FSCC\].

| FSCTL name                      | FSCTL function number |
|---------------------------------|-----------------------|
| FSCTL_DUPLICATE_EXTENTS_TO_FILE | 0x98344               |

Windows 10 v1607 operating system and later and Windows Server 2016
operating system and later allow the additional **CtlCode** value, as
specified in \[MS-FSCC\].

| FSCTL name        | FSCTL function number |
|-------------------|-----------------------|
| FSCTL_MARK_HANDLE | 0x900FC               |

Windows 10 v1803 operating system and later and Windows Server v1803
operating system and later allow the additional **CtlCode** value, as
specified in \[MS-FSCC\].

| FSCTL name                         | FSCTL function number |
|------------------------------------|-----------------------|
| FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX | 0x983e8‬               |

Windows 10 and later and Windows Server 2016 and later allow the
additional **CtlCode** value, as specified in
[\[MS-SQOS\]](%5bMS-SQOS%5d.pdf#Section_ccff4c80055e4ca7b3c5f3dc80068dcb).

| FSCTL name                | FSCTL function number |
|---------------------------|-----------------------|
| FSCTL_STORAGE_QOS_CONTROL | 0x90350               |

Windows 11 operating system and later and Windows Server 2022 operating
system and later allow the additional **CtlCode** value, as specified in
\[MS-FSCC\].

| FSCTL name                                | FSCTL function number |
|-------------------------------------------|-----------------------|
| FSCTL_GET_RETRIEVAL_POINTERS_AND_REFCOUNT | 0x903D3               |
| FSCTL_GET_RETRIEVAL_POINTER_COUNT         | 0x9042B               |
| FSCTL_REFS_STREAM_SNAPSHOT_MANAGEMENT     | 0x90440               |

Windows 11 and later and Windows Server 2022 and later allow the
additional **CtlCode** value, as specified in \[MS-FSCC\].

| FSCTL name                         | FSCTL function number |
|------------------------------------|-----------------------|
| FSCTL_SET_INTEGRITY_INFORMATION_EX | 0x90380               |

[\<381\> Section 3.3.5.15](#Appendix_A_Target_381): For the following
FSCTLs, Windows Vista SP1, Windows Server 2008, Windows 7, and Windows
Server 2008 R2 return STATUS_FILE_CLOSED instead of
STATUS_INVALID_DEVICE_REQUEST:

- FSCTL_QUERY_NETWORK_INTERFACE_INFO

- FSCTL_DFS_GET_REFERRALS_EX

- FSCTL_VALIDATE_NEGOTIATE_INFO

[\<382\> Section 3.3.5.15.1](#Appendix_A_Target_382): If
**MaxOutputResponse** is not 16 bytes, Windows-based servers do not
refresh the snapshots.

[\<383\> Section 3.3.5.15.1](#Appendix_A_Target_383): Windows-based SMB2
servers will place two extra bytes set to zero in the **SnapShots**
array and set **SnapShotArraySize** to two, if **NumberOfSnapShots** is
zero.

[\<384\> Section 3.3.5.15.2](#Appendix_A_Target_384): A Windows-based
DFS server does not return any data to the caller if the buffer supplied
to FSCTL_GET_DFS_REFERRALS is too small.

[\<385\> Section 3.3.5.15.3](#Appendix_A_Target_385): Windows-based
servers return STATUS_INVALID_DEVICE_REQUEST if the
FSCTL_PIPE_TRANSCEIVE being executed is not a named pipe share.

[\<386\> Section 3.3.5.15.3](#Appendix_A_Target_386): Windows SMB2
servers send an interim response to the client if the read/write attempt
is not finished in 1 millisecond.

[\<387\> Section 3.3.5.15.3](#Appendix_A_Target_387): Some Windows–based
SMB2 servers return the input buffer that was received in the request as
part of the response. Windows 7, Windows Server 2008 R2, Windows 8,
Windows Server 2012, Windows 8.1, and Windows Server 2012 R2 will not
return the input buffer that was received in the request, and the
**InputCount** field is always zero. Windows Vista SP1 and Windows
Server 2008 will send back the input buffer based on the **InputOffset**
and **InputCount** fields indicated in the request.

[\<388\> Section 3.3.5.15.3](#Appendix_A_Target_388): Windows–based SMB2
servers set **OutputOffset** to **InputOffset** + **InputCount**,
rounded up to a multiple of 8.

[\<389\> Section 3.3.5.15.4](#Appendix_A_Target_389): Windows-based
servers return STATUS_INVALID_DEVICE_REQUEST, if FSCTL_PIPE_PEEK request
being executed is not a named pipe share.

[\<390\> Section 3.3.5.15.4](#Appendix_A_Target_390): Windows SMB2
servers will set **OutputOffset** to **InputOffset** + **InputCount**,
rounded up to a multiple of 8.

[\<391\> Section 3.3.5.15.5](#Appendix_A_Target_391): Windows-based
servers do not support any additional contexts.

[\<392\> Section 3.3.5.15.5](#Appendix_A_Target_392): Windows-based
servers construct the 24-byte blob using **Open.DurableFileId** and
other pieces of information which include the process ID of the caller
and a timestamp.

[\<393\> Section 3.3.5.15.6](#Appendix_A_Target_393): Windows Vista SP1,
Windows Server 2008, Windows 7, and Windows Server 2008 R2 do not verify
byte-range locks on both source and destination files.

[\<394\> Section 3.3.5.15.7](#Appendix_A_Target_394): Windows 7, Windows
Server 2008 R2, Windows 8, Windows Server 2012, Windows 8.1, and Windows
Server 2012 R2 servers support the FSCTL_SRV_READ_HASH request.

[\<395\> Section 3.3.5.15.7](#Appendix_A_Target_395): When the branch
cache feature is available and the file size is less than 65,536 bytes,
Windows servers fail the request with STATUS_HASH_NOT_PRESENT.

[\<396\> Section 3.3.5.15.7](#Appendix_A_Target_396): Windows-based
servers set the **FileDataOffset** field to the starting offset from the
segment covering the **Offset** requested in the SRV_READ_HASH request.

[\<397\> Section 3.3.5.15.8](#Appendix_A_Target_397): The following
FSCTLs are explicitly blocked by Windows-based SMB2 server and are not
passed through to the object store. They are failed with
STATUS_NOT_SUPPORTED.

FSCTL_REQUEST_OPLOCK_LEVEL_1 (0x00090000)

FSCTL_REQUEST_OPLOCK_LEVEL_2 (0x00090004)

FSCTL_REQUEST_BATCH_OPLOCK (0x00090008)

FSCTL_REQUEST_FILTER_OPLOCK (0x0009005C)

FSCTL_OPLOCK_BREAK_ACKNOWLEDGE (0x0009000C)

FSCTL_OPBATCH_ACK_CLOSE_PENDING (0x00090010)

FSCTL_OPLOCK_BREAK_NOTIFY (0x00090014)

FSCTL_MOVE_FILE (0x00090074)

FSCTL_QUERY_RETRIEVAL_POINTERS (0x0009003B)

FSCTL_PIPE_ASSIGN_EVENT (0x00110000)

FSCTL_GET_VOLUME_BITMAP (0x0009006F)

FSCTL_GET_NTFS_FILE_RECORD (0x00090068)

FSCTL_INVALIDATE_VOLUMES (0x00090054)

FSCTL_READ_USN_JOURNAL (0x000900BB)

FSCTL_CREATE_USN_JOURNAL (0x000900E7)

FSCTL_QUERY_USN_JOURNAL (0x000900F4)

FSCTL_DELETE_USN_JOURNAL (0x000900F8)

FSCTL_ENUM_USN_DATA (0x000900B3)

FSCTL_QUERY_DEPENDENT_VOLUME (0x000901F0)

FSCTL_SD_GLOBAL_CHANGE (0x000901F4)

FSCTL_GET_BOOT_AREA_INFO (0x00090230)

FSCTL_GET_RETRIEVAL_POINTER_BASE (0x00090234)

FSCTL_SET_PERSISTENT_VOLUME_STATE (0x00090238)

FSCTL_QUERY_PERSISTENT_VOLUME_STATE (0x0009023C)

FSCTL_REQUEST_OPLOCK (0x00090240)

FSCTL_TXFS_MODIFY_RM (0x00098144)

FSCTL_TXFS_QUERY_RM_INFORMATION (0x00094148)

FSCTL_TXFS_ROLLFORWARD_REDO (0x00098150)

FSCTL_TXFS_ROLLFORWARD_UNDO (0x00098154)

FSCTL_TXFS_START_RM (0x00098158)

FSCTL_TXFS_SHUTDOWN_RM (0x0009815C)

FSCTL_TXFS_READ_BACKUP_INFORMATION (0x00094160)

FSCTL_TXFS_WRITE_BACKUP_INFORMATION (0x00098164)

FSCTL_TXFS_CREATE_SECONDARY_RM (0x00098168)

FSCTL_TXFS_GET_METADATA_INFO (0x0009416C)

FSCTL_TXFS_GET_TRANSACTED_VERSION (0x00094170)

FSCTL_TXFS_SAVEPOINT_INFORMATION (0x00098178)

FSCTL_TXFS_CREATE_MINIVERSION (0x0009817C)

FSCTL_TXFS_TRANSACTION_ACTIVE (0x0009418C)

FSCTL_TXFS_LIST_TRANSACTIONS (0x000941E4)

FSCTL_TXFS_READ_BACKUP_INFORMATION2 (0x000901F8)

FSCTL_TXFS_WRITE_BACKUP_INFORMATION2 (0x00090200)

FSCTL_QUERY_FILE_REGIONS (0x00090284)

FSCTL_IS_CSV_FILE (0x00090248)

FSCTL_IS_FILE_ON_CSV_VOLUME (0x0009025C)

Windows 10 v1511 operating system and prior and Windows Server 2012 R2
operating system and prior block FSCTL_MARK_HANDLE (0x000900FC) and do
not pass it through to the object store. The request is failed with
STATUS_NOT_SUPPORTED.

Windows Vista SP1, Windows 7, Windows Server 2008, and Windows Server
2008 R2 fail FSCTLs whose transfer type is METHOD_NEITHER with error
STATUS_NOT_SUPPORTED except the following ones. For more information
about FSCTL transfer type, see
[\[MSDN-IoCtlCodes\]](https://go.microsoft.com/fwlink/?LinkId=120805).

FSCTL_PIPE_TRANSCEIVE (0x0011C017)

FSCTL_QUERY_ALLOCATED_RANGES (0x000940CF)

FSCTL_WRITE_USN_CLOSE_RECORD (0x000900EF)

FSCTL_READ_FILE_USN_DATA (0x000900EB)

FSCTL_GET_RETRIEVAL_POINTERS (0x00090073)

FSCTL_FIND_FILES_BY_SID (0x0009008F)

FSCTL_SRV_READ_HASH (0x001441BB)

[\<398\> Section 3.3.5.15.8](#Appendix_A_Target_398): Windows performs
passthrough FSCTL operations via Server Requests an FsControl Request
\[MS-FSA\] section 2.1.5.10.

[\<399\> Section 3.3.5.15.8](#Appendix_A_Target_399): Windows–based SMB2
servers will set **OutputOffset** to **InputOffset** + **InputCount**,
rounded up to a multiple of 8.

[\<400\> Section 3.3.5.15.9](#Appendix_A_Target_400): Windows 7, Windows
Server 2008 R2, Windows 8, Windows Server 2012, Windows 8.1, and Windows
Server 2012 R2 servers process the FSCTL_LMR_REQUEST_RESILIENCY request
regardless of the negotiated dialect.

[\<401\> Section 3.3.5.15.9](#Appendix_A_Target_401): Windows 7 and
Windows Server 2008 R2 servers keep the resilient handle open
indefinitely when the requested **Timeout** value is equal to zero.
Windows 8, Windows Server 2012, Windows 8.1, and Windows Server 2012 R2
servers set a constant value of 120 seconds.

[\<402\> Section 3.3.5.15.13](#Appendix_A_Target_402): Windows 8,
Windows Server 2012, Windows 8.1, and Windows Server 2012 R2 require
that the caller is a member of the Administrators group.

[\<403\> Section 3.3.5.16](#Appendix_A_Target_403): Windows-based
servers use only the 30 least significant bits of **AsyncId** to look up
a request in **Connection.AsyncCommandList**.

[\<404\> Section 3.3.5.16](#Appendix_A_Target_404): When being handled
by an object store, Windows performs cancellation of in-progress
requests via the interface in \[MS-FSA\] section 2.1.5.20, Server
Requests Canceling an Operation, passing **Request.CancelRequestId** as
an input parameter. Windows does not attempt to cancel other in-progress
requests.

[\<405\> Section 3.3.5.17](#Appendix_A_Target_405): Windows Vista SP1,
Windows 7, Windows Server 2008, and Windows Server 2008 R2 servers do
not disconnect the connection.

[\<406\> Section 3.3.5.18](#Appendix_A_Target_406): Windows Vista SP1,
Windows Server 2008, Windows 7, Windows Server 2008 R2, Windows 8,
Windows Server 2012, Windows 8.1, and Windows Server 2012 R2 fail the
request with STATUS_NOT_SUPPORTED.

[\<407\> Section 3.3.5.18](#Appendix_A_Target_407): Windows-based SMB2
servers fail the request with STATUS_INVALID_PARAMETER if
**OutputBufferLength** is greater than 65536.

[\<408\> Section 3.3.5.18](#Appendix_A_Target_408): Windows Vista SP1,
Windows Server 2008, Windows 7, and Windows Server 2008 R2 close and
reopen the directory handle prior to processing the request.

[\<409\> Section 3.3.5.18](#Appendix_A_Target_409): Windows-based
servers perform query directory requests, as specified in \[MS-FSA\]
section 2.1.5.6 with the following input parameters:

- *Open* is set to **Open.LocalOpen**.

- *FileInformationClass* is set to the **InformationClass** that is
  received in the SMB2 QUERY_DIRECTORY Request.

- *OutputBufferSize* is set to the **OutputBufferLength** that is
  received in the SMB2 QUERY_DIRECTORY Request.

- If SMB2_RESTART_SCANS or SMB2_REOPEN is set in the **Flags** field of
  the SMB2 QUERY_DIRECTORY Request, *RestartScan* is set to TRUE.

- If SMB2_RETURN_SINGLE_ENTRY is set in the **Flags** field of the
  request, *ReturnSingleEntry* is set to TRUE.

- *FileIndex* is set to 0.

- *FileNamePattern* is set to the search pattern specified in the SMB2
  QUERY_DIRECTORY by **FileNameOffset** and **FileNameLength**.

When SMB2_REOPEN is set in the **Flags** field of SMB2 QUERY_DIRECTORY
request and the object store does not return any files, Windows 10 v1803
through Windows 11, and Windows Server 2019 fail the request with
STATUS_NO_MORE_FILES.

When SMB2_REOPEN is set in the **Flags** field of SMB2 QUERY_DIRECTORY
request and the object store does not return any files, Windows 11 v22H2
and Windows 11, version 23H2 with
[\[MSKB-5062663\]](https://go.microsoft.com/fwlink/?linkid=2326502),
Windows 11, version 24H2 with
[\[MSKB-5062660\]](https://go.microsoft.com/fwlink/?linkid=2326402) and
later, Windows Server 2022 with
[\[MSKB-5063880\]](https://go.microsoft.com/fwlink/?linkid=2327426) and
Windows Server 2022, 23H2 with
[\[MSKB-5063899\]](https://go.microsoft.com/fwlink/?linkid=2327818) and
Windows Server 2025 with \[MSKB-5062660\] and later fail the request
with STATUS_NO_SUCH_FILE.

[\<410\> Section 3.3.5.18](#Appendix_A_Target_410): Windows-based
servers ignore SMB2_INDEX_SPECIFIED in **Flags** field and **FileIndex**
value.

[\<411\> Section 3.3.5.19](#Appendix_A_Target_411): Windows-based SMB2
servers fail the request with STATUS_INVALID_PARAMETER if
**OutputBufferLength** is greater than 65536.

[\<412\> Section 3.3.5.19](#Appendix_A_Target_412): Windows-based
servers handle the following commands asynchronously: SMB2
Create (section 2.2.13) when this create would result in an oplock
break, SMB2 IOCTL Request (section 2.2.31) for FSCTL_PIPE_TRANSCEIVE if
it blocks for more than 1 millisecond, SMB2 IOCTL Request for
FSCTL_SRV_COPYCHUNK or FSCTL_SRV_COPYCHUNK_WRITE (section 2.2.31) when
oplock break happens, SMB2 Change_Notify Request (section 2.2.35) if it
blocks for more than 0.5 milliseconds, SMB2 Read
Request (section 2.2.19) for named pipes if it blocks for more than 0.5
milliseconds, SMB2 Write Request (section 2.2.21) for named pipes if it
blocks for more than 0.5 milliseconds, SMB2 Write
Request (section 2.2.21) for large file write, SMB2 lock
Request (section 2.2.26) if the SMB2_LOCKFLAG_FAIL_IMMEDIATELY flag is
not set, and SMB2 FLUSH Request (section 2.2.17) for named pipes.

[\<413\> Section 3.3.5.19](#Appendix_A_Target_413): Windows requests
ChangeNotify processing via Server Requests Change Notifications for a
Directory in \[MS-FSA\] section 2.1.5.11. If the SMB2_WATCH_TREE flag is
set, the WatchTree boolean is passed as TRUE. ChangeNotify notification
is reported as described in \[MS-FSA\] section 2.1.5.11.1.

[\<414\> Section 3.3.5.20](#Appendix_A_Target_414): Windows-based SMB2
servers fail the request with STATUS_INVALID_PARAMETER if
**OutputBufferLength** is greater than 65536.

[\<415\> Section 3.3.5.20.1](#Appendix_A_Target_415): Windows-based SMB2
servers fail the following request levels with STATUS_INVALID_INFO_CLASS
instead of STATUS_NOT_SUPPORTED: 1, 2, 3, 10, 11, 12, 13, 19, 20, 27,
31, 36, 37, 38, 39, 40, 50.

[\<416\> Section 3.3.5.20.1](#Appendix_A_Target_416): Windows-based SMB2
servers fail the following request levels with STATUS_NOT_SUPPORTED
instead of STATUS_INVALID_INFO_CLASS: 41, 43, 47, 49, 51, and 53.
Windows-based SMB2 servers fail requests of level 52 with
STATUS_INFO_LENGTH_MISMATCH.

[\<417\> Section 3.3.5.20.1](#Appendix_A_Target_417): Windows 10 v1709,
Windows Server v1709 and prior do not support the
**FileNormalizedNameInformation** information class.

[\<418\> Section 3.3.5.20.1](#Appendix_A_Target_418): Windows-based SMB2
servers will set **CurrentByteOffset** to any value.

[\<419\> Section 3.3.5.20.1](#Appendix_A_Target_419): Windows performs
SMB2 GET_INFO SMB2_0_INFO_FILE processing as specified in the subsection
of \[MS-FSA\] section 2.1.5.12, corresponding to the requested
FILE_INFORMATION_CLASS value of the **FileInfoClass** request field, as
listed in section [2.2.37](#Section_d623b2f7a5cd46398cc971fa7d9f9ba9).

[\<420\> Section 3.3.5.20.1](#Appendix_A_Target_420): If the information
class is **FileAllInformation**, Windows Vista SP1, Windows Server 2008,
Windows 7, Windows Server 2008 R2, Windows 8, Windows Server 2012,
Windows 8.1, and Windows Server 2012 R2 return an absolute path to the
file name as part of **FileNameInformation**.

[\<421\> Section 3.3.5.20.2](#Appendix_A_Target_421): Windows performs
SMB2 GET_INFO SMB2_0_INFO_FILESYSTEM processing via the subsection of
\[MS-FSA\] section 2.1.5.13 corresponding to the requested
FS_INFORMATION_CLASS value of the **FileInfoClass** request field, as
listed in section 2.2.37.

[\<422\> Section 3.3.5.20.2](#Appendix_A_Target_422): Windows 7 through
Windows 11 and Windows Server 2008 R2 operating system through Windows
Server 2022 SMB2 servers do not clear the bits
FILE_RETURNS_CLEANUP_RESULT_INFO, FILE_SUPPORTS_POSIX_UNLINK_RENAME
before sending to the client.

[\<423\> Section 3.3.5.20.2](#Appendix_A_Target_423): SetFsInfo calls to
Windows-based servers fail with STATUS_ACCESS_DENIED because
Windows-based servers do not allow setting volume information over the
network.

[\<424\> Section 3.3.5.20.3](#Appendix_A_Target_424): Windows performs
SMB2 GET_INFO SMB2_0_INFO_SECURITY processing via Server Requests a
Query of Security Information (\[MS-FSA\] section 2.1.5.14).

[\<425\> Section 3.3.5.20.4](#Appendix_A_Target_425): Windows-based
servers do support quotas, if configured.

[\<426\> Section 3.3.5.20.4](#Appendix_A_Target_426): Windows performs
SMB2 GET_INFO SMB2_0_INFO_QUOTA processing via Server Requests a Query
of Quota Information (\[MS-FSA\] section 2.1.5.21).

[\<427\> Section 3.3.5.21](#Appendix_A_Target_427): Windows-based SMB2
servers fail the request with STATUS_INVALID_PARAMETER if
**BufferLength** is greater than 65536.

[\<428\> Section 3.3.5.21.1](#Appendix_A_Target_428): Windows-based SMB2
servers fail the following request levels with STATUS_NOT_SUPPORTED
instead of STATUS_INVALID_INFO_CLASS: 30, 41, 42, 43.

[\<429\> Section 3.3.5.21.1](#Appendix_A_Target_429): Windows performs
SMB2 SET_INFO SMB2_0_INFO_FILE processing via the subsection of
\[MS-FSA\] section 2.1.5.15 corresponding to the requested
FILE_INFORMATION_CLASS value of the **FileInfoClass** request field, as
listed in section 2.2.37.

[\<430\> Section 3.3.5.21.2](#Appendix_A_Target_430): Windows performs
SMB2 SET_INFO SMB2_0_INFO_FILESYSTEM processing via the subsection of
\[MS-FSA\] section 2.1.5.16 corresponding to the requested
FS_INFORMATION_CLASS value of the **FileInfoClass** request field, as
listed in section 2.2.37.

[\<431\> Section 3.3.5.21.3](#Appendix_A_Target_431): If the underlying
object store does not support object security based on Access Control
Lists (as specified in \[MS-DTYP\] section 2.4.5), it returns
STATUS_SUCCESS.

[\<432\> Section 3.3.5.21.3](#Appendix_A_Target_432): Windows Server
2008, Windows 7 and Windows Server 2008 R2 ignore the
ATTRIBUTE_SECURITY_INFORMATION flag value.

[\<433\> Section 3.3.5.21.3](#Appendix_A_Target_433): Windows Server
2008, Windows 7 and Windows Server 2008 R2 ignore the
SCOPE_SECURITY_INFORMATION flag value.

[\<434\> Section 3.3.5.21.3](#Appendix_A_Target_434): Windows Server
2008, Windows 7 and Windows Server 2008 R2 ignore the
BACKUP_SECURITY_INFORMATION flag value.

[\<435\> Section 3.3.5.21.3](#Appendix_A_Target_435): Windows performs
SMB2 SET_INFO SMB2_0_INFO_SECURITY processing via Server Requests
Setting of Security Information \[MS-FSA\] section 2.1.5.17.

[\<436\> Section 3.3.5.21.4](#Appendix_A_Target_436): Windows-based
servers do support quotas, if configured.

[\<437\> Section 3.3.5.21.4](#Appendix_A_Target_437): Windows performs
SMB2 SET_INFO SMB2_0_INFO_QUOTA processing via Server Requests Setting
of Quota Information (\[MS-FSA\] section 2.1.5.22).

[\<438\> Section 3.3.5.22.1](#Appendix_A_Target_438): Windows-based
servers complete the [**oplock
break**](#gt_5c86b468-90a1-4542-8bde-460c098d2a5a) indication request
with the object store by providing the following SMB2 parameters as
input parameters, as specified \[MS-FSA\] section 2.1.5.19:

| Object Store parameter | SMB2 parameter         |
|------------------------|------------------------|
| Open                   | Open.LocalOpen         |
| Type                   | SMB2_OPLOCK_LEVEL_NONE |

[\<439\> Section 3.3.5.22.1](#Appendix_A_Target_439): Windows-based
servers complete the oplock break indication request with the object
store by providing the following SMB2 parameters as input parameters, as
specified \[MS-FSA\] section 2.1.5.19:

| Object Store parameter | SMB2 parameter         |
|------------------------|------------------------|
| Open                   | Open.LocalOpen         |
| Type                   | SMB2_OPLOCK_LEVEL_NONE |

[\<440\> Section 3.3.5.22.1](#Appendix_A_Target_440): Windows-based
servers complete the oplock break indication request with the object
store by providing the following SMB2 parameters as input parameters, as
specified \[MS-FSA\] section 2.1.5.19:

| Object Store parameter | SMB2 parameter         |
|------------------------|------------------------|
| Open                   | Open.LocalOpen         |
| Type                   | SMB2_OPLOCK_LEVEL_NONE |

[\<441\> Section 3.3.5.22.1](#Appendix_A_Target_441): If multiple
conflicting **Opens** occur before an Oplock Acknowledgment for the
first oplock break is received, that change the server oplock state to a
level that is lower than the pending notification, the server fails the
Oplock Acknowledgment with STATUS_REQUEST_NOT_ACCEPTED. Windows-based
servers complete the oplock break indication request with the object
store by providing the following SMB2 parameters as input parameters, as
specified in \[MS-FSA\] section 2.1.5.19:

| Object Store parameter | SMB2 parameter |
|------------------------|----------------|
| Open                   | Open.LocalOpen |
| Type                   | OplockLevel    |

[\<442\> Section 3.3.6.3](#Appendix_A_Target_442): Windows-based servers
use a constant time-out value of 45 seconds.

[\<443\> Section 3.3.7.1](#Appendix_A_Target_443): Windows performs
cancellation of in-progress requests via the interface in \[MS-FSA\]
section 2.1.5.20, Server Requests Canceling an Operation, passing
**Request.CancelRequestId** as an input parameter.

[\<444\> Section 3.3.7.1](#Appendix_A_Target_444): Windows 7, Windows
Server 2008 R2, Windows 8, Windows Server 2012, Windows 8.1, and Windows
Server 2012 R2 servers will not reset
**ResilientOpenScavengerExpiryTime**.

[\<445\> Section 3.3.7.1](#Appendix_A_Target_445): Windows performs
cancellation of in-progress requests via the interface in \[MS-FSA\]
section 2.1.5.20, Server Requests Canceling an Operation, passing
**Request.CancelRequestId** as an input parameter.

