[< Back to MS-SMB2 Index](../INDEX.md)

---

# 8 Index

A

Abstract data model

client ([section 3.1.1](#abstract-data-model) 154, [section
3.2.1](#abstract-data-model-1) 161)

server ([section 3.1.1](#abstract-data-model) 154, [section
3.3.1](#abstract-data-model-2) 258)

[Access mask encoding](#smb2-access-mask-encoding) 76

[Applicability](#applicability-statement) 28

[Application Requests Reauthenticating a
User](#application-requests-reauthenticating-a-user) 180

[Authenticating the user](#authenticating-the-user) 179

C

[Capability negotiation](#versioning-and-capability-negotiation) 28

[Change notifications
algorithm](#algorithm-for-change-notifications-in-an-object-store) 259

[Change tracking](#change-tracking) 492

Channel ([section 3.2.1.8](#per-channel) 167, [section
3.3.1.14](#per-channel-1) 272)

Client

abstract data model ([section 3.1.1](#abstract-data-model) 154, [section
3.2.1](#abstract-data-model-1) 161)

[global connections](#global-1) 161

[higher-layer triggered events](#higher-layer-triggered-events-1) 169

[notifying offline status of
server](#application-notifies-offline-status-of-a-server) 222

[notifying online status of
server](#application-notifies-online-status-of-a-server) 223

[overview](#higher-layer-triggered-events-1) 169

[re-establishing a durable open](#re-establishing-a-durable-open) 187

[requesting applying of file
attributes](#application-requests-applying-file-attributes) 195

[requesting applying of file security
attributes](#application-requests-applying-file-security) 198

[requesting applying of file system
attributes](#application-requests-applying-file-system-attributes) 196

[requesting applying of quota
information](#application-requests-applying-quota-information) 200

[requesting cancellation of
operation](#application-requests-canceling-an-operation) 221

[requesting change of notifications for
directory](#application-requests-change-notifications-for-a-directory)
203

[requesting closing of file or named
pipe](#application-requests-closing-a-file-or-named-pipe) 188

[requesting closing of share
connection](#application-requests-closing-a-share-connection) 221

[requesting connection to
share](#application-requests-a-connection-to-a-share) 173

[requesting enumeration of
directory](#application-requests-enumerating-a-directory) 202

[requesting flushing of cached
data](#application-requests-flushing-cached-data) 201

[requesting IO control code
operation](#application-requests-an-io-control-code-operation) 205

[requesting locking of array of byte
ranges](#application-requests-locking-of-an-array-of-byte-ranges) 204

[requesting move to server
instance](#application-requests-moving-to-a-server-instance) 223

[requesting number of opens on tree
connect](#application-requests-number-of-opens-on-a-tree-connect) 222

[requesting opening of file](#application-requests-opening-a-file) 182

[requesting querying for file
attributes](#application-requests-querying-file-attributes) 193

[requesting querying for file security
attributes](#application-requests-querying-file-security) 197

[requesting querying for file system
attributes](#application-requests-querying-file-system-attributes) 196

[requesting querying for quota
information](#application-requests-querying-quota-information) 199

[requesting reading from file or named
pipe](#application-requests-reading-from-a-file-or-named-pipe) 189

[requesting session key for authenticated
context](#application-requests-the-session-key-for-an-authenticated-context)
222

[requesting termination of authenticated
context](#application-requests-terminating-an-authenticated-context) 221

[requesting unlocking of array of byte
ranges](#application-requests-unlocking-of-an-array-of-byte-ranges) 220

[requesting writing to file or named
pipe](#application-requests-writing-to-a-file-or-named-pipe) 191

[sending any outgoing message](#sending-any-outgoing-message) 169

[signing outgoing message](#signing-an-outgoing-message) 155

initialization ([section 3.1.3](#initialization) 154, [section
3.2.3](#initialization-1) 168)

local events ([section 3.1.7](#other-local-events) 161, [section
3.2.7](#other-local-events-1) 257, [section
3.2.7.1](#handling-a-network-disconnect) 257)

message processing

[overview](#processing-events-and-sequencing-rules-1) 223

[receiving any message](#receiving-any-message) 223

[receiving SMB2 CHANGE_NOTIFY
response](#receiving-an-smb2-change_notify-response) 252

[receiving SMB2 CLOSE response](#receiving-an-smb2-close-response) 246

[receiving SMB2 CREATE response for new create
operation](#receiving-an-smb2-create-response-for-a-new-create-operation)
242

[receiving SMB2 CREATE response for open
reestablishment](#receiving-an-smb2-create-response-for-an-open-reestablishment)
245

[receiving SMB2 FLUSH response](#receiving-an-smb2-flush-response) 247

[receiving SMB2 IOCTL response](#receiving-an-smb2-ioctl-response) 249

[receiving SMB2 LOCK response](#receiving-an-smb2-lock-response) 248

[receiving SMB2 LOGOFF response](#receiving-an-smb2-logoff-response) 239

[receiving SMB2 NEGOTIATE
response](#receiving-an-smb2-negotiate-response) 227

[receiving SMB2 OPLOCK_BREAK
notification](#receiving-an-smb2-oplock_break-command) 253

[receiving SMB2 QUERY_DIRECTORY
response](#receiving-an-smb2-query_directory-response) 252

[receiving SMB2 QUERY_INFO
response](#receiving-an-smb2-query_info-response) 252

[receiving SMB2 READ response](#receiving-an-smb2-read-response) 247

[receiving SMB2 SESSION_SETUP
response](#receiving-an-smb2-session_setup-response) 232

[receiving SMB2 SET_INFO response](#receiving-an-smb2-set_info-response)
253

[receiving SMB2 TREE_CONNECT
response](#receiving-an-smb2-tree_connect-response) 239

[receiving SMB2 TREE_DISCONNECT
response](#receiving-an-smb2-tree_disconnect-response) 242

[receiving SMB2 WRITE response](#receiving-an-smb2-write-response) 248

[verifying incoming message](#verifying-an-incoming-message) 159

[message sequence numbers
algorithm](#algorithm-for-handling-available-message-sequence-numbers-by-the-client)
172

[per channel](#per-channel) 167

[per open](#per-application-open-of-a-file) 166

[per pending request](#per-pending-request) 167

[per session](#per-session) 164

[per SMB2 transport connection](#per-smb2-transport-connection) 162

[per tree connect](#per-tree-connect) 165

[per unique open file](#per-open-file) 165

[required global data](#global) 154

sequencing rules

[overview](#processing-events-and-sequencing-rules-1) 223

[receiving any message](#receiving-any-message) 223

[receiving SMB2 CHANGE_NOTIFY
response](#receiving-an-smb2-change_notify-response) 252

[receiving SMB2 CLOSE response](#receiving-an-smb2-close-response) 246

[receiving SMB2 CREATE response for new create
operation](#receiving-an-smb2-create-response-for-a-new-create-operation)
242

[receiving SMB2 CREATE response for open
reestablishment](#receiving-an-smb2-create-response-for-an-open-reestablishment)
245

[receiving SMB2 FLUSH response](#receiving-an-smb2-flush-response) 247

[receiving SMB2 IOCTL response](#receiving-an-smb2-ioctl-response) 249

[receiving SMB2 LOCK response](#receiving-an-smb2-lock-response) 248

[receiving SMB2 LOGOFF response](#receiving-an-smb2-logoff-response) 239

[receiving SMB2 NEGOTIATE
response](#receiving-an-smb2-negotiate-response) 227

[receiving SMB2 OPLOCK_BREAK
notification](#receiving-an-smb2-oplock_break-command) 253

[receiving SMB2 QUERY_DIRECTORY
response](#receiving-an-smb2-query_directory-response) 252

[receiving SMB2 QUERY_INFO
response](#receiving-an-smb2-query_info-response) 252

[receiving SMB2 READ response](#receiving-an-smb2-read-response) 247

[receiving SMB2 SESSION_SETUP
response](#receiving-an-smb2-session_setup-response) 232

[receiving SMB2 SET_INFO response](#receiving-an-smb2-set_info-response)
253

[receiving SMB2 TREE_CONNECT
response](#receiving-an-smb2-tree_connect-response) 239

[receiving SMB2 TREE_DISCONNECT
response](#receiving-an-smb2-tree_disconnect-response) 242

[receiving SMB2 WRITE response](#receiving-an-smb2-write-response) 248

[verifying incoming message](#verifying-an-incoming-message) 159

timer events ([section 3.1.6](#timer-events) 160, [section
3.2.6](#timer-events-1) 256)

timers ([section 3.1.2](#timers) 154, [section 3.2.2](#timers-1) 168)

[Connecting to the share](#connecting-to-the-share) 181

[Connecting to the target server](#connecting-to-the-target-server) 175

[Connections - global](#global-1) 161

[Credit granting algorithm](#algorithm-for-the-granting-of-credits) 259

D

[Data - global](#global) 154

Data model - abstract

[client](#abstract-data-model-1) 161

[server](#abstract-data-model-2) 258

Data model – abstract

client ([section 3.1.1](#abstract-data-model) 154, [section
3.2.1](#abstract-data-model-1) 161)

server ([section 3.1.1](#abstract-data-model) 154, [section
3.3.1](#abstract-data-model-2) 258)

[Directory_Access_Mask packet](#directory_access_mask) 78

[Disconnecting example](#disconnecting-a-share-and-logging-off) 431

[Durable open scavenger timer](#durable-open-scavenger-timer) 275

[Durable open scavenger timer
event](#durable-open-scavenger-timer-event) 392

E

[Establishing alternate channel example](#establish-alternate-channel)
433

Examples

[disconnecting](#disconnecting-a-share-and-logging-off) 431

[establishing alternate channel](#establish-alternate-channel) 433

[logging off](#disconnecting-a-share-and-logging-off) 431

[multi-protocol
negotiate](#connecting-to-a-share-by-using-a-multi-protocol-negotiate)
395

[named pipe](#executing-an-operation-on-a-named-pipe) 410

[negotiating SMB 2.10 dialect by using multi-protocol
negotiate](#negotiating-smb-2.1-dialect-by-using-multi-protocol-negotiate)
400

[overview](#protocol-examples) 395

remote files

[reading](#reading-from-a-remote-file) 417

[writing](#writing-to-a-remote-file) 422

[SMB2 negotiate](#connecting-to-a-share-by-using-an-smb2-negotiate) 405

F

[Fields - vendor-extensible](#vendor-extensible-fields) 30

[Fields – vendor-extensible](#vendor-extensible-fields) 30

[File_Pipe_Printer_Access_Mask packet](#file_pipe_printer_access_mask)
77

G

[Global connections](#global-1) 161

[Global data](#global) 154

[Global structures](#global-2) 261

[Glossary](#glossary) 15

H

[HASH_HEADER packet](#hash_header) 127

Higher-layer triggered events

[client](#higher-layer-triggered-events-1) 169

[notifying offline status of
server](#application-notifies-offline-status-of-a-server) 222

[notifying online status of
server](#application-notifies-online-status-of-a-server) 223

[overview](#higher-layer-triggered-events-1) 169

[re-establishing a durable open](#re-establishing-a-durable-open) 187

[requesting applying of file
attributes](#application-requests-applying-file-attributes) 195

[requesting applying of file security
attributes](#application-requests-applying-file-security) 198

[requesting applying of file system
attributes](#application-requests-applying-file-system-attributes) 196

[requesting applying of quota
information](#application-requests-applying-quota-information) 200

[requesting cancellation of
operation](#application-requests-canceling-an-operation) 221

[requesting change of notifications for
directory](#application-requests-change-notifications-for-a-directory)
203

[requesting closing of file or named
pipe](#application-requests-closing-a-file-or-named-pipe) 188

[requesting closing of share
connection](#application-requests-closing-a-share-connection) 221

[requesting connection to
share](#application-requests-a-connection-to-a-share) 173

[requesting enumeration of
directory](#application-requests-enumerating-a-directory) 202

[requesting flushing of cached
data](#application-requests-flushing-cached-data) 201

[requesting IO control code
operation](#application-requests-an-io-control-code-operation) 205

[requesting locking of array of byte
ranges](#application-requests-locking-of-an-array-of-byte-ranges) 204

[requesting move to server
instance](#application-requests-moving-to-a-server-instance) 223

[requesting number of opens on tree
connect](#application-requests-number-of-opens-on-a-tree-connect) 222

[requesting opening of file](#application-requests-opening-a-file) 182

[requesting querying for file
attributes](#application-requests-querying-file-attributes) 193

[requesting querying for file security
attributes](#application-requests-querying-file-security) 197

[requesting querying for file system
attributes](#application-requests-querying-file-system-attributes) 196

[requesting querying for quota
information](#application-requests-querying-quota-information) 199

[requesting reading from file or named
pipe](#application-requests-reading-from-a-file-or-named-pipe) 189

[requesting session key for authenticated
context](#application-requests-the-session-key-for-an-authenticated-context)
222

[requesting termination of authenticated
context](#application-requests-terminating-an-authenticated-context) 221

[requesting unlocking of array of byte
ranges](#application-requests-unlocking-of-an-array-of-byte-ranges) 220

[requesting writing to file or named
pipe](#application-requests-writing-to-a-file-or-named-pipe) 191

[sending any outgoing message](#sending-any-outgoing-message) 169

[signing outgoing message](#signing-an-outgoing-message) 155

[server](#higher-layer-triggered-events-2) 277

[deregistering share](#server-application-deregisters-a-share) 287

[disabling SMB2 server](#server-application-disables-the-smb2-server)
291

[enabling SMB2 server](#server-application-enables-the-smb2-server) 291

[notification that DFS is
active](#dfs-server-notifies-smb2-server-that-dfs-is-active) 284

[notification that share is DFS
share](#dfs-server-notifies-smb2-server-that-a-share-is-a-dfs-share) 284

[notification that share is not DFS
share](#dfs-server-notifies-smb2-server-that-a-share-is-not-a-dfs-share)
284

[object store indicating lease
break](#object-store-indicates-a-lease-break) 283

[object store indicating oplock
break](#object-store-indicates-an-oplock-break) 282

[overview](#higher-layer-triggered-events-2) 277

[querying Open](#server-application-queries-an-open) 290

[querying session](#server-application-queries-a-session) 289

[querying share](#server-application-requests-querying-a-share) 287

[querying TreeConnect](#server-application-queries-a-treeconnect) 290

[registering share](#server-application-registers-a-share) 285

[requesting closing of
open](#server-application-requests-closing-an-open) 288

[requesting closing of
session](#server-application-requests-closing-a-session) 285

[requesting security
context](#server-application-requests-security-context-of-the-client)
284

[requesting server
statistics](#server-application-requests-server-statistics) 291

[requesting session
key](#server-application-requests-session-key-of-the-client) 282

[requesting transport binding
change](#server-application-requests-transport-binding-change) 290

[sending any outgoing message](#sending-any-outgoing-message-1) 277

[sending error response](#sending-an-error-response) 280

[sending interim response for asynchronous
operation](#sending-an-interim-response-for-an-asynchronous-operation)
279

[sending success response](#sending-a-success-response) 280

[signing outgoing message](#signing-an-outgoing-message) 155

[updating share](#server-application-updates-a-share) 286

I

[Idle connection timer](#idle-connection-timer) 168

[Idle connection timer event](#idle-connection-timer-event) 256

[Implementer - security
considerations](#security-considerations-for-implementers) 450

[Incoming message - verifying](#verifying-an-incoming-message) 159

[Index of security parameters](#index-of-security-parameters) 450

[Informative references](#informative-references) 21

Initialization

client ([section 3.1.3](#initialization) 154, [section
3.2.3](#initialization-1) 168)

server ([section 3.1.3](#initialization) 154, [section
3.3.3](#initialization-2) 276)

[Introduction](#introduction) 15

L

[Lease](#per-lease) 271

[Lease table](#per-lease-table) 271

[Leasing algorithm](#algorithm-for-leasing-in-an-object-store) 260

Local events

client ([section 3.1.7](#other-local-events) 161, [section
3.2.7](#other-local-events-1) 257, [section
3.2.7.1](#handling-a-network-disconnect) 257)

server ([section 3.1.7](#other-local-events) 161, [section
3.3.7](#other-local-events-2) 393, [section
3.3.7.1](#handling-loss-of-a-connection) 393)

[Logging off example](#disconnecting-a-share-and-logging-off) 431

M

Message processing

client

[overview](#processing-events-and-sequencing-rules-1) 223

[receiving any message](#receiving-any-message) 223

[receiving SMB2 CHANGE_NOTIFY
response](#receiving-an-smb2-change_notify-response) 252

[receiving SMB2 CLOSE response](#receiving-an-smb2-close-response) 246

[receiving SMB2 CREATE response for new create
operation](#receiving-an-smb2-create-response-for-a-new-create-operation)
242

[receiving SMB2 CREATE response for open
reestablishment](#receiving-an-smb2-create-response-for-an-open-reestablishment)
245

[receiving SMB2 FLUSH response](#receiving-an-smb2-flush-response) 247

[receiving SMB2 IOCTL response](#receiving-an-smb2-ioctl-response) 249

[receiving SMB2 LOCK response](#receiving-an-smb2-lock-response) 248

[receiving SMB2 LOGOFF response](#receiving-an-smb2-logoff-response) 239

[receiving SMB2 NEGOTIATE
response](#receiving-an-smb2-negotiate-response) 227

[receiving SMB2 OPLOCK_BREAK
notification](#receiving-an-smb2-oplock_break-command) 253

[receiving SMB2 QUERY_DIRECTORY
response](#receiving-an-smb2-query_directory-response) 252

[receiving SMB2 QUERY_INFO
response](#receiving-an-smb2-query_info-response) 252

[receiving SMB2 READ response](#receiving-an-smb2-read-response) 247

[receiving SMB2 SESSION_SETUP
response](#receiving-an-smb2-session_setup-response) 232

[receiving SMB2 SET_INFO response](#receiving-an-smb2-set_info-response)
253

[receiving SMB2 TREE_CONNECT
response](#receiving-an-smb2-tree_connect-response) 239

[receiving SMB2 TREE_DISCONNECT
response](#receiving-an-smb2-tree_disconnect-response) 242

[receiving SMB2 WRITE response](#receiving-an-smb2-write-response) 248

[verifying incoming message](#verifying-an-incoming-message) 159

server

[accepting incoming connection](#accepting-an-incoming-connection) 292

[overview](#processing-events-and-sequencing-rules-2) 292

[receiving any message](#receiving-any-message-1) 293

[receiving SMB_COM_NEGOTIATE](#receiving-an-smb_com_negotiate) 302

[receiving SMB2 CANCEL request](#receiving-an-smb2-cancel-request) 375

[receiving SMB2 CHANGE_NOTIFY
request](#receiving-an-smb2-change_notify-request) 378

[receiving SMB2 CLOSE request](#receiving-an-smb2-close-request) 347

[receiving SMB2 CREATE request](#receiving-an-smb2-create-request) 324

[receiving SMB2 ECHO request](#receiving-an-smb2-echo-request) 376

[receiving SMB2 FLUSH request](#receiving-an-smb2-flush-request) 348

[receiving SMB2 IOCTL request](#receiving-an-smb2-ioctl-request) 359

[receiving SMB2 LOCK request](#receiving-an-smb2-lock-request) 356

[receiving SMB2 LOGOFF request](#receiving-an-smb2-logoff-request) 319

[receiving SMB2 NEGOTIATE request](#receiving-an-smb2-negotiate-request)
304

[receiving SMB2 OPLOCK_BREAK
acknowledgment](#receiving-an-smb2-oplock_break-acknowledgment) 389

[receiving SMB2 QUERY_DIRECTORY
request](#receiving-an-smb2-query_directory-request) 376

[receiving SMB2 QUERY_INFO
request](#receiving-an-smb2-query_info-request) 380

[receiving SMB2 READ request](#receiving-an-smb2-read-request) 349

[receiving SMB2 SESSION_SETUP
request](#receiving-an-smb2-session_setup-request) 310

[receiving SMB2 SET_INFO request](#receiving-an-smb2-set_info-request)
386

[receiving SMB2 TREE_CONNECT
request](#receiving-an-smb2-tree_connect-request) 320

[receiving SMB2 TREE_DISCONNECT
request](#receiving-an-smb2-tree_disconnect-request) 324

[receiving SMB2 WRITE request](#receiving-an-smb2-write-request) 352

[verifying incoming message](#verifying-an-incoming-message) 159

Message sequence numbers algorithm ([section
3.2.4.1.6](#algorithm-for-handling-available-message-sequence-numbers-by-the-client)
172, [section
3.3.1.1](#algorithm-for-handling-available-message-sequence-numbers-by-the-server)
258)

Messages

[overview](#messages) 32

[signing outgoing](#signing-an-outgoing-message) 155

[SMB2 CANCEL Request](#smb2-cancel-request) 117

[SMB2 CHANGE_NOTIFY Request](#smb2-change_notify-request) 135

[SMB2 CHANGE_NOTIFY Response](#smb2-change_notify-response) 137

[SMB2 CLOSE Request](#smb2-close-request) 98

[SMB2 CLOSE Response](#smb2-close-response) 99

[SMB2 COMPRESSION_TRANSFORM_HEADER](#smb2-compression_transform_header)
148

[SMB2 CREATE Request](#smb2-create-request) 71

[SMB2 CREATE Response](#smb2-create-response) 89

[SMB2 ECHO Request](#smb2-echo-request) 116

[SMB2 ECHO Response](#smb2-echo-response) 116

[SMB2 ERROR Response](#smb2-error-response) 40

[SMB2 FLUSH Request](#smb2-flush-request) 100

[SMB2 FLUSH Response](#smb2-flush-response) 101

[SMB2 IOCTL Request](#smb2-ioctl-request) 117

[SMB2 IOCTL Response](#smb2-ioctl-response) 123

[SMB2 LOCK Request](#smb2-lock-request) 114

[SMB2 LOCK Response](#smb2-lock-response) 116

[SMB2 LOGOFF Request](#smb2-logoff-request) 61

[SMB2 LOGOFF Response](#smb2-logoff-response) 61

[SMB2 NEGOTIATE Request](#smb2-negotiate-request) 47

[SMB2 NEGOTIATE Response](#smb2-negotiate-response) 54

[SMB2 Packet Header](#smb2-packet-header) 34

[SMB2 QUERY_DIRECTORY Request](#smb2-query_directory-request) 132

[SMB2 QUERY_DIRECTORY Response](#smb2-query_directory-response) 134

[SMB2 QUERY_INFO Request](#smb2-query_info-request) 137

[SMB2 QUERY_INFO Response](#smb2-query_info-response) 142

[SMB2 READ Request](#smb2-read-request) 101

[SMB2 READ Response](#smb2-read-response) 103

[SMB2 SESSION_SETUP Request](#smb2-session_setup-request) 59

[SMB2 SESSION_SETUP Response](#smb2-session_setup-response) 60

[SMB2 SET_INFO Request](#smb2-set_info-request) 143

[SMB2 SET_INFO Response](#smb2-set_info-response) 145

[SMB2 TRANSFORM_HEADER](#smb2-transform_header) 146

[SMB2 TREE_CONNECT Request](#smb2-tree_connect-request) 62

[SMB2 TREE_CONNECT Response](#smb2-tree_connect-response) 68

[SMB2 TREE_DISCONNECT Request](#smb2-tree_disconnect-request) 71

[SMB2 TREE_DISCONNECT Response](#smb2-tree_disconnect-response) 71

[SMB2 WRITE Request](#smb2-write-request) 105

[SMB2 WRITE Response](#smb2-write-response) 107

[SMB2_RDMA_TRANSFORM](#smb2_rdma_transform) 150

[syntax](#message-syntax) 32

[transport](#transport) 32

[verifying incoming](#verifying-an-incoming-message) 159

[Multi-protocol negotiate
example](#connecting-to-a-share-by-using-a-multi-protocol-negotiate) 395

N

[Named pipe example](#executing-an-operation-on-a-named-pipe) 410

[Negotiating SMB 2.10 dialect by using multi-protocol negotiate
example](#negotiating-smb-2.1-dialect-by-using-multi-protocol-negotiate)
400

[Negotiating the protocol](#negotiating-the-protocol) 176

[Network disconnect](#handling-a-network-disconnect) 257

[NETWORK_INTERFACE_INFO_Response
packet](#network_interface_info-response) 129

[NETWORK_RESILIENCY_REQUEST_Request
packet](#network_resiliency_request-request) 122

[Normative references](#normative-references) 19

O

Open ([section 3.2.1.6](#per-application-open-of-a-file) 166, [section
3.3.1.10](#per-open) 268)

[Oplock break acknowledgment timer](#oplock-break-acknowledgment-timer)
275

[Oplock break acknowledgment timer
event](#oplock-break-acknowledgment-timer-event) 392

[Outgoing message - signing](#signing-an-outgoing-message) 155

[Overview (synopsis)](#overview) 23

P

[Parameter index - security](#index-of-security-parameters) 450

[Parameters - security index](#index-of-security-parameters) 450

[Pending request](#per-pending-request) 167

[Pipe - named - example](#executing-an-operation-on-a-named-pipe) 410

[Preconditions](#prerequisitespreconditions) 27

[Prerequisites](#prerequisitespreconditions) 27

[Product behavior](#appendix-a-product-behavior) 451

R

[References](#references) 19

[informative](#informative-references) 21

[normative](#normative-references) 19

[Relationship to other protocols](#relationship-to-other-protocols) 26

Remote files

[reading - example](#reading-from-a-remote-file) 417

[writing - example](#writing-to-a-remote-file) 422

[Request](#per-request) 272

[Request expiration timer](#request-expiration-timer) 168

[Request expiration timer event](#request-expiration-timer-event) 256

[Resilient open scavenger timer](#resilient-open-scavenger-timer) 275

[Resilient open scavenger timer
event](#resilient-open-scavenger-timer-event) 392

S

Security

[implementer considerations](#security-considerations-for-implementers)
450

[overview](#security) 450

[parameter index](#index-of-security-parameters) 450

Sequencing rules

client

[overview](#processing-events-and-sequencing-rules-1) 223

[receiving any message](#receiving-any-message) 223

[receiving SMB2 CHANGE_NOTIFY
response](#receiving-an-smb2-change_notify-response) 252

[receiving SMB2 CLOSE response](#receiving-an-smb2-close-response) 246

[receiving SMB2 CREATE response for new create
operation](#receiving-an-smb2-create-response-for-a-new-create-operation)
242

[receiving SMB2 CREATE response for open
reestablishment](#receiving-an-smb2-create-response-for-an-open-reestablishment)
245

[receiving SMB2 FLUSH response](#receiving-an-smb2-flush-response) 247

[receiving SMB2 IOCTL response](#receiving-an-smb2-ioctl-response) 249

[receiving SMB2 LOCK response](#receiving-an-smb2-lock-response) 248

[receiving SMB2 LOGOFF response](#receiving-an-smb2-logoff-response) 239

[receiving SMB2 NEGOTIATE
response](#receiving-an-smb2-negotiate-response) 227

[receiving SMB2 OPLOCK_BREAK
notification](#receiving-an-smb2-oplock_break-command) 253

[receiving SMB2 QUERY_DIRECTORY
response](#receiving-an-smb2-query_directory-response) 252

[receiving SMB2 QUERY_INFO
response](#receiving-an-smb2-query_info-response) 252

[receiving SMB2 READ response](#receiving-an-smb2-read-response) 247

[receiving SMB2 SESSION_SETUP
response](#receiving-an-smb2-session_setup-response) 232

[receiving SMB2 SET_INFO response](#receiving-an-smb2-set_info-response)
253

[receiving SMB2 TREE_CONNECT
response](#receiving-an-smb2-tree_connect-response) 239

[receiving SMB2 TREE_DISCONNECT
response](#receiving-an-smb2-tree_disconnect-response) 242

[receiving SMB2 WRITE response](#receiving-an-smb2-write-response) 248

[verifying incoming message](#verifying-an-incoming-message) 159

server

[accepting incoming connection](#accepting-an-incoming-connection) 292

[overview](#processing-events-and-sequencing-rules-2) 292

[receiving any message](#receiving-any-message-1) 293

[receiving SMB_COM_NEGOTIATE](#receiving-an-smb_com_negotiate) 302

[receiving SMB2 CANCEL request](#receiving-an-smb2-cancel-request) 375

[receiving SMB2 CHANGE_NOTIFY
request](#receiving-an-smb2-change_notify-request) 378

[receiving SMB2 CLOSE request](#receiving-an-smb2-close-request) 347

[receiving SMB2 CREATE request](#receiving-an-smb2-create-request) 324

[receiving SMB2 ECHO request](#receiving-an-smb2-echo-request) 376

[receiving SMB2 FLUSH request](#receiving-an-smb2-flush-request) 348

[receiving SMB2 IOCTL request](#receiving-an-smb2-ioctl-request) 359

[receiving SMB2 LOCK request](#receiving-an-smb2-lock-request) 356

[receiving SMB2 LOGOFF request](#receiving-an-smb2-logoff-request) 319

[receiving SMB2 NEGOTIATE request](#receiving-an-smb2-negotiate-request)
304

[receiving SMB2 OPLOCK_BREAK
acknowledgment](#receiving-an-smb2-oplock_break-acknowledgment) 389

[receiving SMB2 QUERY_DIRECTORY
request](#receiving-an-smb2-query_directory-request) 376

[receiving SMB2 QUERY_INFO
request](#receiving-an-smb2-query_info-request) 380

[receiving SMB2 READ request](#receiving-an-smb2-read-request) 349

[receiving SMB2 SESSION_SETUP
request](#receiving-an-smb2-session_setup-request) 310

[receiving SMB2 SET_INFO request](#receiving-an-smb2-set_info-request)
386

[receiving SMB2 TREE_CONNECT
request](#receiving-an-smb2-tree_connect-request) 320

[receiving SMB2 TREE_DISCONNECT
request](#receiving-an-smb2-tree_disconnect-request) 324

[receiving SMB2 WRITE request](#receiving-an-smb2-write-request) 352

[verifying incoming message](#verifying-an-incoming-message) 159

Server

abstract data model ([section 3.1.1](#abstract-data-model) 154, [section
3.3.1](#abstract-data-model-2) 258)

[change notifications
algorithm](#algorithm-for-change-notifications-in-an-object-store) 259

[credit granting algorithm](#algorithm-for-the-granting-of-credits) 259

[global structures](#global-2) 261

[higher-layer triggered events](#higher-layer-triggered-events-2) 277

[deregistering share](#server-application-deregisters-a-share) 287

[disabling SMB2 server](#server-application-disables-the-smb2-server)
291

[enabling SMB2 server](#server-application-enables-the-smb2-server) 291

[notification that DFS is
active](#dfs-server-notifies-smb2-server-that-dfs-is-active) 284

[notification that share is DFS
share](#dfs-server-notifies-smb2-server-that-a-share-is-a-dfs-share) 284

[notification that share is not DFS
share](#dfs-server-notifies-smb2-server-that-a-share-is-not-a-dfs-share)
284

[object store indicating lease
break](#object-store-indicates-a-lease-break) 283

[object store indicating oplock
break](#object-store-indicates-an-oplock-break) 282

[overview](#higher-layer-triggered-events-2) 277

[querying Open](#server-application-queries-an-open) 290

[querying session](#server-application-queries-a-session) 289

[querying share](#server-application-requests-querying-a-share) 287

[querying TreeConnect](#server-application-queries-a-treeconnect) 290

[registering share](#server-application-registers-a-share) 285

[requesting closing of
open](#server-application-requests-closing-an-open) 288

[requesting closing of
session](#server-application-requests-closing-a-session) 285

[requesting security
context](#server-application-requests-security-context-of-the-client)
284

[requesting server
statistics](#server-application-requests-server-statistics) 291

[requesting session
key](#server-application-requests-session-key-of-the-client) 282

[requesting transport binding
change](#server-application-requests-transport-binding-change) 290

[sending any outgoing message](#sending-any-outgoing-message-1) 277

[sending error response](#sending-an-error-response) 280

[sending interim response for asynchronous
operation](#sending-an-interim-response-for-an-asynchronous-operation)
279

[sending success response](#sending-a-success-response) 280

[signing outgoing message](#signing-an-outgoing-message) 155

[updating share](#server-application-updates-a-share) 286

initialization ([section 3.1.3](#initialization) 154, [section
3.3.3](#initialization-2) 276)

[leasing algorithm](#algorithm-for-leasing-in-an-object-store) 260

local events ([section 3.1.7](#other-local-events) 161, [section
3.3.7](#other-local-events-2) 393, [section
3.3.7.1](#handling-loss-of-a-connection) 393)

message processing

[accepting incoming connection](#accepting-an-incoming-connection) 292

[overview](#processing-events-and-sequencing-rules-2) 292

[receiving any message](#receiving-any-message-1) 293

[receiving SMB_COM_NEGOTIATE](#receiving-an-smb_com_negotiate) 302

[receiving SMB2 CANCEL request](#receiving-an-smb2-cancel-request) 375

[receiving SMB2 CHANGE_NOTIFY
request](#receiving-an-smb2-change_notify-request) 378

[receiving SMB2 CLOSE request](#receiving-an-smb2-close-request) 347

[receiving SMB2 CREATE request](#receiving-an-smb2-create-request) 324

[receiving SMB2 ECHO request](#receiving-an-smb2-echo-request) 376

[receiving SMB2 FLUSH request](#receiving-an-smb2-flush-request) 348

[receiving SMB2 IOCTL request](#receiving-an-smb2-ioctl-request) 359

[receiving SMB2 LOCK request](#receiving-an-smb2-lock-request) 356

[receiving SMB2 LOGOFF request](#receiving-an-smb2-logoff-request) 319

[receiving SMB2 NEGOTIATE request](#receiving-an-smb2-negotiate-request)
304

[receiving SMB2 OPLOCK_BREAK
acknowledgment](#receiving-an-smb2-oplock_break-acknowledgment) 389

[receiving SMB2 QUERY_DIRECTORY
request](#receiving-an-smb2-query_directory-request) 376

[receiving SMB2 QUERY_INFO
request](#receiving-an-smb2-query_info-request) 380

[receiving SMB2 READ request](#receiving-an-smb2-read-request) 349

[receiving SMB2 SESSION_SETUP
request](#receiving-an-smb2-session_setup-request) 310

[receiving SMB2 SET_INFO request](#receiving-an-smb2-set_info-request)
386

[receiving SMB2 TREE_CONNECT
request](#receiving-an-smb2-tree_connect-request) 320

[receiving SMB2 TREE_DISCONNECT
request](#receiving-an-smb2-tree_disconnect-request) 324

[receiving SMB2 WRITE request](#receiving-an-smb2-write-request) 352

[verifying incoming message](#verifying-an-incoming-message) 159

[message sequence numbers
algorithm](#algorithm-for-handling-available-message-sequence-numbers-by-the-server)
258

[per channel](#per-channel-1) 272

[per lease](#per-lease) 271

[per lease table](#per-lease-table) 271

[per open](#per-open) 268

[per request](#per-request) 272

[per session](#per-session-1) 266

[per share](#per-share-1) 263

[per transport connection](#per-transport-connection) 264

[per tree connect](#per-tree-connect-1) 268

[required global data](#global) 154

sequencing rules

[accepting incoming connection](#accepting-an-incoming-connection) 292

[overview](#processing-events-and-sequencing-rules-2) 292

[receiving any message](#receiving-any-message-1) 293

[receiving SMB_COM_NEGOTIATE](#receiving-an-smb_com_negotiate) 302

[receiving SMB2 CANCEL request](#receiving-an-smb2-cancel-request) 375

[receiving SMB2 CHANGE_NOTIFY
request](#receiving-an-smb2-change_notify-request) 378

[receiving SMB2 CLOSE request](#receiving-an-smb2-close-request) 347

[receiving SMB2 CREATE request](#receiving-an-smb2-create-request) 324

[receiving SMB2 ECHO request](#receiving-an-smb2-echo-request) 376

[receiving SMB2 FLUSH request](#receiving-an-smb2-flush-request) 348

[receiving SMB2 IOCTL request](#receiving-an-smb2-ioctl-request) 359

[receiving SMB2 LOCK request](#receiving-an-smb2-lock-request) 356

[receiving SMB2 LOGOFF request](#receiving-an-smb2-logoff-request) 319

[receiving SMB2 NEGOTIATE request](#receiving-an-smb2-negotiate-request)
304

[receiving SMB2 OPLOCK_BREAK
acknowledgment](#receiving-an-smb2-oplock_break-acknowledgment) 389

[receiving SMB2 QUERY_DIRECTORY
request](#receiving-an-smb2-query_directory-request) 376

[receiving SMB2 QUERY_INFO
request](#receiving-an-smb2-query_info-request) 380

[receiving SMB2 READ request](#receiving-an-smb2-read-request) 349

[receiving SMB2 SESSION_SETUP
request](#receiving-an-smb2-session_setup-request) 310

[receiving SMB2 SET_INFO request](#receiving-an-smb2-set_info-request)
386

[receiving SMB2 TREE_CONNECT
request](#receiving-an-smb2-tree_connect-request) 320

[receiving SMB2 TREE_DISCONNECT
request](#receiving-an-smb2-tree_disconnect-request) 324

[receiving SMB2 WRITE request](#receiving-an-smb2-write-request) 352

[verifying incoming message](#verifying-an-incoming-message) 159

timer events ([section 3.1.6](#timer-events) 160, [section
3.3.6](#timer-events-2) 392, [section
3.3.6.1](#oplock-break-acknowledgment-timer-event) 392)

timers ([section 3.1.2](#timers) 154, [section 3.3.2](#timers-2) 275)

Session ([section 3.2.1.3](#per-session) 164, [section
3.3.1.8](#per-session-1) 266)

[Session expiration timer](#session-expiration-timer) 275

[Session expiration timer event](#session-expiration-timer-event) 392

[Share](#per-share-1) 263

[SMB2 CANCEL Request message](#smb2-cancel-request) 117

[SMB2 CHANGE_NOTIFY Request message](#smb2-change_notify-request) 135

[SMB2 CHANGE_NOTIFY Response message](#smb2-change_notify-response) 137

[SMB2 CLOSE Request message](#smb2-close-request) 98

[SMB2 CLOSE Response message](#smb2-close-response) 99

[SMB2 COMPRESSION_TRANSFORM_HEADER
message](#smb2-compression_transform_header) 148

[SMB2 CREATE Request message](#smb2-create-request) 71

[SMB2 CREATE Response message](#smb2-create-response) 89

[SMB2 ECHO Request message](#smb2-echo-request) 116

[SMB2 ECHO Response message](#smb2-echo-response) 116

[SMB2 ERROR Response message](#smb2-error-response) 40

[SMB2 FLUSH Request message](#smb2-flush-request) 100

[SMB2 FLUSH Response message](#smb2-flush-response) 101

[SMB2 IOCTL Request message](#smb2-ioctl-request) 117

[SMB2 IOCTL Response message](#smb2-ioctl-response) 123

[SMB2 LOCK Request message](#smb2-lock-request) 114

[SMB2 LOCK Request packet](#smb2-lock-request) 114

[SMB2 LOCK Response message](#smb2-lock-response) 116

[SMB2 LOGOFF Request message](#smb2-logoff-request) 61

[SMB2 LOGOFF Response message](#smb2-logoff-response) 61

[SMB2 negotiate
example](#connecting-to-a-share-by-using-an-smb2-negotiate) 405

[SMB2 NEGOTIATE Request message](#smb2-negotiate-request) 47

[SMB2 NEGOTIATE Response message](#smb2-negotiate-response) 54

[SMB2 Packet Header](#smb2-packet-header) 34

[SMB2 Packet Header message](#smb2-packet-header) 34

[SMB2 QUERY_DIRECTORY Request message](#smb2-query_directory-request)
132

[SMB2 QUERY_DIRECTORY Response message](#smb2-query_directory-response)
134

[SMB2 QUERY_INFO Request message](#smb2-query_info-request) 137

[SMB2 QUERY_INFO Response message](#smb2-query_info-response) 142

[SMB2 READ Request message](#smb2-read-request) 101

[SMB2 READ Response message](#smb2-read-response) 103

[SMB2 SESSION_SETUP Request message](#smb2-session_setup-request) 59

[SMB2 SESSION_SETUP Response message](#smb2-session_setup-response) 60

[SMB2 SET_INFO Request message](#smb2-set_info-request) 143

[SMB2 SET_INFO Response message](#smb2-set_info-response) 145

[SMB2 TRANSFORM_HEADER message](#smb2-transform_header) 146

[SMB2 TREE_CONNECT Request message](#smb2-tree_connect-request) 62

[SMB2 TREE_CONNECT Response message](#smb2-tree_connect-response) 68

[SMB2 TREE_DISCONNECT Request message](#smb2-tree_disconnect-request) 71

[SMB2 TREE_DISCONNECT Response message](#smb2-tree_disconnect-response)
71

[SMB2 WRITE Request message](#smb2-write-request) 105

[SMB2 WRITE Response message](#smb2-write-response) 107

[SMB2_CANCEL_Request packet](#smb2-cancel-request) 117

[SMB2_CHANGE_NOTIFY_Request packet](#smb2-change_notify-request) 135

[SMB2_CHANGE_NOTIFY_Response packet](#smb2-change_notify-response) 137

[SMB2_CLOSE_Request packet](#smb2-close-request) 98

[SMB2_CLOSE_Response packet](#smb2-close-response) 99

[SMB2_CREATE_ALLOCATION_SIZE](#smb2_create_allocation_size-1) 94

[SMB2_CREATE_ALLOCATION_SIZE packet](#smb2_create_allocation_size) 83

[SMB2_CREATE_APP_INSTANCE_ID packet](#smb2_create_app_instance_id) 88

[SMB2_CREATE_CONTEXT Response
Values](#smb2_create_context-response-values) 92

[SMB2_CREATE_CONTEXT_Request_Values
packet](#smb2_create_context-request-values) 80

[SMB2_CREATE_DURABLE_HANDLE_RECONNECT](#smb2_create_durable_handle_reconnect-1)
94

[SMB2_CREATE_DURABLE_HANDLE_RECONNECT
packet](#smb2_create_durable_handle_reconnect) 83

[SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2
packet](#smb2_create_durable_handle_reconnect_v2) 87

[SMB2_CREATE_DURABLE_HANDLE_REQUEST
packet](#smb2_create_durable_handle_request) 82

[SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2
packet](#smb2_create_durable_handle_request_v2) 86

[SMB2_CREATE_DURABLE_HANDLE_RESPONSE
packet](#smb2_create_durable_handle_response) 93

[SMB2_CREATE_DURABLE_HANDLE_RESPONSE_V2
packet](#smb2_create_durable_handle_response_v2) 97

[SMB2_CREATE_EA_BUFFER](#smb2_create_ea_buffer-1) 93

[SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST
packet](#smb2_create_query_maximal_access_request) 83

[SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE
packet](#smb2_create_query_maximal_access_response) 94

[SMB2_CREATE_QUERY_ON_DISK_ID](#smb2_create_query_on_disk_id) 85

[SMB2_CREATE_QUERY_ON_DISK_ID packet](#smb2_create_query_on_disk_id-1)
94

[SMB2_CREATE_Request packet](#smb2-create-request) 71

[SMB2_CREATE_REQUEST_LEASE packet](#smb2_create_request_lease) 84

[SMB2_CREATE_REQUEST_LEASE_V2 packet](#smb2_create_request_lease_v2) 85

[SMB2_CREATE_Response packet](#smb2-create-response) 89

[SMB2_CREATE_RESPONSE_LEASE packet](#smb2_create_response_lease) 95

[SMB2_CREATE_RESPONSE_LEASE_V2 packet](#smb2_create_response_lease_v2)
96

[SMB2_CREATE_SD_BUFFER](#smb2_create_sd_buffer-1) 93

[SMB2_CREATE_TIMEWARP_TOKEN](#smb2_create_timewarp_token-1) 94

[SMB2_CREATE_TIMEWARP_TOKEN packet](#smb2_create_timewarp_token) 83

[SMB2_ECHO_Request packet](#smb2-echo-request) 116

[SMB2_ECHO_Response packet](#smb2-echo-response) 116

[SMB2_ENCRYPTION_CAPABILITIES packet](#smb2_encryption_capabilities) 51

[SMB2_ERROR_Response packet](#smb2-error-response) 40

[SMB2_FILEID packet](#smb2_fileid) 92

[SMB2_FLUSH_Request packet](#smb2-flush-request) 100

[SMB2_FLUSH_Response packet](#smb2-flush-response) 101

[SMB2_IOCTL_Request packet](#smb2-ioctl-request) 117

[SMB2_IOCTL_Response packet](#smb2-ioctl-response) 123

[SMB2_Lease_Break_Acknowledgment packet](#lease-break-acknowledgment)
111

[SMB2_Lease_Break_Notification packet](#lease-break-notification) 108

[SMB2_Lease_Break_Response packet](#lease-break-response) 113

[SMB2_LOCK_ELEMENT packet](#smb2_lock_element-structure) 115

[SMB2_LOCK_Request packet](#smb2-lock-request) 114

[SMB2_LOCK_Response packet](#smb2-lock-response) 116

[SMB2_LOGOFF_Request packet](#smb2-logoff-request) 61

[SMB2_LOGOFF_Response packet](#smb2-logoff-response) 61

[SMB2_NEGOTIATE_CONTEXT_Request_Values
packet](#smb2-negotiate_context-request-values) 49

[SMB2_NEGOTIATE_Request packet](#smb2-negotiate-request) 47

[SMB2_NEGOTIATE_Response packet](#smb2-negotiate-response) 54

[SMB2_Oplock_Break_Acknowledgment packet](#oplock-break-acknowledgment)
110

[SMB2_Oplock_Break_Notification packet](#oplock-break-notification) 107

[SMB2_Oplock_Break_Response packet](#oplock-break-response) 112

[SMB2_Packet_Header_ASYNC packet](#smb2-packet-header---async) 34

[SMB2_Packet_Header_SYNC packet](#smb2-packet-header---sync) 37

[SMB2_Packet_Transport packet](#transport) 32

[SMB2_PREAUTH_INTEGRITY_CAPABILITIES
packet](#smb2_preauth_integrity_capabilities) 50

[SMB2_QUERY_DIRECTORY_Request packet](#smb2-query_directory-request) 132

[SMB2_QUERY_DIRECTORY_Response packet](#smb2-query_directory-response)
134

[SMB2_QUERY_INFO_Request packet](#smb2-query_info-request) 137

[SMB2_QUERY_INFO_Response packet](#smb2-query_info-response) 142

[SMB2_QUERY_QUOTA_INFO packet](#smb2_query_quota_info) 141

[SMB2_RDMA_TRANSFORM message](#smb2_rdma_transform) 150

[SMB2_READ_Request packet](#smb2-read-request) 101

[SMB2_READ_Response packet](#smb2-read-response) 103

[SMB2_SESSION_SETUP_Request packet](#smb2-session_setup-request) 59

[SMB2_SESSION_SETUP_Response packet](#smb2-session_setup-response) 60

[SMB2_SET_INFO_Request packet](#smb2-set_info-request) 143

[SMB2_SET_INFO_Response packet](#smb2-set_info-response) 145

[SMB2_TRANSFORM_HEADER packet](#smb2-transform_header) 146

[SMB2_TREE_CONNECT_Request packet](#smb2-tree_connect-request) 62

[SMB2_TREE_CONNECT_Response packet](#smb2-tree_connect-response) 68

[SMB2_TREE_DISCONNECT_Request packet](#smb2-tree_disconnect-request) 71

[SMB2_TREE_DISCONNECT_Response packet](#smb2-tree_disconnect-response)
71

[SMB2_WRITE_Request packet](#smb2-write-request) 105

[SMB2_WRITE_Response packet](#smb2-write-response) 107

[SOCKADDR_IN packet](#sockaddr_in) 131

[SOCKADDR_IN6 packet](#sockaddr_in6) 131

[SOCKADDR_STORAGE packet](#sockaddr_storage) 130

[SRV_COPYCHUNK packet](#srv_copychunk) 120

[SRV_COPYCHUNK_COPY packet](#srv_copychunk_copy) 119

[SRV_COPYCHUNK_RESPONSE packet](#srv_copychunk_response) 124

[SRV_HASH_RETRIEVE_FILE_BASED_Response
packet](#srv_hash_retrieve_file_based) 128

[SRV_READ_HASH packet](#srv_read_hash-request) 121

[SRV_READ_HASH response](#srv_read_hash-response) 126

[SRV_READ_HASH_Response packet](#srv_hash_retrieve_hash_based) 128

[SRV_REQUEST_RESUME_KEY_Response
packet](#srv_request_resume_key-response) 126

[SRV_SNAPSHOT_ARRAY packet](#srv_snapshot_array) 125

[Standards assignments](#standards-assignments) 30

[Symbolic_Link_Error_Response packet](#symbolic-link-error-response) 42

[Syntax](#message-syntax) 32

T

Timer events

client ([section 3.1.6](#timer-events) 160, [section
3.2.6](#timer-events-1) 256)

server ([section 3.1.6](#timer-events) 160, [section
3.3.6](#timer-events-2) 392, [section
3.3.6.1](#oplock-break-acknowledgment-timer-event) 392)

Timers

client ([section 3.1.2](#timers) 154, [section 3.2.2](#timers-1) 168)

server ([section 3.1.2](#timers) 154, [section 3.3.2](#timers-2) 275)

[Tracking changes](#change-tracking) 492

[Transport](#transport) 32

[connection](#per-transport-connection) 264

[disconnect](#handling-loss-of-a-connection) 393

[messages](#transport) 32

[Transport connection](#per-smb2-transport-connection) 162

Tree connect ([section 3.2.1.4](#per-tree-connect) 165, [section
3.3.1.9](#per-tree-connect-1) 268)

Triggered events – higher layer

client

[notifying offline status of
server](#application-notifies-offline-status-of-a-server) 222

[notifying online status of
server](#application-notifies-online-status-of-a-server) 223

[overview](#higher-layer-triggered-events-1) 169

[re-establishing a durable open](#re-establishing-a-durable-open) 187

[requesting applying of file
attributes](#application-requests-applying-file-attributes) 195

[requesting applying of file security
attributes](#application-requests-applying-file-security) 198

[requesting applying of file system
attributes](#application-requests-applying-file-system-attributes) 196

[requesting applying of quota
information](#application-requests-applying-quota-information) 200

[requesting cancellation of
operation](#application-requests-canceling-an-operation) 221

[requesting change of notifications for
directory](#application-requests-change-notifications-for-a-directory)
203

[requesting closing of file or named
pipe](#application-requests-closing-a-file-or-named-pipe) 188

[requesting closing of share
connection](#application-requests-closing-a-share-connection) 221

[requesting connection to
share](#application-requests-a-connection-to-a-share) 173

[requesting enumeration of
directory](#application-requests-enumerating-a-directory) 202

[requesting flushing of cached
data](#application-requests-flushing-cached-data) 201

[requesting IO control code
operation](#application-requests-an-io-control-code-operation) 205

[requesting locking of array of byte
ranges](#application-requests-locking-of-an-array-of-byte-ranges) 204

[requesting move to server
instance](#application-requests-moving-to-a-server-instance) 223

[requesting number of opens on tree
connect](#application-requests-number-of-opens-on-a-tree-connect) 222

[requesting opening of file](#application-requests-opening-a-file) 182

[requesting querying for file
attributes](#application-requests-querying-file-attributes) 193

[requesting querying for file security
attributes](#application-requests-querying-file-security) 197

[requesting querying for file system
attributes](#application-requests-querying-file-system-attributes) 196

[requesting querying for quota
information](#application-requests-querying-quota-information) 199

[requesting reading from file or named
pipe](#application-requests-reading-from-a-file-or-named-pipe) 189

[requesting session key for authenticated
context](#application-requests-the-session-key-for-an-authenticated-context)
222

[requesting termination of authenticated
context](#application-requests-terminating-an-authenticated-context) 221

[requesting unlocking of array of byte
ranges](#application-requests-unlocking-of-an-array-of-byte-ranges) 220

[requesting writing to file or named
pipe](#application-requests-writing-to-a-file-or-named-pipe) 191

[sending any outgoing message](#sending-any-outgoing-message) 169

[signing outgoing message](#signing-an-outgoing-message) 155

server

[deregistering share](#server-application-deregisters-a-share) 287

[disabling SMB2 server](#server-application-disables-the-smb2-server)
291

[enabling SMB2 server](#server-application-enables-the-smb2-server) 291

[notification that DFS is
active](#dfs-server-notifies-smb2-server-that-dfs-is-active) 284

[notification that share is DFS
share](#dfs-server-notifies-smb2-server-that-a-share-is-a-dfs-share) 284

[notification that share is not DFS
share](#dfs-server-notifies-smb2-server-that-a-share-is-not-a-dfs-share)
284

[object store indicating lease
break](#object-store-indicates-a-lease-break) 283

[object store indicating oplock
break](#object-store-indicates-an-oplock-break) 282

[overview](#higher-layer-triggered-events-2) 277

[querying Open](#server-application-queries-an-open) 290

[querying session](#server-application-queries-a-session) 289

[querying share](#server-application-requests-querying-a-share) 287

[querying TreeConnect](#server-application-queries-a-treeconnect) 290

[registering share](#server-application-registers-a-share) 285

[requesting closing of
open](#server-application-requests-closing-an-open) 288

[requesting closing of
session](#server-application-requests-closing-a-session) 285

[requesting security
context](#server-application-requests-security-context-of-the-client)
284

[requesting server
statistics](#server-application-requests-server-statistics) 291

[requesting session
key](#server-application-requests-session-key-of-the-client) 282

[requesting transport binding
change](#server-application-requests-transport-binding-change) 290

[sending any outgoing message](#sending-any-outgoing-message-1) 277

[sending error response](#sending-an-error-response) 280

[sending interim response for asynchronous
operation](#sending-an-interim-response-for-an-asynchronous-operation)
279

[sending success response](#sending-a-success-response) 280

[signing outgoing message](#signing-an-outgoing-message) 155

[updating share](#server-application-updates-a-share) 286

Triggered events - higher-layer

[client](#higher-layer-triggered-events-1) 169

[server](#higher-layer-triggered-events-2) 277

U

[Unique open file](#per-open-file) 165

V

[VALIDATE_NEGOTIATE_INFO_Request
packet](#validate_negotiate_info-request) 122

[VALIDATE_NEGOTIATE_INFO_Response
packet](#validate_negotiate_info-response) 132

[Vendor-extensible fields](#vendor-extensible-fields) 30

[Versioning](#versioning-and-capability-negotiation) 28
