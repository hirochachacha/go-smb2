package smb2

type (
	Client           = Session  // deprecated type name
	RemoteFileSystem = Share    // deprecated type name
	RemoteFile       = File     // deprecated type name
	RemoteFileStat   = FileStat // deprecated type name
)

const MaxReadSizeLimit = 0x100000 // deprecated constant
