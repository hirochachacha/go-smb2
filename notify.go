package smb2

import (
	"context"
	"os"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

// ChangeFilter selects the directory changes reported by WaitForChange.
type ChangeFilter uint32

const (
	ChangeFileName    ChangeFilter = wire.FILE_NOTIFY_CHANGE_FILE_NAME
	ChangeDirName     ChangeFilter = wire.FILE_NOTIFY_CHANGE_DIR_NAME
	ChangeAttributes  ChangeFilter = wire.FILE_NOTIFY_CHANGE_ATTRIBUTES
	ChangeSize        ChangeFilter = wire.FILE_NOTIFY_CHANGE_SIZE
	ChangeLastWrite   ChangeFilter = wire.FILE_NOTIFY_CHANGE_LAST_WRITE
	ChangeLastAccess  ChangeFilter = wire.FILE_NOTIFY_CHANGE_LAST_ACCESS
	ChangeCreation    ChangeFilter = wire.FILE_NOTIFY_CHANGE_CREATION
	ChangeEA          ChangeFilter = wire.FILE_NOTIFY_CHANGE_EA
	ChangeSecurity    ChangeFilter = wire.FILE_NOTIFY_CHANGE_SECURITY
	ChangeStreamName  ChangeFilter = wire.FILE_NOTIFY_CHANGE_STREAM_NAME
	ChangeStreamSize  ChangeFilter = wire.FILE_NOTIFY_CHANGE_STREAM_SIZE
	ChangeStreamWrite ChangeFilter = wire.FILE_NOTIFY_CHANGE_STREAM_WRITE
)

const changeFilterMask = ChangeFileName | ChangeDirName |
	ChangeAttributes | ChangeSize | ChangeLastWrite |
	ChangeLastAccess | ChangeCreation | ChangeEA |
	ChangeSecurity | ChangeStreamName | ChangeStreamSize |
	ChangeStreamWrite

// ChangeAction identifies the change described by a ChangeEvent.
type ChangeAction uint32

const (
	ChangeActionAdded                ChangeAction = wire.FILE_ACTION_ADDED
	ChangeActionRemoved              ChangeAction = wire.FILE_ACTION_REMOVED
	ChangeActionModified             ChangeAction = wire.FILE_ACTION_MODIFIED
	ChangeActionRenamedOldName       ChangeAction = wire.FILE_ACTION_RENAMED_OLD_NAME
	ChangeActionRenamedNewName       ChangeAction = wire.FILE_ACTION_RENAMED_NEW_NAME
	ChangeActionAddedStream          ChangeAction = wire.FILE_ACTION_ADDED_STREAM
	ChangeActionRemovedStream        ChangeAction = wire.FILE_ACTION_REMOVED_STREAM
	ChangeActionModifiedStream       ChangeAction = wire.FILE_ACTION_MODIFIED_STREAM
	ChangeActionRemovedByDelete      ChangeAction = wire.FILE_ACTION_REMOVED_BY_DELETE
	ChangeActionIDNotTunnelled       ChangeAction = wire.FILE_ACTION_ID_NOT_TUNNELLED
	ChangeActionTunnelledIDCollision ChangeAction = wire.FILE_ACTION_TUNNELLED_ID_COLLISION
)

// ChangeEvent is one directory change. Name is relative to the monitored
// directory and is not normalized or joined with the File name.
type ChangeEvent struct {
	Action ChangeAction
	Name   string
}

// ChangeResult is the result of one WaitForChange request. A canceled
// request may have consumed a server notification, and notification results
// do not guarantee a complete change history; callers issue the next request
// when they want to continue monitoring.
type ChangeResult struct {
	Events         []ChangeEvent
	RescanRequired bool
}

// WaitForChange waits for one directory change notification. The server fixes
// the completion filter and watch mode from the first CHANGE_NOTIFY request on
// the open and ignores them in later requests ([MS-SMB2] 3.3.1.3); use another
// Open for a different monitor. A canceled call can consume a notification, and
// the server does not provide a complete change history, so callers must issue
// another call when they want to continue monitoring.
func (f *File) WaitForChange(ctx context.Context, filter ChangeFilter, recursive bool) (ChangeResult, error) {
	if ctx == nil {
		panic("nil context")
	}

	var result ChangeResult
	if err := f.checkValid(); err != nil {
		return result, err
	}
	if !f.isDir || filter == 0 || filter&^changeFilterMask != 0 {
		return result, os.ErrInvalid
	}

	res, err := f.fs.Request().WithFollowSymlinks(true).WithFileID(f.fd).
		ChangeNotify(uint32(filter), recursive, maxSingleCreditPayloadSize).
		Do(ctx)
	if err != nil {
		return result, &os.PathError{Op: "wait for change", Path: f.name, Err: err}
	}
	defer res.Close()

	header, err := res.Header(0)
	if err != nil {
		return result, &os.PathError{Op: "wait for change", Path: f.name, Err: err}
	}
	status := erref.NtStatus(header.Status())
	r, err := res.ChangeNotify(0)
	if err != nil {
		return result, &os.PathError{Op: "wait for change", Path: f.name, Err: err}
	}
	if status == erref.STATUS_NOTIFY_ENUM_DIR {
		return ChangeResult{RescanRequired: true}, nil
	}

	if len(r.Output()) == 0 {
		return ChangeResult{RescanRequired: true}, nil
	}

	entries, err := r.FileNotifyInformation()
	if err != nil {
		return result, &os.PathError{Op: "wait for change", Path: f.name, Err: err}
	}
	events := make([]ChangeEvent, 0, len(entries))
	for _, e := range entries {
		events = append(events, ChangeEvent{Action: ChangeAction(e.Action()), Name: e.FileName()})
	}
	return ChangeResult{Events: events}, nil
}
