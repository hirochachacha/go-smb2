package smb2

import (
	"context"
	"os"
	"strings"

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

	res, err := f.fs.request().withFileId(f.fd).
		changeNotify(uint32(filter), recursive, maxSingleCreditPayloadSize).
		sendRecv(ctx)
	if err != nil {
		return result, &os.PathError{Op: "wait for change", Path: f.name, Err: err}
	}
	defer res.close()

	status := erref.NtStatus(res.packet(0).codec().Status())
	r := wire.ChangeNotifyResponseDecoder(res.data(0))
	if r.IsInvalid() {
		return result, &os.PathError{Op: "wait for change", Path: f.name, Err: &InvalidResponseError{"broken change notify response format"}}
	}
	output := r.Output()
	if uint32(len(output)) > maxSingleCreditPayloadSize {
		return result, &os.PathError{Op: "wait for change", Path: f.name, Err: &InvalidResponseError{"broken change notify response format"}}
	}

	if status == erref.STATUS_NOTIFY_ENUM_DIR {
		if len(output) != 0 {
			return result, &os.PathError{Op: "wait for change", Path: f.name, Err: &InvalidResponseError{"broken change notify response format"}}
		}
		return ChangeResult{RescanRequired: true}, nil
	}

	if len(output) == 0 {
		return ChangeResult{RescanRequired: true}, nil
	}

	events := make([]ChangeEvent, 0, 1)
	for len(output) > 0 {
		e := wire.FileNotifyInformationDecoder(output)
		if e.IsInvalid() {
			return result, &os.PathError{Op: "wait for change", Path: f.name, Err: &InvalidResponseError{"broken file notify information format"}}
		}
		name := e.FileName()
		// [MS-SMB2] 3.2.5.16 rejects path separators for a non-recursive watch.
		if !recursive && strings.ContainsAny(name, `/\`) {
			return result, &os.PathError{Op: "wait for change", Path: f.name, Err: &InvalidResponseError{"invalid file notify information name"}}
		}
		events = append(events, ChangeEvent{Action: ChangeAction(e.Action()), Name: name})
		next := e.NextEntryOffset()
		if next == 0 {
			break
		}
		output = output[next:]
	}

	return ChangeResult{Events: events}, nil
}
