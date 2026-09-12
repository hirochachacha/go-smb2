package smb2

import (
	"context"
	"os"
	"strings"

	"github.com/hirochachacha/go-smb2/internal/erref"
	"github.com/hirochachacha/go-smb2/internal/smb2"
)

// ChangeFilter selects the directory changes reported by WaitForChange.
type ChangeFilter uint32

const (
	ChangeFileName    ChangeFilter = smb2.FILE_NOTIFY_CHANGE_FILE_NAME
	ChangeDirName     ChangeFilter = smb2.FILE_NOTIFY_CHANGE_DIR_NAME
	ChangeAttributes  ChangeFilter = smb2.FILE_NOTIFY_CHANGE_ATTRIBUTES
	ChangeSize        ChangeFilter = smb2.FILE_NOTIFY_CHANGE_SIZE
	ChangeLastWrite   ChangeFilter = smb2.FILE_NOTIFY_CHANGE_LAST_WRITE
	ChangeLastAccess  ChangeFilter = smb2.FILE_NOTIFY_CHANGE_LAST_ACCESS
	ChangeCreation    ChangeFilter = smb2.FILE_NOTIFY_CHANGE_CREATION
	ChangeEA          ChangeFilter = smb2.FILE_NOTIFY_CHANGE_EA
	ChangeSecurity    ChangeFilter = smb2.FILE_NOTIFY_CHANGE_SECURITY
	ChangeStreamName  ChangeFilter = smb2.FILE_NOTIFY_CHANGE_STREAM_NAME
	ChangeStreamSize  ChangeFilter = smb2.FILE_NOTIFY_CHANGE_STREAM_SIZE
	ChangeStreamWrite ChangeFilter = smb2.FILE_NOTIFY_CHANGE_STREAM_WRITE
)

const changeFilterMask = ChangeFileName | ChangeDirName |
	ChangeAttributes | ChangeSize | ChangeLastWrite |
	ChangeLastAccess | ChangeCreation | ChangeEA |
	ChangeSecurity | ChangeStreamName | ChangeStreamSize |
	ChangeStreamWrite

// ChangeAction identifies the change described by a ChangeEvent.
type ChangeAction uint32

const (
	ChangeActionAdded                ChangeAction = smb2.FILE_ACTION_ADDED
	ChangeActionRemoved              ChangeAction = smb2.FILE_ACTION_REMOVED
	ChangeActionModified             ChangeAction = smb2.FILE_ACTION_MODIFIED
	ChangeActionRenamedOldName       ChangeAction = smb2.FILE_ACTION_RENAMED_OLD_NAME
	ChangeActionRenamedNewName       ChangeAction = smb2.FILE_ACTION_RENAMED_NEW_NAME
	ChangeActionAddedStream          ChangeAction = smb2.FILE_ACTION_ADDED_STREAM
	ChangeActionRemovedStream        ChangeAction = smb2.FILE_ACTION_REMOVED_STREAM
	ChangeActionModifiedStream       ChangeAction = smb2.FILE_ACTION_MODIFIED_STREAM
	ChangeActionRemovedByDelete      ChangeAction = smb2.FILE_ACTION_REMOVED_BY_DELETE
	ChangeActionIDNotTunnelled       ChangeAction = smb2.FILE_ACTION_ID_NOT_TUNNELLED
	ChangeActionTunnelledIDCollision ChangeAction = smb2.FILE_ACTION_TUNNELLED_ID_COLLISION
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

type notifyState struct {
	filter    ChangeFilter
	recursive bool
	set       bool
	active    bool
}

// WaitForChange waits for one directory change notification. The first valid
// call fixes filter and recursive for this File; use another Open for a
// different monitor. A canceled call can consume a notification, and the
// server does not provide a complete change history, so callers must issue
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

	f.m.Lock()
	if f.notify == nil {
		f.notify = &notifyState{}
	}
	if f.notify.active || (f.notify.set && (f.notify.filter != filter || f.notify.recursive != recursive)) {
		f.m.Unlock()
		return result, os.ErrInvalid
	}
	if !f.notify.set {
		f.notify.filter = filter
		f.notify.recursive = recursive
		f.notify.set = true
	}
	f.notify.active = true
	f.m.Unlock()
	defer func() {
		f.m.Lock()
		f.notify.active = false
		f.m.Unlock()
	}()

	outputBufferLength := uint32(min(64*1024, f.fs.maxTransactSize(0)))
	res, err := f.fs.request().withFileId(f.fd).
		changeNotify(uint32(filter), recursive, outputBufferLength).
		sendRecv(ctx)
	if err != nil {
		return result, &os.PathError{Op: "wait for change", Path: f.name, Err: err}
	}
	defer res.close()

	status := erref.NtStatus(res.packet(0).codec().Status())
	r := smb2.ChangeNotifyResponseDecoder(res.data(0))
	if status == erref.STATUS_NOTIFY_ENUM_DIR {
		if r.IsInvalid() || r.OutputBufferLength() != 0 {
			return result, &os.PathError{Op: "wait for change", Path: f.name, Err: &InvalidResponseError{"broken change notify response format"}}
		}
		return ChangeResult{RescanRequired: true}, nil
	}

	if r.IsInvalid() || r.OutputBufferLength() > outputBufferLength {
		return result, &os.PathError{Op: "wait for change", Path: f.name, Err: &InvalidResponseError{"broken change notify response format"}}
	}
	output := r.OutputBuffer()
	if len(output) == 0 {
		return ChangeResult{RescanRequired: true}, nil
	}

	events := make([]ChangeEvent, 0, 1)
	for len(output) > 0 {
		e := smb2.FileNotifyInformationDecoder(output)
		if e.IsInvalid() {
			return result, &os.PathError{Op: "wait for change", Path: f.name, Err: &InvalidResponseError{"broken file notify information format"}}
		}
		name := e.FileName()
		// [MS-SMB2] 3.2.5.16 rejects rooted names, quotes, and path
		// separators for a non-recursive watch; names remain relative.
		if strings.HasPrefix(name, "/") || strings.HasPrefix(name, `\`) || strings.Contains(name, `"`) || (!recursive && strings.ContainsAny(name, `/\`)) {
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
