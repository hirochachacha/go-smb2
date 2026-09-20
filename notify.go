package smb2

import (
	"context"
	"os"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/notify"
)

const changeFilterMask = notify.FileName | notify.DirName |
	notify.Attributes | notify.Size | notify.LastWrite |
	notify.LastAccess | notify.Creation | notify.EA |
	notify.Security | notify.StreamName | notify.StreamSize |
	notify.StreamWrite

// WaitForChange waits for one directory change notification. The server fixes
// the completion filter and watch mode from the first CHANGE_NOTIFY request on
// the open and ignores them in later requests ([MS-SMB2] 3.3.1.3); use another
// Open for a different monitor. A canceled call can consume a notification, and
// the server does not provide a complete change history, so callers must issue
// another call when they want to continue monitoring.
func (f *File) WaitForChange(ctx context.Context, filter notify.Filter, recursive bool) (notify.Result, error) {
	if ctx == nil {
		panic("nil context")
	}

	var result notify.Result
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
		return notify.Result{RescanRequired: true}, nil
	}

	if len(r.Output()) == 0 {
		return notify.Result{RescanRequired: true}, nil
	}

	entries, err := r.FileNotifyInformation()
	if err != nil {
		return result, &os.PathError{Op: "wait for change", Path: f.name, Err: err}
	}
	events := make([]notify.Event, 0, len(entries))
	for _, e := range entries {
		events = append(events, notify.Event{Action: notify.Action(e.Action()), Name: e.FileName()})
	}
	return notify.Result{Events: events}, nil
}
