package notify

import (
	"testing"

	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

func TestFilterConstants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		got  Filter
		want uint32
	}{
		{"FileName", FileName, wire.FILE_NOTIFY_CHANGE_FILE_NAME},
		{"DirName", DirName, wire.FILE_NOTIFY_CHANGE_DIR_NAME},
		{"Attributes", Attributes, wire.FILE_NOTIFY_CHANGE_ATTRIBUTES},
		{"Size", Size, wire.FILE_NOTIFY_CHANGE_SIZE},
		{"LastWrite", LastWrite, wire.FILE_NOTIFY_CHANGE_LAST_WRITE},
		{"LastAccess", LastAccess, wire.FILE_NOTIFY_CHANGE_LAST_ACCESS},
		{"Creation", Creation, wire.FILE_NOTIFY_CHANGE_CREATION},
		{"EA", EA, wire.FILE_NOTIFY_CHANGE_EA},
		{"Security", Security, wire.FILE_NOTIFY_CHANGE_SECURITY},
		{"StreamName", StreamName, wire.FILE_NOTIFY_CHANGE_STREAM_NAME},
		{"StreamSize", StreamSize, wire.FILE_NOTIFY_CHANGE_STREAM_SIZE},
		{"StreamWrite", StreamWrite, wire.FILE_NOTIFY_CHANGE_STREAM_WRITE},
	}

	for _, tt := range tests {
		if uint32(tt.got) != tt.want {
			t.Errorf("Filter %s = %d, want %d", tt.name, tt.got, tt.want)
		}
	}
}

func TestActionConstants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		got  Action
		want uint32
	}{
		{"Added", Added, wire.FILE_ACTION_ADDED},
		{"Removed", Removed, wire.FILE_ACTION_REMOVED},
		{"Modified", Modified, wire.FILE_ACTION_MODIFIED},
		{"RenamedOldName", RenamedOldName, wire.FILE_ACTION_RENAMED_OLD_NAME},
		{"RenamedNewName", RenamedNewName, wire.FILE_ACTION_RENAMED_NEW_NAME},
		{"AddedStream", AddedStream, wire.FILE_ACTION_ADDED_STREAM},
		{"RemovedStream", RemovedStream, wire.FILE_ACTION_REMOVED_STREAM},
		{"ModifiedStream", ModifiedStream, wire.FILE_ACTION_MODIFIED_STREAM},
		{"RemovedByDelete", RemovedByDelete, wire.FILE_ACTION_REMOVED_BY_DELETE},
		{"IDNotTunnelled", IDNotTunnelled, wire.FILE_ACTION_ID_NOT_TUNNELLED},
		{"TunnelledIDCollision", TunnelledIDCollision, wire.FILE_ACTION_TUNNELLED_ID_COLLISION},
	}

	for _, tt := range tests {
		if uint32(tt.got) != tt.want {
			t.Errorf("Action %s = %d, want %d", tt.name, tt.got, tt.want)
		}
	}
}

func TestEventAndResultTypes(t *testing.T) {
	t.Parallel()

	ev := Event{Action: Added, Name: "file.txt"}
	if ev.Action != Added || ev.Name != "file.txt" {
		t.Fatalf("unexpected Event values: %+v", ev)
	}

	res := Result{
		Events:         []Event{ev},
		RescanRequired: false,
	}
	if len(res.Events) != 1 || res.RescanRequired {
		t.Fatalf("unexpected Result values: %+v", res)
	}
}
