// Package directory shares SMB directory enumeration between filesystem layers.
package directory

import (
	"context"
	"errors"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

const bufferSize = 64 * 1024

// Reader owns a directory handle opened for candidate enumeration.
type Reader struct {
	request func() *protocol.Request
	id      wire.FileId
}

// Open follows links and opens dir on the supplied share. Resolution errors
// are returned before enumeration, so the client can follow DFS referrals.
func Open(ctx context.Context, request func() *protocol.Request, dir string) (*Reader, error) {
	res, err := request().WithFollowSymlinks(true).
		Create(dir, wire.FILE_LIST_DIRECTORY|wire.FILE_READ_ATTRIBUTES|wire.READ_CONTROL|wire.SYNCHRONIZE,
			wire.FILE_OPEN, wire.FILE_DIRECTORY_FILE, wire.FILE_ATTRIBUTE_NORMAL).Do(ctx)
	if err != nil {
		return nil, err
	}
	defer res.Close()
	created, err := res.Create(0)
	if err != nil {
		return nil, err
	}
	return &Reader{request: request, id: created.FileId().Decode()}, nil
}

// Close releases only the handle created by Open, even if enumeration was canceled.
func (r *Reader) Close() error {
	res, err := r.request().WithFileID(r.id).Close().Do(context.Background())
	if err != nil {
		return err
	}
	res.Close()
	return nil
}

// Names returns candidate basenames without glob matching or sorting.
func (r *Reader) Names(ctx context.Context, pattern string) ([]string, error) {
	var names []string
	for {
		page, err := ReadPage(ctx, r.request, r.id, pattern, func(entry wire.FileIdBothDirectoryInformationDecoder) string { return entry.FileName() })
		names = append(names, page...)
		if errors.Is(err, erref.STATUS_NO_MORE_FILES) || errors.Is(err, erref.STATUS_NO_SUCH_FILE) {
			return names, nil
		}
		if err != nil {
			return nil, err
		}
		if len(page) == 0 {
			return names, nil
		}
	}
}

// ReadPage decodes one non-dot page from an existing handle. Decode runs while
// response storage is valid; its result must not retain borrowed byte slices.
func ReadPage[T any](ctx context.Context, request func() *protocol.Request, id wire.FileId, pattern string, decode func(wire.FileIdBothDirectoryInformationDecoder) T) ([]T, error) {
	for dotPages := 0; dotPages < 3; dotPages++ {
		res, err := request().WithFileID(id).QueryDir(wire.FileIdBothDirectoryInformation, pattern, bufferSize).Do(ctx)
		if err != nil {
			return nil, err
		}
		page, err := decodePage(res, decode)
		if err != nil {
			return nil, err
		}
		if page != nil {
			return page, nil
		}
	}
	return nil, errors.New("query directory returned only dot entries")
}

func decodePage[T any](res *protocol.Response, decode func(wire.FileIdBothDirectoryInformationDecoder) T) ([]T, error) {
	defer res.Close()
	query, err := res.QueryDir(0)
	if err != nil {
		return nil, err
	}
	entries, err := query.FileIdBothDirectoryInformation()
	if err != nil {
		return nil, err
	}
	page := make([]T, 0, len(entries))
	for _, entry := range entries {
		if !wire.IsDotDirectoryName(entry.FileNameBytes()) {
			page = append(page, decode(entry))
		}
	}
	if len(entries) > 0 && len(page) == 0 {
		return nil, nil
	}
	return page, nil
}
