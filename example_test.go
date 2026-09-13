package smb2_test

import (
	"context"
	"fmt"
	"io"

	"github.com/hirochachacha/go-smb2/v2"
)

func Example() {
	client, err := smb2.NewClient(smb2.ClientConfig{
		Credentials: smb2.NTLMCredential{
			User:     "Guest",
			Password: "",
			Domain:   "MicrosoftAccount",
		},
	})
	if err != nil {
		panic(err)
	}
	defer client.Close()

	ctx := context.Background()
	fs, err := client.Mount(ctx, `\\localhost\share`)
	if err != nil {
		panic(err)
	}
	defer fs.Unmount(ctx)

	f, err := fs.Create(ctx, "hello.txt")
	if err != nil {
		panic(err)
	}
	defer fs.Remove(ctx, "hello.txt")
	defer f.Close(ctx)

	_, err = f.Write(ctx, []byte("Hello world!"))
	if err != nil {
		panic(err)
	}

	_, err = f.Seek(ctx, 0, io.SeekStart)
	if err != nil {
		panic(err)
	}

	bs, err := io.ReadAll(f.WithContext(ctx))
	if err != nil {
		panic(err)
	}

	fmt.Println(string(bs))

	// Hello world!
}
