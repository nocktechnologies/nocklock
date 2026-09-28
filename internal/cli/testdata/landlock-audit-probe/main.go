package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"

	"github.com/nocktechnologies/nocklock/internal/fence/fs/landlock"
)

func denied(err error) bool {
	return errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EPERM)
}

func main() {
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var spec landlock.Spec
	if err := json.Unmarshal(data, &spec); err != nil {
		panic(err)
	}
	if err := landlock.Apply(spec); err != nil {
		panic(err)
	}
	action := os.Args[2]
	for _, path := range os.Args[3:] {
		var err error
		switch action {
		case "create":
			var f *os.File
			f, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err == nil {
				_ = f.Close()
			}
		case "overwrite":
			err = os.WriteFile(path, []byte("tampered"), 0o600)
		case "delete":
			err = os.Remove(path)
		case "rename":
			err = os.Rename(path, path+".renamed")
		default:
			panic("unknown action")
		}
		if denied(err) {
			fmt.Println("DENIED", action, path)
			continue
		}
		if action == "create" && errors.Is(err, fs.ErrExist) {
			fmt.Println("EXISTS", action, path)
			continue
		}
		if err == nil {
			fmt.Println("ALLOWED", action, path)
			continue
		}
		if errors.Is(err, fs.ErrNotExist) {
			fmt.Println("MISSING", action, path)
			continue
		}
		fmt.Println("ERROR", action, path, err)
	}
}
