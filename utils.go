package goutils

import (
	"crypto/md5"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"time"
)

func GetFuncName(i interface{}) string {
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}

// CopyFile copies the contents from src to dst atomically.
// If dst does not exist, CopyFile creates it and preserve the modification time.
// If the copy fails, CopyFile aborts and dst is preserved.
func CopyFile(dst, src string) error {
	fi, err := os.Stat(src)
	if os.IsNotExist(err) {
		// src is not existed
		return err
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	return CopyFileFromReader(dst, in, fi.ModTime())
}

// CopyFile copies the contents from src to dst atomically.
// If dst does not exist, CopyFile creates it and preserve the modification time.
// If the copy fails, CopyFile aborts and dst is preserved.
func CopyFileFromReader(dst string, src io.Reader, modTime time.Time) error {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	f.Close()

	in := src

	// tmp, err := ioutil.TempFile("", "")
	tmp, err := ioutil.TempFile(filepath.Dir(dst), "_tmp_")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	_, err = io.Copy(tmp, in)
	if err = tmp.Close(); err != nil {
		return err
	}

	if err = os.Chtimes(tmp.Name(), time.Now(), modTime); err != nil {
		os.Remove(tmp.Name())
		return err
	}

	return os.Rename(tmp.Name(), dst)
}

func FileMd5(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
