package srt

import (
	"fmt"
	"os"
	"runtime"
	"path/filepath"
)

func Log(format string, args ...interface{}) {
	log(format, args...)
}

func log(format string, args ...interface{}) {
	_, fn, line, _ := runtime.Caller(1)

	logline := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "%s:%d %s", filepath.Base(fn), line, logline)
}

func logIn(format string, args ...interface{}) {
	log(format, args...)
}

func logOut(format string, args ...interface{}) {
	log(format, args...)
}
