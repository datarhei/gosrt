package main

import (
	"fmt"
	"os"
)

func log(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
}

func logIn(format string, args ...interface{}) {
	log(format, args...)
}

func logOut(format string, args ...interface{}) {
	log(format, args...)
}
