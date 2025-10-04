package main

import "github.com/aleister1102/crlfuzz/internal/runner"

func main() {
	options := runner.ParseOptions()
	runner.New(options)
}
