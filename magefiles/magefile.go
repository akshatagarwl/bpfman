//go:build mage
// +build mage

package main

import (
	"os"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

// Default target to run when none is specified
// If not set, running mage will list available targets
var Default = Build.All

func createBPFBinDir() error {
	return os.MkdirAll("bpf/bin", os.ModePerm)
}

func createBinDir() error {
	return os.MkdirAll("bin", os.ModePerm)
}

type Build mg.Namespace

func (Build) BPF() error {
	mg.Deps(createBPFBinDir)
	return sh.RunV("go", "generate", "./...")
}

func (Build) Go() error {
	mg.Deps(createBinDir)
	return sh.RunV("go", "build", "-o", "bin/bpfman", ".")
}

func (Build) All() error {
	mg.Deps(Build.BPF, Build.Go)
	return nil
}

func Tidy() error {
	return sh.RunV("go", "mod", "tidy", "-v")
}

func gofmt() error {
	return sh.RunV("go", "fmt", "./...")
}

func wsl() error {
	return sh.RunV("go", "run", "github.com/bombsimon/wsl/v4/cmd...@master", "--fix", "./...")
}

func gofumpt() error {
	return sh.RunV("go", "run", "mvdan.cc/gofumpt@latest", "-l", "-w", ".")
}

func Format() error {
	mg.Deps(gofmt, wsl, gofumpt)
	return nil
}

type Lint mg.Namespace

func (Lint) Check() error {
	return sh.RunV("go", "run", "github.com/golangci/golangci-lint/cmd/golangci-lint@v1.55.2", "run", "./...")
}

func (Lint) Fix() error {
	return sh.RunV("go", "run", "github.com/golangci/golangci-lint/cmd/golangci-lint@v1.55.2", "run", "--fix", "./...")
}

func cleanBPFBin() error {
	return sh.Rm("./bpf/bin")
}

func cleanBin() error {
	return sh.Rm("./bin")
}

func Clean() error {
	mg.Deps(cleanBPFBin, cleanBin)
	return nil
}
