package main

import (
	"fmt"
	"github.com/google/logger"
	apipb "github.com/jsannemo/omogenexec/api"
	"github.com/jsannemo/omogenexec/util"
	"path"
	"path/filepath"
	"strings"
)

type compilation struct {
	// This is unset if the compilation failed.
	Program        *apipb.CompiledProgram
	CompilerErrors string
}

type compileFunc func(program *apipb.Program, outputBase util.FileBase) (*compilation, error)

func compile(program *apipb.Program, outputPath string) (*compilation, error) {
	langs := GetLanguages()
	lang, found := langs[program.Language]
	if !found {
		logger.Fatalf("Could not find submission language %v", program.Language)
	}
	fb := util.NewFileBase(outputPath)
	fb.GroupWritable = true
	fb.OwnerGid = util.OmogenexecGroupId()
	if err := fb.Mkdir("."); err != nil {
		return nil, fmt.Errorf("failed mkdir %s: %v", outputPath, err)
	}
	for _, file := range program.Sources {
		err := fb.WriteFile(file.Path, file.Contents)
		if err != nil {
			return nil, fmt.Errorf("failed writing %s: %v", file.Path, err)
		}
	}
	return lang.Compile(program, fb)
}

func noCompile(runCommand string, include func(string) bool) compileFunc {
	return func(program *apipb.Program, outputBase util.FileBase) (*compilation, error) {
		var filteredPaths []string
		for _, file := range program.Sources {
			if include(file.Path) {
				filteredPaths = append(filteredPaths, file.Path)
			}
		}
		runCommand = strings.ReplaceAll(runCommand, "{files}", strings.Join(filteredPaths, " "))
		return &compilation{
			Program: &apipb.CompiledProgram{
				ProgramRoot: outputBase.Path(),
				RunCommand:  runCommand,
			}}, nil
	}
}

func cppCompile(gppPath string) compileFunc {
	return func(program *apipb.Program, outputBase util.FileBase) (*compilation, error) {
		var filteredPaths []string
		for _, file := range program.Sources {
			if isCppFile(file.Path) {
				filteredPaths = append(filteredPaths, file.Path)
			}
		}
		sandboxArgs := sandboxForCompile(outputBase.Path())
		sandbox := NewSandbox(sandboxArgs)
		err := sandbox.Start()
		if err != nil {
			return nil, err
		}
		run, err := sandbox.Run(gppPath, substituteArgs(gppFlags, filteredPaths))
		sandbox.Finish()
		if err != nil {
			return nil, fmt.Errorf("sandbox failed: %v, %v", err, sandbox.sandboxErr.String())
		}
		stderr, err := outputBase.ReadFile("__compiler_errors")
		if err != nil {
			return nil, fmt.Errorf("could not read compiler errors: %v", err)
		}
		if !run.CrashedWith(0) {
			return &compilation{
				CompilerErrors: string(stderr),
			}, nil
		}
		return &compilation{
			Program: &apipb.CompiledProgram{
				ProgramRoot: outputBase.Path(),
				RunCommand:  "./a.out",
			}}, nil
	}
}

func isCppFile(path string) bool {
	ext := filepath.Ext(path)
	return ext == ".cc" || ext == ".cpp" || ext == ".h"
}

func sandboxForCompile(sourcePath string) sandboxArgs {
	return sandboxArgs{
		WorkingDirectory: sourcePath,
		InputPath:        "",
		OutputPath:       "",
		ErrorPath:        path.Join(sourcePath, "__compiler_errors"),
		ExtraReadPaths:   nil,
		ExtraWritePaths:  []string{sourcePath},
		TimeLimitMs:      60 * 1000,
		MemoryLimitKb:    1000 * 1000,
	}
}

func substituteArgs(args []string, paths []string) []string {
	var newArgs []string
	for _, arg := range args {
		if arg == "{files}" {
			newArgs = append(newArgs, paths...)
		} else {
			newArgs = append(newArgs, arg)
		}
	}
	return newArgs
}
