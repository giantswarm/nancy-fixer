package gocli

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/pterm/pterm"
)

type GoConfig struct {
	Cwd    string
	Logger *pterm.Logger
}

func CallGoNoBuffer(config GoConfig, args ...string) (string, error) {
	var stdout, stderr bytes.Buffer

	err := CallGo(config, &stdout, &stderr, args...)

	if err != nil {
		return "", err
	}

	errOutput := stderr.String()

	if errOutput != "" {
		return stdout.String(), fmt.Errorf("go %s: %s", strings.Join(args, " "), errOutput)
	}
	return stdout.String(), nil

}

func CallGo(
	config GoConfig,
	stdout *bytes.Buffer,
	stderr *bytes.Buffer,
	args ...string,
) (err error) {
	goExecutable, err := exec.LookPath("go")
	if err != nil {
		return fmt.Errorf("go executable not found: %w", err)
	}

	cmd := exec.Cmd{
		Path:   goExecutable,
		Args:   append([]string{goExecutable}, args...),
		Stdout: stdout,
		Stderr: stderr,
		Env:    append(os.Environ(), "GOTOOLCHAIN=auto"),
	}
	if config.Cwd != "" {
		cmd.Dir = config.Cwd
	}

	if config.Logger != nil {
		config.Logger.Debug("Running go command",
			config.Logger.Args("args", strings.Join(args, " "), "cwd", config.Cwd))
	}

	err = cmd.Run()
	if err != nil {
		stderrStr := stderr.String()
		stdoutStr := stdout.String()
		if config.Logger != nil {
			config.Logger.Debug("Go command failed",
				config.Logger.Args(
					"args", strings.Join(args, " "),
					"cwd", config.Cwd,
					"stderr", stderrStr,
					"stdout", stdoutStr,
					"error", err.Error(),
				))
		}
		return fmt.Errorf("go %s (cwd=%s): %s: %w", strings.Join(args, " "), config.Cwd, stderrStr, err)
	}
	return nil
}
