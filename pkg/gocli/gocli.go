package gocli

import (
	"bytes"
	"os/exec"

	"github.com/pkg/errors"
)

type GoConfig struct {
	Cwd string
}

func CallGoNoBuffer(config GoConfig, args ...string) (string, error) {
	var stdout, stderr bytes.Buffer

	err := CallGo(config, &stdout, &stderr, args...)

	if err != nil {
		return "", errors.Cause(err)
	}

	errOutput := stderr.String()

	if errOutput != "" {
		return stdout.String(), errors.New(errOutput)
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
		return errors.Cause(err)
	}

	cmd := exec.Cmd{
		Path:   goExecutable,
		Args:   append([]string{goExecutable}, args...),
		Stdout: stdout,
		Stderr: stderr,
	}
	if config.Cwd != "" {
		cmd.Dir = config.Cwd
	}

	err = cmd.Run()
	if err != nil {
		outErr := stderr.String()

		return errors.Wrap(err, outErr)
	}
	return nil
}
