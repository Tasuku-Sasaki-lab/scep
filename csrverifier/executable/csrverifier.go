// Package executablecsrverifier defines the ExecutableCSRVerifier csrverifier.CSRVerifier.
package executablecsrverifier

import (
	"errors"
	"os"
	"os/exec"
	"fmt"
	"crypto/x509"
	//"io"

	"github.com/go-kit/kit/log"
)

const (
	userExecute os.FileMode = 1 << (6 - 3*iota)
	groupExecute
	otherExecute
)

// New creates a executablecsrverifier.ExecutableCSRVerifier.
func New(path string, logger log.Logger) (*ExecutableCSRVerifier, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	fileMode := fileInfo.Mode()
	if fileMode.IsDir() {
		return nil, errors.New("CSR Verifier executable is a directory")
	}

	filePerm := fileMode.Perm()
	if filePerm&(userExecute|groupExecute|otherExecute) == 0 {
		return nil, errors.New("CSR Verifier executable is not executable")
	}

	return &ExecutableCSRVerifier{executable: path, logger: logger}, nil
}

// ExecutableCSRVerifier implements a csrverifier.CSRVerifier.
// It executes a command, and passes it the raw decrypted CSR.
// If the command exit code is 0, the CSR is considered valid.
// In any other cases, the CSR is considered invalid.
type ExecutableCSRVerifier struct {
	executable string
	logger     log.Logger
}

func (v *ExecutableCSRVerifier) Verify(data []byte, ChallengePassword string,CSR *x509.CertificateRequest) (bool, error) {
	cmd := exec.Command(v.executable,ChallengePassword)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return false, err
	}

	go func() {
		defer stdin.Close()
		stdin.Write(data)
	}()

	out, err := cmd.CombinedOutput()
	if err != nil {
		v.logger.Log("err", err)
		v.logger.Log("err", out)
		// mask the executable error
		fmt.Printf("エラー %s\n",err)
		fmt.Printf("エラー %s\n",out)
		return false, nil
	}
	return true, err
}
