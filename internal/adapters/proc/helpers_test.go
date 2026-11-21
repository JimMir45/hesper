package proc

import (
	"context"
	"os"

	"github.com/JimMir45/hesper/internal/actions"
	"github.com/JimMir45/hesper/internal/adapters"
	"github.com/JimMir45/hesper/internal/kernel"
)

func mkReq(c actions.Card, runID, actionID string, params map[string]string, target kernel.Target, workDir string) adapters.ExecRequest {
	return adapters.ExecRequest{
		RunID:    runID,
		ActionID: actionID,
		Card:     c,
		Params:   params,
		Target:   target,
		WorkDir:  workDir,
	}
}

func kernelTarget(v string) kernel.Target {
	return kernel.Target{Kind: "host", Value: v}
}

func tContext() context.Context {
	return context.Background()
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
