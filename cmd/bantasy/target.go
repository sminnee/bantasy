package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// errConflict marks a write that lost to another writer.
var errConflict = errors.New("changed by another writer since it was read; run the command again")

// target is one rule file: a local file, or one key of one ConfigMap. write
// replaces the text that read returned.
type target interface {
	name() string
	read() (string, error)
	write(text string) error
}

// fileTarget is a local rule file.
type fileTarget struct {
	path string
}

func (t *fileTarget) name() string { return t.path }

// read returns "" for a missing file.
func (t *fileTarget) read() (string, error) {
	b, err := os.ReadFile(t.path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}

	return string(b), err
}

// write replaces the file with one rename, so a reader never sees half a
// file. It renames over the file that a symlink points to, so the link
// stays. A local file has no conflict check: the last writer wins.
func (t *fileTarget) write(text string) error {
	path := t.path
	if p, err := filepath.EvalSymlinks(path); err == nil {
		path = p
	}

	mode := os.FileMode(0o644)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}

	_, err = tmp.WriteString(text)
	if err == nil {
		err = tmp.Chmod(mode)
	}

	if cerr := tmp.Close(); err == nil {
		err = cerr
	}

	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}

	if err != nil {
		_ = os.Remove(tmp.Name())
	}

	return err
}

// kubectlFunc runs kubectl with args and stdin. err is not nil when kubectl
// exits non-zero.
type kubectlFunc func(stdin string, args ...string) (stdout, stderr string, err error)

func execKubectl(stdin string, args ...string) (string, string, error) {
	cmd := exec.Command("kubectl", args...) //nolint:gosec // args are kubectl flags and names, not a shell line
	cmd.Stdin = strings.NewReader(stdin)

	var out, errOut bytes.Buffer

	cmd.Stdout = &out
	cmd.Stderr = &errOut

	err := cmd.Run()

	return out.String(), errOut.String(), err
}

// configMapTarget is one key of one ConfigMap.
type configMapTarget struct {
	namespace, configMap, key string
	context                   string
	kubectl                   kubectlFunc

	// obj is the ConfigMap that read found, or nil when it was missing.
	obj map[string]any
}

// parseConfigMapRef reads <namespace>/<name>:<key>.
func parseConfigMapRef(ref string) (*configMapTarget, error) {
	ns, rest, ok1 := strings.Cut(ref, "/")
	name, key, ok2 := strings.Cut(rest, ":")

	if !ok1 || !ok2 || ns == "" || name == "" || key == "" || strings.Contains(name, "/") {
		return nil, fmt.Errorf("--configmap %q: use <namespace>/<name>:<key>", ref)
	}

	return &configMapTarget{namespace: ns, configMap: name, key: key}, nil
}

func (t *configMapTarget) name() string {
	return t.namespace + "/" + t.configMap + ":" + t.key
}

func (t *configMapTarget) run(stdin string, args ...string) (string, string, error) {
	if t.context != "" {
		args = append([]string{"--context", t.context}, args...)
	}

	return t.kubectl(stdin, args...)
}

func (t *configMapTarget) read() (string, error) {
	out, errOut, err := t.run("", "get", "configmap", t.configMap, "-n", t.namespace, "-o", "json")
	if err != nil {
		if strings.Contains(errOut, "NotFound") {
			t.obj = nil
			return "", nil
		}

		return "", fmt.Errorf("kubectl get configmap: %w: %s", err, strings.TrimSpace(errOut))
	}

	d := json.NewDecoder(strings.NewReader(out))
	d.UseNumber()

	var obj map[string]any
	if err := d.Decode(&obj); err != nil {
		return "", fmt.Errorf("kubectl get configmap: %w", err)
	}

	t.obj = obj

	data, _ := obj["data"].(map[string]any)
	text, _ := data[t.key].(string)

	return text, nil
}

// write sends the ConfigMap that read found, with its resourceVersion and
// its other keys, so the API server refuses it after a concurrent change.
func (t *configMapTarget) write(text string) error {
	verb := "replace"
	obj := t.obj

	if obj == nil {
		verb = "create"
		obj = map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata":   map[string]any{"name": t.configMap, "namespace": t.namespace},
		}
	}

	data, ok := obj["data"].(map[string]any)
	if !ok {
		data = map[string]any{}
		obj["data"] = data
	}

	data[t.key] = text

	b, err := json.Marshal(obj)
	if err != nil {
		return err
	}

	_, errOut, err := t.run(string(b), verb, "-f", "-")
	if err == nil {
		return nil
	}

	for _, s := range []string{"Conflict", "the object has been modified", "AlreadyExists"} {
		if strings.Contains(errOut, s) {
			return errConflict
		}
	}

	return fmt.Errorf("kubectl %s: %w: %s", verb, err, strings.TrimSpace(errOut))
}
