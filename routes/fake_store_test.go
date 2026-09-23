// SPDX-License-Identifier: EUPL-1.2

package routes

import (
	"context"
	"encoding/json"
	"errors"

	"azugo.io/core"
	"github.com/lx-lib/lx-go-jsondb"
)

// fakeStore is a minimal jsondb.Store fake that lets tests control the
// result/error returned by Exec, without contacting a real Postgres instance.
type fakeStore struct {
	// resultJSON, if non-empty, is unmarshalled into Exec's data parameter.
	resultJSON string
	// execErr, if non-nil, is returned by every Exec call.
	execErr error

	// calls records every method name Exec was invoked with, in order.
	calls []string
}

func (f *fakeStore) Start(context.Context) error { return nil }
func (f *fakeStore) IsReady() bool               { return true }
func (f *fakeStore) Close()                      {}
func (f *fakeStore) AddTask(core.Tasker)         {}
func (f *fakeStore) Ping(context.Context) error  { return nil }

func (f *fakeStore) Begin(context.Context) (*jsondb.Tx, error) {
	return nil, errors.New("fakeStore: Begin not supported")
}

func (f *fakeStore) Exec(_ context.Context, method string, _, data interface{}) error {
	f.calls = append(f.calls, method)

	if f.execErr != nil {
		return f.execErr
	}

	if data != nil && f.resultJSON != "" {
		return json.Unmarshal([]byte(f.resultJSON), data)
	}

	return nil
}
