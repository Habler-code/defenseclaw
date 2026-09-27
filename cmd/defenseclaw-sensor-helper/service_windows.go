// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log/slog"

	"golang.org/x/sys/windows/svc"
)

// runUnderServiceManager speaks the SCM control protocol when this process
// was started as a Windows service, and runs normally otherwise.
//
// The Service Control Manager expects a service to report Running within a
// few seconds of start and to acknowledge Stop. A plain console binary
// answers neither, so SCM kills it with error 1053 -- observed on Windows
// Server 2025 before this existed. The same binary still runs from a
// console for diagnostics, which is why the mode is detected rather than
// chosen by a flag.
//
// Under SCM, serve's error never comes back from here: svc.Run returns only
// the dispatcher's own result, and the handler reports the failure to SCM as
// an exit code. The handler therefore writes that error to logger itself.
func runUnderServiceManager(
	ctx context.Context,
	logger *slog.Logger,
	serve func(context.Context) error,
) error {
	inService, err := svc.IsWindowsService()
	if err != nil || !inService {
		return serve(ctx)
	}
	return svc.Run("", &helperService{ctx: ctx, serve: serve, logger: logger})
}

type helperService struct {
	ctx    context.Context
	serve  func(context.Context) error
	logger *slog.Logger
}

// logExit records why serve returned. It runs before the handler reports
// StopPending, because once SCM sees the service stopped the process can end
// at any time, and the exit code SCM shows (1) carries no reason.
func (s *helperService) logExit(err error) {
	if err == nil || s.logger == nil {
		return
	}
	s.logger.Error("sensor helper exited", "error", err)
}

// Execute is the SCM entry point.
//
// Accepted controls are Stop and Shutdown only. This service has no
// meaningful pause state: the planes either have an event source or they
// report that they do not, and a paused helper would look to the gateway
// exactly like a helper that had gone away.
func (s *helperService) Execute(
	_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status,
) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()

	failed := make(chan error, 1)
	go func() { failed <- s.serve(ctx) }()

	status <- svc.Status{State: svc.Running, Accepts: accepted}
	for {
		select {
		case err := <-failed:
			// The listener stopped on its own. Reporting a non-zero exit
			// code is what lets SCM's restart policy see a crash rather
			// than an orderly stop.
			s.logExit(err)
			status <- svc.Status{State: svc.StopPending}
			if err != nil {
				return false, 1
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				s.logExit(<-failed)
				return false, 0
			default:
				// Anything else is not accepted above, so receiving it
				// means SCM and this handler disagree. Ignore rather than
				// act on a control this service never advertised.
			}
		}
	}
}
