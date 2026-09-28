// Copyright 2026 Cisco Systems, Inc. and its affiliates
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

package semantic

import (
	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/types"
)

// RedirectReductionSafe reports whether a match of this expression on the
// view returned by actionfacts.Facts.DynamicRedirectTargetReduction also holds
// for the whole action, whose commands still carry the runtime-expanded
// redirections the view dropped.
//
// The view differs from the action only in each command's redirects (the
// action has more), in argv_complete, and in the parse result. An expression
// is safe when it reads neither argv_complete nor parse, and reads redirects
// only as the range of an exists() reached from the root through &&, || and
// exists() or all() predicates alone: more redirections can then only keep a
// match. Any other use of redirects (under !, ==, !=, in, or as the range of
// all()) could turn a match off with more redirections, so it is unsafe.
// Negation elsewhere, for example over argv, is unaffected: the view keeps
// those facts unchanged.
func (p *Program) RedirectReductionSafe() bool {
	return p != nil && p.redirectReductionSafe
}

func redirectReductionSafe(ast *cel.Ast) bool {
	if ast == nil || ast.NativeRep() == nil {
		return false
	}
	// monotone is true while every operator between the root and expr keeps
	// a true result true when a command gains redirections.
	var visit func(expr celast.Expr, monotone bool) bool
	visit = func(expr celast.Expr, monotone bool) bool {
		switch expr.Kind() {
		case celast.IdentKind, celast.LiteralKind:
			return true
		case celast.SelectKind:
			selected := expr.AsSelect()
			switch selected.FieldName() {
			case "parse", "argv_complete":
				return false
			case "redirects":
				if !monotone {
					return false
				}
			}
			return visit(selected.Operand(), false)
		case celast.CallKind:
			call := expr.AsCall()
			name := call.FunctionName()
			argumentsMonotone := monotone &&
				(name == operators.LogicalAnd || name == operators.LogicalOr)
			if call.IsMemberFunction() && !visit(call.Target(), false) {
				return false
			}
			for _, argument := range call.Args() {
				if !visit(argument, argumentsMonotone) {
					return false
				}
			}
			return true
		case celast.ComprehensionKind:
			loop := expr.AsComprehension()
			exists := quantifierComprehension(loop, false, operators.LogicalOr)
			all := quantifierComprehension(loop, true, operators.LogicalAnd)
			// exists() only gains matches from a longer range; all() can
			// lose them, so only an exists() range may read redirects.
			return visit(loop.IterRange(), monotone && exists) &&
				visit(loop.AccuInit(), false) &&
				visit(loop.LoopCondition(), false) &&
				visit(loop.LoopStep(), monotone && (exists || all)) &&
				visit(loop.Result(), monotone && (exists || all))
		case celast.ListKind:
			for _, element := range expr.AsList().Elements() {
				if !visit(element, false) {
					return false
				}
			}
			return true
		default:
			return false
		}
	}
	return visit(ast.NativeRep().Expr(), true)
}

// quantifierComprehension reports whether loop is the expansion of exists()
// (initial false, step "result || predicate") or all() (initial true, step
// "result && predicate"), selected by initial and step.
func quantifierComprehension(
	loop celast.ComprehensionExpr,
	initial bool,
	step string,
) bool {
	init := loop.AccuInit()
	if init.Kind() != celast.LiteralKind ||
		init.AsLiteral() != types.Bool(initial) ||
		loop.Result().Kind() != celast.IdentKind ||
		loop.Result().AsIdent() != loop.AccuVar() ||
		loop.LoopStep().Kind() != celast.CallKind {
		return false
	}
	call := loop.LoopStep().AsCall()
	arguments := call.Args()
	return call.FunctionName() == step && len(arguments) == 2 &&
		arguments[0].Kind() == celast.IdentKind &&
		arguments[0].AsIdent() == loop.AccuVar()
}
