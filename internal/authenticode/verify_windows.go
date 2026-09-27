// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package authenticode

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modWintrust                        = windows.NewLazySystemDLL("wintrust.dll")
	procWTHelperProvDataFromStateData  = modWintrust.NewProc("WTHelperProvDataFromStateData")
	procWTHelperGetProvSignerFromChain = modWintrust.NewProc("WTHelperGetProvSignerFromChain")
	procWTHelperGetProvCertFromChain   = modWintrust.NewProc("WTHelperGetProvCertFromChain")
)

// cryptProviderCert is the leading, stable part of CRYPT_PROVIDER_CERT;
// only these fields are read.
type cryptProviderCert struct {
	size uint32
	cert *windows.CertContext
}

// Verification is the WinVerifyTrust state of one file. It stays open
// until Close so the verified signer certificate can be read from it. A
// Verification is used by one goroutine.
type Verification struct {
	file   *windows.WinTrustFileInfo
	data   *windows.WinTrustData
	closed bool
}

// VerifyFile verifies the embedded Authenticode signature of an open file
// with WinVerifyTrust (WINTRUST_ACTION_GENERIC_VERIFY_V2) and returns the
// WinVerifyTrust result. path names the file; the check reads handle, so
// the bytes verified are those of the file held open rather than whatever
// the path resolves to later.
//
// No UI is shown and revocation is not fetched, so the result never waits
// on the network (the CMID broker starts at boot, possibly before the
// network, and the IPC accept path must not block); the chain, file
// digest, and timestamp are still verified.
//
// The returned Verification is never nil and must be closed whatever the
// result, because WinVerifyTrust allocates its state either way.
func VerifyFile(path *uint16, handle windows.Handle) (*Verification, error) {
	file := &windows.WinTrustFileInfo{
		Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
		FilePath: path,
		File:     handle,
	}
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(file),
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		ProvFlags: windows.WTD_CACHE_ONLY_URL_RETRIEVAL |
			windows.WTD_REVOCATION_CHECK_NONE |
			windows.WTD_DISABLE_MD2_MD4,
		UIContext: windows.WTD_UICONTEXT_EXECUTE,
	}
	verification := &Verification{file: file, data: data}
	err := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	return verification, err
}

// PrimarySignerCertificate returns the leaf certificate of the primary
// signer of a signature VerifyFile accepted. The context belongs to the
// verification state: it is valid until Close, and the caller copies what
// it keeps.
func (v *Verification) PrimarySignerCertificate() (*windows.CertContext, error) {
	for _, proc := range []*windows.LazyProc{
		procWTHelperProvDataFromStateData,
		procWTHelperGetProvSignerFromChain,
		procWTHelperGetProvCertFromChain,
	} {
		if err := proc.Find(); err != nil {
			return nil, fmt.Errorf("resolve %s: %w", proc.Name, err)
		}
	}
	if v == nil || v.closed || v.data.StateData == 0 {
		return nil, errors.New("WinVerifyTrust returned no verification state")
	}
	provider, _, _ := procWTHelperProvDataFromStateData.Call(uintptr(v.data.StateData))
	if provider == 0 {
		return nil, errors.New("WinVerifyTrust returned no provider data")
	}
	signer, _, _ := procWTHelperGetProvSignerFromChain.Call(provider, 0, 0, 0)
	if signer == 0 {
		return nil, errors.New("WinVerifyTrust returned no primary signer")
	}
	certificate, _, _ := procWTHelperGetProvCertFromChain.Call(signer, 0)
	if certificate == 0 {
		return nil, errors.New("WinVerifyTrust returned no signer certificate")
	}
	providerCert := (*cryptProviderCert)(wintrustPointer(certificate))
	if uintptr(providerCert.size) < unsafe.Sizeof(cryptProviderCert{}) || providerCert.cert == nil {
		return nil, errors.New("WinVerifyTrust returned a malformed signer certificate")
	}
	return providerCert.cert, nil
}

// Close releases the WinVerifyTrust state. It is safe to call more than
// once; only the first call releases it.
func (v *Verification) Close() error {
	if v == nil || v.closed {
		return nil
	}
	v.closed = true
	v.data.StateAction = windows.WTD_STATEACTION_CLOSE
	err := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, v.data)
	runtime.KeepAlive(v.file)
	return err
}

// wintrustPointer converts an address returned by wintrust.dll into a
// pointer. The memory belongs to the WinVerifyTrust state, never the Go
// heap, and stays valid until the state is closed.
func wintrustPointer(address uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&address))
}
