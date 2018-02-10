package zcash

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
)

func TestNewWalletDialsTheInsightAPI(t *testing.T) {
	t.Error("pending")
}

func TestWalletParams(t *testing.T) {
	expected := &chaincfg.Params{Name: "TestParams"}
	w, err := NewWallet("", expected, "", "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if w.Params() != expected {
		t.Errorf(
			"Params() did not return chain cfg params.\nExpected: %v\n     Got: %v",
			expected,
			w.Params(),
		)
	}
}

func TestWalletCurrencyCodeMainNet(t *testing.T) {
	expected := "zec"
	w, err := NewWallet("", &chaincfg.Params{Name: chaincfg.MainNetParams.Name}, "", "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if w.CurrencyCode() != expected {
		t.Errorf(
			"CurrencyCode() did not return expected.\nExpected: %v\n     Got: %v",
			expected,
			w.CurrencyCode(),
		)
	}
}

func TestWalletCurrencyCodeTestnet(t *testing.T) {
	expected := "tzec"
	w, err := NewWallet("", &chaincfg.Params{Name: ""}, "", "", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if w.CurrencyCode() != expected {
		t.Errorf(
			"CurrencyCode() did not return expected.\nExpected: %v\n     Got: %v",
			expected,
			w.CurrencyCode(),
		)
	}
}

func TestWalletScriptToAddress(t *testing.T) {
	// TODO: Test this better
	for _, tc := range []struct {
		name    string
		script  []byte
		params  *chaincfg.Params
		address string
		err     error
	}{
		{
			name:    "empty script",
			script:  nil,
			address: "",
			params:  nil,
			err:     fmt.Errorf("unknown script type"),
		},
		{
			name:    "basic script",
			script:  []byte{0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87},
			address: "t3JZcvsuaXE6ygokL4XUiZSTrQBUoPYFnXJ",
			params:  &chaincfg.MainNetParams,
			err:     nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, err := NewWallet("", tc.params, "", "", false, 0)
			if err != nil {
				t.Fatal(err)
			}
			address, err := w.ScriptToAddress([]byte(tc.script))
			switch {
			case tc.err == nil && err != nil:
				t.Errorf("\nUnexpected error: %v\n     Got: %v", tc.err, err)
			case tc.err != nil && err == nil:
				t.Errorf("\nUnexpected error: %v\n     Got: %v", tc.err, err)
			case tc.err != nil && err != nil && tc.err.Error() != err.Error():
				t.Errorf("\nUnexpected error: %v\n     Got: %v", tc.err, err)
			}
			if tc.address != "" || address != nil {
				if fmt.Sprint(address) != tc.address {
					t.Errorf("\nExpected: %v\n     Got: %v", tc.address, address)
				}
			}
		})
	}

}
