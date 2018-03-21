package zcash

func (w *Wallet) sign(t *Transaction) error {
	// TODO: See spvwallet/sortsignsend.go#L358 for how to do this
	for i, _ := range t.Inputs {
		t.Inputs[i].ScriptSig = Script{Hex: "aa"}
	}
	return nil
}
