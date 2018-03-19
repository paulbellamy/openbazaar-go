package zcash

func (w *Wallet) sign(t *Transaction) error {
	// TODO: See spvwallet/sortsignsend.go#L358 for how to do this
	for i, input := range t.Inputs {
		input.ScriptSig = Script{Hex: "aa"}
		t.Inputs[i] = input
	}
	return nil
}
