package zcash

import (
	"github.com/OpenBazaar/multiwallet/client"
)

// TODO: Move this all to multiwallet
type BlockStore interface {
	Ingest(block client.Block) error
	Latest() *client.Block
}

type blockStore struct {
	blocks []client.Block
}

func NewBlockStore() (BlockStore, error) {
	return &blockStore{}, nil
}

// TODO: Check if we've already processed this block, skip it
// TODO: If the block is new, update height
// TODO: Detect and handle re-orgs
// TODO: Check block is valid
func (b *blockStore) Ingest(block client.Block) error {
	b.blocks = append(b.blocks, block)
	return nil
}

func (b *blockStore) Latest() *client.Block {
	if len(b.blocks) == 0 {
		return nil
	}
	return &(b.blocks[len(b.blocks)-1])
}
