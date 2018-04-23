package client

import (
	"fmt"
	"strconv"
	"strings"
)

type Status struct {
	Info Info `json:"info"`
}

type Info struct {
	Version         int         `json:"version"`
	ProtocolVersion int         `json:"protocolversion"`
	Blocks          int         `json:"blocks"`
	TimeOffset      int         `json:"timeoffset"`
	Connections     int         `json:"connections"`
	DifficultyIface interface{} `json:"difficulty"`
	Difficulty      float64
	Testnet         bool        `json:"testnet"`
	RelayFeeIface   interface{} `json:"relayfee"`
	RelayFee        float64
	Errors          string `json:"errors"`
	Network         string `json:"network"`
}

type BlockList struct {
	Blocks     []Block    `json:"blocks"`
	Length     int        `json:"length"`
	Pagination Pagination `json:"pagination"`
}

type Pagination struct {
	Next      string `json:"next"`
	Prev      string `json:"prev"`
	CurrentTs int    `json:"currentTs"`
	Current   string `json:"current"`
	IsToday   bool   `json:"isToday"`
	More      bool   `json:"more"`
	MoreTs    int    `json:"moreTs"`
}

type Block struct {
	Hash              string    `json:"hash"`
	Size              int       `json:"size"`
	Height            int       `json:"height"`
	Version           int       `json:"version"`
	MerkleRoot        string    `json:"merkleroot"`
	Tx                []string  `json:"tx"`
	Time              int64     `json:"time"`
	Nonce             string    `json:"nonce"`
	Solution          string    `json:"solution"`
	Bits              string    `json:"bits"`
	Difficulty        float64   `json:"difficulty"`
	Chainwork         string    `json:"chainwork"`
	Confirmations     int       `json:"confirmations"`
	PreviousBlockhash string    `json:"previousblockhash"`
	NextBlockhash     string    `json:"nextblockhash"`
	Reward            float64   `json:"reward"`
	IsMainChain       bool      `json:"isMainChain"`
	PoolInfo          *PoolInfo `json:"poolinfo"`
}

type PoolInfo struct {
	PoolName string `json:"poolName"`
	URL      string `json:"url"`
}

type Utxo struct {
	Address       string      `json:"address"`
	Txid          string      `json:"txid"`
	Vout          int         `json:"vout"`
	ScriptPubKey  string      `json:"scriptPubKey"`
	AmountIface   interface{} `json:"amount"`
	Amount        float64
	Satoshis      int64 `json:"satoshis"`
	Confirmations int   `json:"confirmations"`
}

type TransactionList struct {
	TotalItems int           `json:"totalItems"`
	From       int           `json:"from"`
	To         int           `json:"to"`
	Items      []Transaction `json:"items"`
}

type Transaction struct {
	Txid          string   `json:"txid"`
	Version       int      `json:"version"`
	Locktime      int      `json:"locktime"`
	Inputs        []Input  `json:"vin"`
	Outputs       []Output `json:"vout"`
	BlockHash     string   `json:"blockhash"`
	BlockHeight   int      `json:"blockheight"`
	Confirmations int      `json:"confirmations"`
	Time          int64    `json:"time"`
	BlockTime     int64    `json:"blocktime"`
}

type RawTxResponse struct {
	RawTx string `json:"rawtx"`
}

type Input struct {
	Txid            string      `json:"txid"`
	Vout            int         `json:"vout"`
	Sequence        int         `json:"sequence"`
	N               int         `json:"n"`
	ScriptSig       Script      `json:"scriptSig"`
	Addr            string      `json:"addr"`
	Satoshis        int64       `json:"valueSat"`
	ValueIface      interface{} `json:"value"`
	Value           float64
	DoubleSpentTxid string `json:"doubleSpentTxID"`
}

type Output struct {
	ValueIface   interface{} `json:"value"`
	Satoshis     *int64      `json:"valueSat"`
	Value        float64
	N            int       `json:"n"`
	ScriptPubKey OutScript `json:"scriptPubKey"`
	SpentTxid    string    `json:"spentTxId"`
	SpentIndex   int       `json:"spentIndex"`
	SpentHeight  int       `json:"spentHeight"`
}

func (o Output) ValueSat() (int64, error) {
	if o.Satoshis != nil {
		return *o.Satoshis, nil
	}
	i := o.ValueIface
	switch v := i.(type) {
	case float64:
		return int64(v * 1e8), nil
	case string:
		parts := strings.SplitN(v, ".", 2)
		if len(parts) < 2 {
			return strconv.ParseInt(v, 10, 64)
		}
		integerDigits, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("error parsing value float: %s\n", err)
		}
		fractionalDigits, err := strconv.ParseInt(parts[1][:8], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("error parsing value float: %s\n", err)
		}
		for j := 8 - len(parts[1]); j > 0; j-- {
			// Account for dropped trailing zeroes in the fractional portion
			fractionalDigits *= 10
		}
		return (integerDigits * 1e8) + fractionalDigits, nil
	case int64:
		return v, nil
	default:
		return 0, fmt.Errorf("Unknown value type in response")
	}
}

type Script struct {
	Hex string `json:"hex"`
	Asm string `json:"asm"`
}

type OutScript struct {
	Script
	Addresses []string `json:"addresses"`
	Type      string   `json:"type"`
}

// websocketBlock sent from insight are just the block hash string, not any actual block info.
type websocketBlock string

// websocketTransaction sent from insight are different from regular.
type websocketTransaction struct {
	Txid     string            `json:"txid"`
	IsRBF    bool              `json:"isRBF"`
	ValueOut float64           `json:"valueOut"`
	Outputs  []websocketOutput `json:"vout"`
}

// websocketOutput is a map from { "t1SJ2CR9xV8EFC23WkePVxnMSjThaqE2oLF": 111553112 }
type websocketOutput map[string]int64
