package client

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/OpenBazaar/multiwallet/client/transport"
	"github.com/btcsuite/btcutil"
	"github.com/graarh/golang-socketio"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"time"
)

type InsightClient struct {
	httpClient      http.Client
	apiUrl          url.URL
	blockNotifyChan chan Block
	txNotifyChan    chan Transaction
	socketClient    *gosocketio.Client
}

func NewInsightClient(apiUrl string, proxyDialer proxy.Dialer) (*InsightClient, error) {
	u, err := url.Parse(apiUrl)
	if err != nil {
		return nil, err
	}
	var port int
	var secure bool
	if u.Scheme == "https" {
		port = 443
		secure = true
	} else if u.Scheme == "http" {
		port = 80
		secure = false
	} else {
		return nil, errors.New("Unknown url scheme")
	}
	dial := net.Dial
	if proxyDialer != nil {
		dial = proxyDialer.Dial
	}
	socketClient, err := gosocketio.Dial(
		gosocketio.GetUrl(u.Host, port, secure),
		transport.GetDefaultWebsocketTransport(proxyDialer),
	)
	if err != nil {
		return nil, err
	}
	socketReady := make(chan struct{})
	socketClient.On(gosocketio.OnConnection, func(h *gosocketio.Channel, args interface{}) {
		close(socketReady)
	})
	ticker := time.NewTicker(time.Second * 10)
	select {
	case <-ticker.C:
		return nil, errors.New("Timed out waiting for websocket connection")
	case <-socketReady:
		break
	}
	socketClient.Emit("subscribe", "inv")

	bch := make(chan Block)
	socketClient.On("block", func(h *gosocketio.Channel, arg Block) {
		bch <- arg
	})
	tch := make(chan Transaction)
	tbTransport := &http.Transport{Dial: dial}
	return &InsightClient{
		http.Client{Timeout: time.Second * 30, Transport: tbTransport},
		*u,
		bch,
		tch,
		socketClient,
	}, nil
}

func (i *InsightClient) doRequest(endpoint, method string, body io.Reader, query url.Values) (*http.Response, error) {
	requestUrl := i.apiUrl
	requestUrl.Path = path.Join(i.apiUrl.Path, endpoint)
	req, err := http.NewRequest(method, requestUrl.String(), body)
	if query != nil {
		req.URL.RawQuery = query.Encode()
	}
	if err != nil {
		return nil, fmt.Errorf("creating request: %s\n", err)
	}
	req.Header.Add("Content-Type", "application/json")

	resp, err := i.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status not ok: %s\n", resp.Status)
	}
	return resp, nil
}

func (i *InsightClient) Status() (*Status, error) {
	resp, err := i.doRequest("status", http.MethodGet, nil, nil)
	if err != nil {
		return nil, err
	}
	status := new(Status)
	decoder := json.NewDecoder(resp.Body)
	defer resp.Body.Close()
	if err = decoder.Decode(status); err != nil {
		return nil, fmt.Errorf("error decoding status: %s\n", err)
	}
	return status, nil
}

func (i *InsightClient) GetTransaction(txid string) (*Transaction, error) {
	resp, err := i.doRequest("tx/"+txid, http.MethodGet, nil, nil)
	if err != nil {
		return nil, err
	}
	tx := new(Transaction)
	decoder := json.NewDecoder(resp.Body)
	defer resp.Body.Close()
	if err = decoder.Decode(tx); err != nil {
		return nil, fmt.Errorf("error decoding transactions: %s\n", err)
	}
	for n, in := range tx.Inputs {
		f, err := toFloat(in.ValueIface)
		if err != nil {
			return nil, err
		}
		tx.Inputs[n].Value = f
	}
	for n, out := range tx.Outputs {
		f, err := toFloat(out.ValueIface)
		if err != nil {
			return nil, err
		}
		tx.Outputs[n].Value = f
	}
	return tx, nil
}

func (i *InsightClient) GetRawTransaction(txid string) ([]byte, error) {
	resp, err := i.doRequest("rawtx/"+txid, http.MethodGet, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	tx := new(RawTxResponse)
	if err = json.NewDecoder(resp.Body).Decode(tx); err != nil {
		return nil, fmt.Errorf("error decoding transactions: %s\n", err)
	}
	return []byte(tx.RawTx), nil
}

func (i *InsightClient) GetTransactions(addrs []btcutil.Address) ([]Transaction, error) {
	var txs []Transaction
	from := 0
	for {
		tl, err := i.getTransactions(addrs, from, from+50)
		if err != nil {
			return txs, err
		}
		txs = append(txs, tl.Items...)
		if len(txs) >= tl.TotalItems {
			break
		}
		from += 50
	}
	return txs, nil
}

func (i *InsightClient) getTransactions(addrs []btcutil.Address, from, to int) (*TransactionList, error) {
	type req struct {
		Addrs string `json:"addrs"`
		From  int    `json:"from"`
		To    int    `json:"to"`
	}
	s := ``
	for n, addr := range addrs {
		s += addr.String()
		if n < len(addrs)-1 {
			s += ","
		}
	}
	r := &req{
		Addrs: s,
		From:  from,
		To:    to,
	}
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	resp, err := i.doRequest("addrs/txs", http.MethodPost, bytes.NewReader(b), nil)
	if err != nil {
		return nil, err
	}
	tl := new(TransactionList)
	decoder := json.NewDecoder(resp.Body)
	defer resp.Body.Close()
	if err = decoder.Decode(tl); err != nil {
		return nil, fmt.Errorf("error decoding transaction list: %s\n", err)
	}
	for z, tx := range tl.Items {
		for n, in := range tx.Inputs {
			f, err := toFloat(in.ValueIface)
			if err != nil {
				return nil, err
			}
			tl.Items[z].Inputs[n].Value = f
		}
		for n, out := range tx.Outputs {
			f, err := toFloat(out.ValueIface)
			if err != nil {
				return nil, err
			}
			tl.Items[z].Outputs[n].Value = f
		}
	}
	return tl, nil
}

// GetBlocks loads all blocks since the provided block index
func (i *InsightClient) GetBlocks(fromIndex int) ([]Block, error) {
	// Fetch the genesis hash
	genesis, err := i.GetBlockIndex(fromIndex)
	if err != nil {
		return nil, err
	}

	var blocks []Block
	to := time.Now().UTC()
	for {
		page, err := i.GetBlocksBefore(to, 200)
		if err != nil {
			return blocks, err
		}
		blocks = append(blocks, page.Blocks...)
		if len(page.Blocks) > 0 && page.Blocks[0].Hash == genesis.Hash {
			// We're done
			break
		}
		if page.Pagination.More {
			// Move back within the day
			// Last block has the earliest timestamp
			to = time.Unix(page.Blocks[len(page.Blocks)-1].Time, 0)
		} else {
			// move back a day, to (just before) midnight
			to = to.Truncate(24 * time.Hour).Add(-1 * time.Nanosecond)
		}
	}
	return blocks, nil
}

func (i *InsightClient) GetBlocksBefore(to time.Time, limit int) (*BlockList, error) {
	resp, err := i.doRequest("blocks", http.MethodGet, nil, url.Values{
		"blockDate":      {to.Format("2006-01-02")},
		"startTimestamp": {fmt.Sprint(to.Unix())},
		"limit":          {fmt.Sprint(limit)},
	})
	if err != nil {
		return nil, err
	}
	list := new(BlockList)
	decoder := json.NewDecoder(resp.Body)
	defer resp.Body.Close()
	if err = decoder.Decode(list); err != nil {
		return nil, fmt.Errorf("error decoding block list: %s\n", err)
	}
	return list, nil
}

func (i *InsightClient) GetBlockIndex(height int) (*Block, error) {
	resp, err := i.doRequest(fmt.Sprintf("block-index/%d", height), http.MethodGet, nil, nil)
	if err != nil {
		return nil, err
	}
	block := new(Block)
	decoder := json.NewDecoder(resp.Body)
	defer resp.Body.Close()
	if err = decoder.Decode(block); err != nil {
		return nil, fmt.Errorf("error decoding block: %s\n", err)
	}
	return block, nil
}

// GetLatestBlock loads a summary of the latest block
func (i *InsightClient) GetLatestBlock() (*Block, error) {
	page, err := i.GetBlocksBefore(time.Now().UTC(), 1)
	if err != nil || len(page.Blocks) == 0 {
		return nil, err
	}
	return &page.Blocks[0], nil
}

func (i *InsightClient) GetUtxos(addrs []btcutil.Address) ([]Utxo, error) {
	type req struct {
		Addrs string `json:"addrs"`
	}
	s := ``
	for n, addr := range addrs {
		s += addr.String()
		if n < len(addrs)-1 {
			s += ","
		}
	}
	r := &req{
		Addrs: s,
	}
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	resp, err := i.doRequest("addrs/utxo", http.MethodPost, bytes.NewReader(b), nil)
	if err != nil {
		return nil, err
	}
	utxos := []Utxo{}
	decoder := json.NewDecoder(resp.Body)
	defer resp.Body.Close()
	if err = decoder.Decode(&utxos); err != nil {
		return nil, fmt.Errorf("error decoding utxo list: %s\n", err)
	}
	for z, u := range utxos {
		f, err := toFloat(u.AmountIface)
		if err != nil {
			return nil, err
		}
		utxos[z].Amount = f
	}
	return utxos, nil
}

func (i *InsightClient) BlockNotify() <-chan Block {
	return i.blockNotifyChan
}

func (i *InsightClient) TransactionNotify() <-chan Transaction {
	return i.txNotifyChan
}

func (i *InsightClient) ListenAddress(addr btcutil.Address) {
	i.socketClient.Emit("subscribe", addr.String())
	i.socketClient.On(addr.String(), func(h *gosocketio.Channel, arg Transaction) {
		i.txNotifyChan <- arg
	})
}

func (i *InsightClient) Broadcast(tx []byte) (string, error) {
	txHex := hex.EncodeToString(tx)
	type RawTx struct {
		Raw string `json:"rawtx"`
	}
	t := RawTx{txHex}
	txJson, err := json.Marshal(&t)
	if err != nil {
		return "", err
	}
	resp, err := i.doRequest("tx/send", http.MethodPost, bytes.NewBuffer(txJson), nil)
	decoder := json.NewDecoder(resp.Body)
	txid := new(Transaction)
	defer resp.Body.Close()
	if err = decoder.Decode(txid); err != nil {
		return "", fmt.Errorf("error decoding utxo list: %s\n", err)
	}
	return txid.Txid, nil
}

func (i *InsightClient) EstimateFee(nbBlocks int) (int, error) {
	resp, err := i.doRequest("utils/estimatefee", http.MethodGet, nil, url.Values{"nbBlocks": {fmt.Sprint(nbBlocks)}})
	if err != nil {
		return 0, err
	}
	data := map[int]float64{}
	defer resp.Body.Close()
	if err = json.NewDecoder(resp.Body).Decode(data); err != nil {
		return 0, fmt.Errorf("error decoding fee estimate: %s\n", err)
	}
	return int(data[nbBlocks] * 1e8), nil
}

func (i *InsightClient) GetInfo() (*Info, error) {
	q, err := url.ParseQuery("?q=values")
	if err != nil {
		return nil, err
	}
	resp, err := i.doRequest("status", http.MethodGet, nil, q)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(resp.Body)
	stat := new(Status)
	defer resp.Body.Close()
	if err = decoder.Decode(stat); err != nil {
		return nil, fmt.Errorf("error decoding utxo list: %s\n", err)
	}
	info := stat.Info
	f, err := toFloat(stat.Info.RelayFeeIface)
	if err != nil {
		return nil, err
	}
	info.RelayFee = f
	f, err = toFloat(stat.Info.DifficultyIface)
	if err != nil {
		return nil, err
	}
	info.Difficulty = f
	return &info, nil
}

// API sometimees returns a float64 or a string so we'll always convert it into a float64
func toFloat(i interface{}) (float64, error) {
	_, fok := i.(float64)
	_, sok := i.(string)
	if fok {
		return i.(float64), nil
	} else if sok {
		s := i.(string)
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return 0, fmt.Errorf("error parsing value float: %s\n", err)
		}
		return f, nil
	} else {
		return 0, errors.New("Unknown value type in response")
	}
}

func (i *InsightClient) Close() {
	i.socketClient.Close()
	close(i.blockNotifyChan)
	close(i.txNotifyChan)
}
