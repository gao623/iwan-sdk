// ========================================================
// iWan SDK - TypeScript Rewrite
// ========================================================
// Original: https://github.com/wanchain/iWan-js-sdk
// Features:
// - Browser + Node full support (auto detect)
// - isTestnet convenience flag (default: false)
// - flag option kept (matches original README)
// - Every request 100% signed with secretKey HMAC-SHA256
// - Robust reconnect (max tries + lock), central timeout, clean pending
// - High performance & zero debug logs
// - Easy extend via .call()
// - CommonJS/ESM/TS/Browser ready (tsdown)

import { EventEmitter } from 'eventemitter3';

// ====================== CONFIG ======================
const DEFAULT_CONFIG = {
  mainnet: { url: 'api.wanchain.org', port: 8443 },
  testnet: { url: 'apitest.wanchain.org', port: 8443 },
  flag: 'ws',
  version: 'v3',
  clientType: 'iWanSDK',
  clientVersion: '1.4.0',
  timeout: 30000,
  pingTime: 30000,
  maxTries: 3,
  reconnTime: 2000,
  wsOptions: { handshakeTimeout: 12000, rejectUnauthorized: false },
} as const;

// ====================== TYPES ======================
/**
 * iWan SDK client options
 */
export interface IwanClientOptions {
  /** RPC server hostname */
  url?: string;
  /** RPC server port */
  port?: number;
  /** Connection flag (default: 'ws') */
  flag?: string;
  /** API version (default: 'v3') */
  version?: string;
  /** Client identifier */
  clientType?: string;
  /** Client version */
  clientVersion?: string;
  /** Request timeout in ms */
  timeout?: number;
  /** Use testnet instead of mainnet */
  isTestnet?: boolean;
}

interface RPCMessage {
  jsonrpc: '2.0';
  method: string;
  params: Record<string, any>;
  id: number;
}

interface RPCResponse<T = any> {
  jsonrpc: '2.0';
  id: number;
  result?: T;
  error?: { code: number; message: string };
}

interface PendingRequest {
  resolve: (value: any) => void;
  reject: (reason?: any) => void;
  time: number;
}

// ====================== CUSTOM ERROR ======================
class IWanError extends Error {
  constructor(message: string, public code?: string) {
    super(message);
    this.name = 'IWanError';
  }
}

// ====================== CRYPTO (Node + Browser Safe) ======================
async function generateSignature(secret: string, msg: string): Promise<string> {
  const encoder = new TextEncoder();
  if (typeof window !== 'undefined' && window.crypto?.subtle) {
    // Browser Web Crypto
    const webCrypto = window.crypto;
    const key = await webCrypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const sig = await webCrypto.subtle.sign('HMAC', key, encoder.encode(msg));
    const arr = Array.from(new Uint8Array(sig));
    return btoa(String.fromCharCode(...arr));
  }

  // Node - dynamic import for ESM compatibility
  const { createHmac } = await import('crypto');
  return createHmac('sha256', secret).update(msg).digest('base64');
}

async function signPayload(payload: RPCMessage, secretKey: string): Promise<RPCMessage> {
  const newPayload = { ...payload };
  newPayload.params.timestamp = Date.now();
  newPayload.params.signature = await generateSignature(secretKey, JSON.stringify(newPayload));
  return newPayload;
}

// ====================== MAIN CLIENT ======================

/**
 * Main iWan SDK client
 *
 * @example
 * ```ts
 * const client = new IwanClient(apiKey, secretKey, { isTestnet: false });
 * const balance = await client.getBalance('WAN', '0x...');
 * ```
 */
export default class IwanClient extends EventEmitter {
  private ws: WebSocket | any = null;
  private readonly apiKey: string;
  private readonly secretKey: string;
  private readonly option: Required<IwanClientOptions> & { isTestnet: boolean };
  private readonly isBrowser: boolean;

  private index = 0;
  private pending = new Map<number, PendingRequest>();
  private heartbeatTimer: NodeJS.Timeout | null = null;
  private tries = DEFAULT_CONFIG.maxTries;
  private lockReconnect = false;
  private manuallyClosed = false;

  private _readyPromise: Promise<void> | null = null;

  /**
   * Creates a new iWan client instance
   * @param apiKey - Your iWan API key (required)
   * @param secretKey - Your iWan secret key (required)
   * @param option - Optional configuration
   * @throws IWanError if APIKEY or SECRETKEY is missing
   */
  constructor(apiKey: string, secretKey: string, option: IwanClientOptions = {}) {
    super();

    if (!apiKey || !secretKey) {
      throw new IWanError('APIKEY and SECRETKEY are both required');
    }

    this.apiKey = apiKey;
    this.secretKey = secretKey;
    this.isBrowser = typeof window !== 'undefined';

    const net = option.isTestnet ? DEFAULT_CONFIG.testnet : DEFAULT_CONFIG.mainnet;
    this.option = {
      url: option.url ?? net.url,
      port: option.port ?? net.port,
      flag: option.flag ?? DEFAULT_CONFIG.flag,
      version: option.version ?? DEFAULT_CONFIG.version,
      clientType: option.clientType ?? DEFAULT_CONFIG.clientType,
      clientVersion: option.clientVersion ?? DEFAULT_CONFIG.clientVersion,
      timeout: option.timeout ?? DEFAULT_CONFIG.timeout,
      isTestnet: option.isTestnet ?? false,
    };

    this.createWebSocket().catch(e => this.emit('error', e));
  }

  private get wsUrl(): string {
    let url = `wss://${this.option.url}:${this.option.port}`;
    if (this.option.flag) url += `/${this.option.flag}`;
    url += `/${this.option.version}/${this.apiKey}`;
    return url;
  }

  private async createWebSocket() {
    let WSConstructor: any;
    if (this.isBrowser) {
      WSConstructor = (window as any).WebSocket;
    } else {
      const module = await import('ws');
      WSConstructor = module.default ?? module;
    }

    const options = this.isBrowser ? undefined : DEFAULT_CONFIG.wsOptions;
    this.ws = new WSConstructor(this.wsUrl, options);

    this.ws.onopen = () => {
      this.manuallyClosed = false;
      this.ws.isAlive = true;
      this.emit('open');
      this._resolveReadyPromise();
    };
    this.ws.onmessage = (event: any) => this.handleMessage(event.data ?? event);
    this.ws.onerror = (err: any) => {
      this.emit('error', err);
      this.clearPending('Connection error, reconnecting...');
      this._rejectReadyPromise();
      this.reconnect();
    };
    this.ws.onclose = (event: any) => {
      this.emit('close', event);
      if (!this.manuallyClosed) {
        this.clearPending('Connection closed by server, reconnecting...');
        this.reconnect();
      } else {
        this._rejectReadyPromise();
        this.emit('closed');
      }
    };

    if (!this.isBrowser && this.ws.on) {
      this.ws.on('pong', () => { this.ws.isAlive = true; });
    }

    this.startHeartbeat();
  }

  // ====================== Unified processing of ready Promise (revised core） ======================
  private _resolveReadyPromise() {
    if (this._readyPromise) {
      // No manual resolution is needed here, because it has already been resolved in the `once` handler.
      this._readyPromise = null;
    }
  }

  private _rejectReadyPromise() {
    if (this._readyPromise) {
      // No manual rejection is needed here, because it has already been rejected in the `once` handler.
      this._readyPromise = null;
    }
  }

  // ====================== Added: Wait for connection ready ======================
  /**
   * Wait for WebSocket connection to be ready
   * 
   * All public methods (`call`, `getBalance`, etc.) automatically call this internally.
   * You only need to call it manually if you want to wait before a batch of operations.
   * 
   * @returns Promise that resolves when connected
   * @throws IWanError when connection fails or manually closed
   */
  public async ready(): Promise<void> {
    if (this.isOpen() && !this.manuallyClosed) return Promise.resolve();

    if (!this._readyPromise) {
      this._readyPromise = new Promise((resolve, reject) => {
        const onOpen = () => {
          resolve();
          this._readyPromise = null;
        };
        const onFail = () => {
          reject(new IWanError('WebSocket connection failed or manually closed'));
          this._readyPromise = null;
        };

        this.once('open', onOpen);
        this.once('closed', onFail);
        this.once('error', onFail);
      });
    }
    return this._readyPromise;
  }

  // ====================== Clean up old requests ======================
  private clearPending(reason: string) {
    console.log("clearPending ===>", "before size", this.pending.size);
    const err = new IWanError(reason);
    this.pending.forEach((p) => p.reject(err));
    this.pending.clear();
    console.log("clearPending ===>", "after size", this.pending.size);
  }

  private handleMessage(data: any) {
    let msg: RPCResponse;
    try {
      const text = typeof data === 'string' ? data : data.toString();
      msg = JSON.parse(text);
    } catch {
      return;
    }

    const pending = this.pending.get(msg.id);
    if (pending) {
      this.pending.delete(msg.id);
      msg.error ? pending.reject(msg.error) : pending.resolve(msg.result);
    }
  }

  private startHeartbeat() {
    this.heartbeatTimer = setInterval(() => {
      if (!this.isOpen() || this.manuallyClosed || this.isBrowser) return;

      if (!this.ws.isAlive) {
        this.tries--;
        if (this.tries < 0) this.reconnect();
      } else {
        this.ws.isAlive = false;
        this.ws.ping();
      }
    }, DEFAULT_CONFIG.pingTime);
  }

  private reconnect() {
    if (this.manuallyClosed || this.lockReconnect) return;
    this.lockReconnect = true;

    setTimeout(() => {
      this.tries = DEFAULT_CONFIG.maxTries;
      this.createWebSocket().catch(e => this.emit('error', e));
      this.lockReconnect = false;
      console.log("reconnect")
      this.emit('reconnect');
    }, DEFAULT_CONFIG.reconnTime);
  }

  private isOpen(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  private async _request<T>(method: string, params: any = {}): Promise<T> {
    await this.ready();

    if (this.manuallyClosed || !this.isOpen()) {
      throw new IWanError('WebSocket manually closed or not connected');
    }

    const payload: RPCMessage = {
      jsonrpc: '2.0',
      method,
      params: { ...params, clientType: this.option.clientType, clientVersion: this.option.clientVersion },
      id: ++this.index,
    };

    const signed = await signPayload(payload, this.secretKey);

    return new Promise((resolve, reject) => {
      const id = signed.id;
      this.pending.set(id, { resolve, reject, time: Date.now() });

      this.ws.send(JSON.stringify(signed));

      setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new IWanError('Request timeout'));
        }
      }, this.option.timeout);
    });
  }

  private checkHash(hash: string): boolean {
    // check if it has the basic requirements of a hash
    return /^(0x)?[0-9a-fA-F]{64}$/i.test(hash)
  }

  // ====================== PUBLIC API ======================
  /**
   * @since 1.3.0
   * Generic RPC call (supports ALL iWan methods)
   * 
   * @param method - RPC method name (e.g. 'getBalance')
   * @param params - Parameters object
   * @returns Promise with result from server
   * @throws IWanError on timeout, connection error, or server error
   */
  public async call<T = any>(method: string, params: any = {}): Promise<T> {
    return await this._request(method, params);
  }

  public async monitorEvent(chainType: string, address: string, topics: string[]): Promise<any> {
    return await this._request('monitorEvent', { chainType, address, topics });
  }

  /**
   * Get balance of an address
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"ETH"</code>,  <code>"WAN"</code>, and other chains.
   * @param {string} address - The account being queried.
   * @returns {Promise<string>} - Balance as string.
   * @example
   * const ret = await sdk.getBalance("WAN", '0x2cc79fa3b80c5b9b02051facd02478ea88a78e2c');
   * console.log(ret);
   * // "10000000000000000000000"
   */
  public async getBalance(chainType: string, address: string): Promise<string> {
    return await this._request('getBalance', { chainType, address });
  }

  /**
   * Get balance for multiple Addresses in a single call.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"ETH"</code>,  <code>"WAN"</code>, and other chains.
   * @param {Array<string>} address - An array of addresses being queried.
   * @returns {Promise<any>} - Result of account role verification
   * @example
   * const ret = await sdk.getMultiBalances("WAN", ['0x2cc79fa3b80c5b9b02051facd02478ea88a78e2c']);
   * console.log(ret);
   * // {"0x2cc79fa3b80c5b9b02051facd02478ea88a78e2c": "10000000000000000000000"}
   */
  public async getMultiBalances(chainType: string, address: Array<string>): Promise<any> {
    return await this._request('getMultiBalances', { chainType, address });
  }

  /**
   * Get smart contract event log via topics.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"ETH"</code>,  <code>"WAN"</code>, and other chains.
   * @param {string} address - The contract address.
   * @param {Array<string|null>} topics - An array of string values which must each appear in the log entries. The order is important, if you want to leave topics out use null, e.g. [null, '0x00...'].
   * @param {any} [option] - An object value which describes the range between fromBlock and toBlock.
   * <br>&nbsp;&nbsp;<code>fromBlock</code> - The number of the earliest block (latest may be given to mean the most recent, block). By default 0.
   * <br>&nbsp;&nbsp;<code>toBlock</code> - The number of the latest block (latest may be given to mean the most recent, block). By default latest.
   * @returns {Promise<any[]>} - The smart contract event logs.
   * @example
   * const ret = await sdk.getScEvent('WAN', '0xda5b90dc89be59365ec44f3f2d7af8b6700d1167', ["0xa4345d0839b39e5a6622a55c68bd8f83ac8a68fad252a8363a2c09dbaf85c793", "0x0000000000000000000000000000000000000000000000000000000000000000"]);
   * console.log(ret);
   * // [
   * //   {
   * //     "address": "0xda5b90dc89be59365ec44f3f2d7af8b6700d1167",
   * //     "topics": [
   * //         "0xa4345d0839b39e5a6622a55c68bd8f83ac8a68fad252a8363a2c09dbaf85c793",
   * //         "0x0000000000000000000000000000000000000000000000000000000000000000"
   * //     ],
   * //     "data": "0x54657374206d6573736167650000000000000000000000000000000000000000",
   * //     "blockNumber": 1121916,
   * //     "transactionHash": "0x6bdd2acf6e946be40e2b3a39d3aaadd6d615d59c89730196870f640990a57cbe",
   * //     "transactionIndex": 0,
   * //     "blockHash": "0xedda83000829f7d0a0820a7bdf2103a3142a70c404f78fd1dfc7751dc007f5a2",
   * //     "logIndex": 0,
   * //     "removed": false
   * //   }
   * // ]
   */
  public async getScEvent(chainType: string, address: string, topics: Array<string|null>, option: any): Promise<any[]> {
    const {fromBlock, toBlock, ...otherOpts} = option || {};
    return await this._request('getScEvent', { chainType, address, topics, fromBlock: fromBlock || 0, toBlock: toBlock || 'latest', ...otherOpts});
  }

  /**
   * Get the owner of the specified contract from the specified chain.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"ETH"</code>,  <code>"WAN"</code>, and other EVM chains.
   * @param {string} scAddr - The token contract address for the specified token.
   * @returns {Promise<string>} - The owner of the specified contract.
   * @example
   * const ret = await sdk.getScOwner('WAN', '0x59adc38f0b3f64fb542b50e3e955e7a8c1eb3e3b');
   * console.log(ret);
   * // "0xbb8703ca8226f411811dd16a3f1a2c1b3f71825d"
   */
  public async getScOwner(chainType: string, scAddr: string): Promise<string> {
    return await this._request('getScOwner', { chainType, scAddr });
  }

  /**
   * Coin exchange ratio,such as 1 ETH to 880 WANs in ICO period, the precision is 10000, the ratio is 880*precision = 880,0000. The ratio would be changed according to the market value ratio periodically.
   * @since 1.3.0
   * @param {string} crossChain - The cross-chain native coin name that you want to search, should be <code>"ETH"</code> or <code>"BTC"</code>.
   * @returns {Promise<string>} - The owner of the specified contract.
   * @example
   * const ret = await sdk.getCoin2WanRatio('ETH');
   * console.log(ret);
   * // "20"
   */
  public async getCoin2WanRatio(crossChain: string): Promise<string> {
    return await this._request('getCoin2WanRatio', { crossChain });
  }

  /**
   * Get the detail UTXO info for Bitcoin-like chain.
   * @since 1.3.0
   * @param {string} chainType - The chain name that you want to search, should be <code>"BTC"</code>, <code>"LTC"</code>, <code>"DOGE"</code>.
   * @param {number} minconf - The min confirm number of BTC UTXO, usually 0.
   * @param {number} maxconf - The max confirm number of BTC UTXO, usually the confirmed blocks you want to wait for the UTXO.
   * @param {Array<string>} address - The contract address.
   * @param {any} [option] - A reserved parameter.
   * @returns {Promise<any[]>} - The smart contract event logs.
   * @example
   * const ret = await sdk.getUTXO('BTC', 0, 100, ["n35aUMToGvxJhYm7QVMtyBL83PTDKzPC1R"]);
   * console.log(ret);
   * // [
   * //    {
   * //      "txid": "302588f81dc5ad7972d3affc781adc6eb326227a6feda53a990e9b98b715edcc",
   * //      "vout": 0,
   * //      "address": "n35aUMToGvxJhYm7QVMtyBL83PTDKzPC1R",
   * //      "account": "",
   * //      "scriptPubKey": "76a914ec8626d9aa394317659a45cfcbd1f0762126c5e888ac",
   * //      "amount": 0.079,
   * //      "confirmations": 16,
   * //      "spendable": false,
   * //      "solvable": false,
   * //      "safe": true,
   * //      "value": 0.079
   * //    }
   * // ]
   */
  public async getUTXO(chainType: string, minconf: number, maxconf: number, address: string, option: any): Promise<any> {
    return await this._request('getUTXO', { chainType, address, minconf: minconf, maxconf: maxconf, ...(option || {}) });
  }

  /**
   * Get the vout with OP_RETURN info for Bitcoin-like chain.
   * @since 1.3.0
   * @param {string} chainType - The chain name that you want to search, should be <code>"BTC"</code>, <code>"LTC"</code>, <code>"DOGE"</code>.
   * @param {any} [option] - Optional:
  * <br>&nbsp;&nbsp;<code>address</code> - Optional, the address array that you want to search.
  * <br>&nbsp;&nbsp;<code>fromBlock</code> - Optional, the number of the earliest block (latest may be given to mean the most recent, block). By default 0.
  * <br>&nbsp;&nbsp;<code>toBlock</code> - Optional, the number of the latest block (latest may be given to mean the most recent, block). By default latest.
   * @returns {Promise<any[]>} - The vout with OP_RETURN info.
   * @example
   * const ret = await sdk.getOpReturnOutputs('BTC', {address:["n35aUMToGvxJhYm7QVMtyBL83PTDKzPC1R"]});
   * console.log(ret);
   * // [
   * //   {
   * //     "txid": "2c7a583b84fe0732fe17017bf0b17437bb5dcdad3ca8a8d661e86be666c33cc0",
   * //     "height": 101641,
   * //     "vout": [
   * //       {
   * //         "scriptPubKey": {
   * //           "addresses": [
   * //             "mzW2hdZN2um7WBvTDerdahKqRgj3md9C29"
   * //           ],
   * //           "asm": "04ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664b OP_CHECKSIG",
   * //           "hex": "4104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac",
   * //           "reqSigs": 1,
   * //           "type": "pubkey"
   * //         },
   * //         "value": 0.49743473,
   * //         "index": 1
   * //       },
   * //       {
   * //         "scriptPubKey": {
   * //           "asm": "OP_RETURN f25ce69be9489038099442ed615ca8b0003330821c2804f2763c7a8e72274d1c0000000000000a00",
   * //           "hex": "6a28f25ce69be9489038099442ed615ca8b0003330821c2804f2763c7a8e72274d1c0000000000000a00",
   * //           "type": "nulldata"
   * //         },
   * //         "value": 0,
   * //         "index": 2
   * //       }
   * //     ]
   * //   }
   * // ]
   */
  public async getOpReturnOutputs(chainType: string, option: any): Promise<any> {
    return await this._request('getOpReturnOutputs', { chainType, ...(option || {}) });
  }

  /**
   * Get the detailed cross-chain storemanGroup info for one cross-chain native coin, like the quota, etc.
   * @since 1.3.0
   * @param {string} crossChain - The cross-chain name that you want to search, should be <code>"ETH"</code> or <code>"BTC"</code>.
   * @param {any} [option] - A reserved parameter.
   * @returns {Promise<any[]>} - The detailed cross-chain storemanGroup info.
   * @example
   * const ret = await sdk.getStoremanGroups('ETH');
   * console.log(ret);
   * // [
   * //   {
   * //     "wanAddress": "0x06daa9379cbe241a84a65b217a11b38fe3b4b063",
   * //     "ethAddress": "0x41623962c5d44565de623d53eb677e0f300467d2",
   * //     "deposit": "128000000000000000000000",
   * //     "txFeeRatio": "10",
   * //     "quota": "400000000000000000000",
   * //     "inboundQuota": "290134198386719012352",
   * //     "outboundQuota": "85607176846820246993",
   * //     "receivable": "80000000000000000",
   * //     "payable": "24178624766460740655",
   * //     "debt": "109785801613280987648"
   * //   }
   * // ]
   */
  public async getStoremanGroups(crossChain: string, option: any): Promise<any> {
    return await this._request('getStoremanGroups', { crossChain, ...(option || {}) });
  }

  /**
   * Get the detail cross-chain storemanGroup info for one specific token contract, like the quota, etc.
   * @since 1.3.0
   * @param {string} crossChain - The cross-chain name that you want to search, should be <code>"ETH"</code> or <code>"EOS"</code>.
   * @param {string} tokenScAddr - The token contract address for the specified token.
   * @param {any} [option] - A reserved parameter.
   * @returns {Promise<any[]>} - The detailed cross-chain storemanGroup info.
   * @example
   * const ret = await sdk.getTokenStoremanGroups('ETH', '0x00f58d6d585f84b2d7267940cede30ce2fe6eae8');
   * console.log(ret);
   * // [
   * //   {
   * //     "tokenOrigAddr": "0xdbf193627ee704d38495c2f5eb3afc3512eafa4c",
   * //     "smgWanAddr": "0x765854f97f7a3b6762240c329331a870b65edd96",
   * //     "smgOrigAddr": "0x38b6c9a1575c90ceabbfe31b204b6b3a3ce4b3d9",
   * //     "wanDeposit": "5000000000000000000000",
   * //     "quota": "10000000000000000000000",
   * //     "txFeeRatio": "1",
   * //     "inboundQuota": "9999500000000000000000",
   * //     "outboundQuota": "500000000000000000",
   * //     "receivable": "0",
   * //     "payable": "0",
   * //     "debt": "500000000000000000"
   * //   }
   * // ]
   */
  public async getTokenStoremanGroups(crossChain: string, tokenScAddr: string, option: any): Promise<any> {
    return await this._request('getTokenStoremanGroups', { crossChain, tokenScAddr, ...(option || {}) });
  }

  /**
   * Get the current gas price in wei as string type.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"ETH"</code>,  <code>"WAN"</code>, and other EVM chains.
   * @param {any} [option] - A reserved parameter.
   * @returns {Promise<string>} - The current gas price in wei.
   * @example
   * const ret = await sdk.getGasPrice('WAN');
   * console.log(ret);
   * // "180000000000"
   */
  public async getGasPrice(chainType: string, option: any): Promise<string> {
    return await this._request('getGasPrice', { chainType, ...(option || {}) });
  }

  /**
   * Get token balance for a single address of a specified token on specified chain.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"ETH"</code>,  <code>"WAN"</code>, and other EVM chains.
   * @param {string} address - The account being queried.
   * @param {string} tokenScAddr - The token contract address for specified token. I.e., If chainType is <code>'WAN'</code>, it should be the token address for <code>"WETH"</code> or <code>"WBTC"</code>.
   * @param {any} [option] - A reserved parameter.
   * @returns {Promise<string>} - The current token balance.
   * @example
   * const ret = await sdk.getTokenBalance("WAN", "0x2cc79fa3b80c5b9b02051facd02478ea88a78e2c", "0x63eed4943abaac5f43f657d8eec098ca6d6a546e");
   * console.log(ret);
   * // "10000000000000000000000"
   */
  public async getTokenBalance(chainType: string, address: string, tokenScAddr: string, option: any): Promise<string> {
    return await this._request('getTokenBalance', { chainType, address, tokenScAddr, ...(option || {}) });
  }

  /**
   * Gets token balance for multiple addresses of specified token on Wanchain in a single call.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"ETH"</code>,  <code>"WAN"</code>, and other EVM chains.
   * @param {Array<string>} address - An array of addresses being queried.
   * @param {string} tokenScAddr - The token contract address for specified token. I.e., If chainType is <code>'WAN'</code>, it should be the token address for <code>"WETH"</code> or <code>"WBTC"</code>.
   * @param {any} [option] - A reserved parameter.
   * @returns {Promise<string>} - The current token balance.
   * @example
   * const ret = await sdk.getMultiTokenBalance("WAN", ["0xfac95c16da814d24cc64b3186348afecf527324f","0xfac95c16da814d24cc64b3186348afecf527324e"], "0x63eed4943abaac5f43f657d8eec098ca6d6a546e");
   * console.log(ret);
   * // {
   * //   "0xfac95c16da814d24cc64b3186348afecf527324f": "10000000000000000000000",
   * //   "0xfac95c16da814d24cc64b3186348afecf527324e": "0"
   * // }
   */
  public async getMultiTokenBalance(chainType: string, address: Array<string>, tokenScAddr: string, option: any): Promise<any> {
    return await this._request('getMultiTokenBalance', { chainType, address, tokenScAddr, ...(option || {}) });
  }

  /**
   * Gets all balances for address.
   * @since 1.3.0
   * @param {string} chainType - chainType The chain being queried. Currently supports <code>'XRP'</code>.
   * @param {string} address - String of address being queried.
   * @param {any} [option] - A reserved parameter.
   * @returns {Promise<string>} - The current balances.
   * @example
   * const ret = await sdk.getAllBalances("WAN", "rgiPXoiRiwYXrzmpno6rRnKdKtsvvvJmn");
   * console.log(ret);
   * // [
   * //     {
   * //         "currency": "XRP",
   * //         "value": "999.99976"
   * //     },
   * //     {
   * //         "value": "0",
   * //         "currency": "FOO",
   * //         "issuer": "rnqpsE8GSmLrZQzXguURJHjT7sN5S1XSqz"
   * //     },
   * //     {
   * //         "value": "1.012345678913579",
   * //         "currency": "BAR",
   * //         "issuer": "rnqpsE8GSmLrZQzXguURJHjT7sN5S1XSqz"
   * //     }
   * // ]
   */
  public async getAllBalances(chainType: string, address: string, option: any): Promise<any> {
    return await this._request('getAllBalances', { chainType, address, ...(option || {}) });
  }

  /**
   * Get total amount of certain token on specified chain.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"ETH"</code>,  <code>"WAN"</code>, and other EVM chains.
   * @param {string} tokenScAddr - The token contract address for the specified token.
   * @param {any} [option] - A reserved parameter.
   * @returns {Promise<string>} - The current token supply.
   * @example
   * const ret = await sdk.getTokenSupply("WAN", "0x63eed4943abaac5f43f657d8eec098ca6d6a546e");
   * console.log(ret);
   * // "30000000000000000000000"
   */
  public async getTokenSupply(chainType: string, tokenScAddr: string, option: any): Promise<string> {
    return await this._request('getTokenSupply', { chainType, tokenScAddr, ...(option || {}) });
  }

  /**
   * Get the token allowance for one specific account on one contract for one specific spender account on a certain chain.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"ETH"</code>,  <code>"WAN"</code>, and other EVM chains.
   * @param {string} tokenScAddr - The token contract address for the specified token.
   * @param {string} ownerAddr - The owner address on the specified contract.
   * @param {string} spenderAddr - The spender address on the specified contract.
   * @param {any} [option] - A reserved parameter.
   * @returns {Promise<string>} - The token allowance for one specific account on one contract for one specific spender account.
   * @example
   * const ret = await sdk.getTokenAllowance("ETH", "0xc5bc855056d99ef4bda0a4ae937065315e2ae11a", "0xc27ecd85faa4ae80bf5e28daf91b605db7be1ba8", "0xcdc96fea7e2a6ce584df5dc22d9211e53a5b18b1");
   * console.log(ret);
   * // "999999999999980000000000000"
   */
  public async getTokenAllowance(chainType: string, tokenScAddr: string, ownerAddr: string, spenderAddr: string, option: any): Promise<string> {
    return await this._request('getTokenAllowance', { chainType, tokenScAddr, ownerAddr, spenderAddr, ...(option || {}) });
  }

  /**
   * Get the info of token contract, like symbol and decimals, on certain chain.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"ETH"</code>,  <code>"WAN"</code>, and other EVM chains.
   * @param {string} tokenScAddr - The token contract address for the specified token.
   * @param {any} [option] - Optional:
   * <br>&nbsp;&nbsp;<code>tokenType</code> - The token type, Currently supports <code>'Erc20'</code> and <code>'Erc721'</code>.
   * @returns {Promise<string>} - The token info.
   * @example
   * const ret = await sdk.getTokenInfo("ETH", "0xc5bc855056d99ef4bda0a4ae937065315e2ae11a");
   * console.log(ret);
   * // {
   * //   "symbol": "WCT",
   * //   "decimals": "18"
   * // }
   */
  public async getTokenInfo(chainType: string, tokenScAddr: string, option: any): Promise<any> {
    return await this._request('getTokenInfo', { chainType, tokenScAddr, ...(option || {}) });
  }

  /**
   * Get the information for multiple tokens.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"ETH"</code>,  <code>"WAN"</code>, and other EVM chains.
   * @param {Array<string>} tokenScAddrArray - The token address array for the tokens that you want to query.
   * @param {any} [option] - Optional:
   * <br>&nbsp;&nbsp;<code>tokenType</code> - The token type, Currently supports <code>'Erc20'</code> and <code>'Erc721'</code>.
   * @returns {Promise<string>} - The information for multiple tokens.
   * @example
   * const ret = await sdk.getMultiTokenInfo("ETH", ["0xc5bc855056d99ef4bda0a4ae937065315e2ae11a","0x7017500899433272b4088afe34c04d742d0ce7df"]);
   * console.log(ret);
   * // {
   * //   "0xc5bc855056d99ef4bda0a4ae937065315e2ae11a": {
   * //     "symbol": "WCT",
   * //     "decimals": "18"
   * //   },
   * //   "0x7017500899433272b4088afe34c04d742d0ce7df": {
   * //     "symbol": "WCT_One",
   * //     "decimals": "18"
   * //   }
   * // }
   */
  public async getMultiTokenInfo(chainType: string, tokenScAddrArray: Array<string>, option: any): Promise<any> {
    return await this._request('getMultiTokenInfo', { chainType, tokenScAddrArray, ...(option || {}) });
  }

  /**
   * Get the nonce of an account.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"ETH"</code>,  <code>"WAN"</code>, and other EVM chains.
   * @param {string} address - The account being queried.
   * @param {any} [option] - A reserved parameter.
   * @returns {Promise<string>} - The nonce.
   * @example
   * const ret = await sdk.getNonce("WAN", "0x2cc79fa3b80c5b9b02051facd02478ea88a78e2c");
   * console.log(ret);
   * // "0x0"
   */
  public async getNonce(chainType: string, address: string, option: any): Promise<string> {
    return await this._request('getNonce', { chainType, address, ...(option || {}) });
  }

  /**
   * Get the pending nonce of an account.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"ETH"</code>,  <code>"WAN"</code>, and other EVM chains.
   * @param {string} address - The account being queried.
   * @param {any} [option] - A reserved parameter.
   * @returns {Promise<string>} - The nonce.
   * @example
   * const ret = await sdk.getNonceIncludePending("WAN", "0x2cc79fa3b80c5b9b02051facd02478ea88a78e2c");
   * console.log(ret);
   * // "0x0"
   */
  public async getNonceIncludePending(chainType: string, address: string, option: any): Promise<string> {
    return await this._request('getNonceIncludePending', { chainType, address, ...(option || {}) });
  }

  /**
   * Get the current latest block number.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"ETH"</code>,  <code>"WAN"</code>, and other EVM chains.
   * @param {any} [option] - A reserved parameter.
   * @returns {Promise<string>} - The current latest block number.
   * @example
   * const ret = await sdk.getBlockNumber("WAN");
   * console.log(ret);
   * // "119858"
   */
  public async getBlockNumber(chainType: string, option: any): Promise<string> {
    return await this._request('getBlockNumber', { chainType, ...(option || {}) });
  }

  /**
   * Submit a pre-signed transaction for broadcast to certain chain.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"ETH"</code>,  <code>"WAN"</code>,  <code>"BTC"</code>, and other chains.
   * @param {string} signedTx - The signedTx you want to send.
   * @param {any} [option] - A reserved parameter.
   * @returns {Promise<string>} - The transaction hash.
   * @example
   * const ret = await sdk.sendRawTransaction('WAN', '0xf86e0109852e90edd000832dc6c0946ed9c11cbd8a6ae8355fa62ebca48493da572661880de0b6b3a7640000801ca0bd349ec9f51dd171eb5c59df9a6b8c5656eacb6793bed945a7ec69135f191abfa0359da11e8a4fdd51b52a8752ac32f9125d168441546d011406736bce67b8a356');
   * console.log(ret);
   * // "0x4dcfc82728b5a9307f249ac095c8e6fcc436db4f85a094a0c5a457255c20f80f"
   */
  public async sendRawTransaction(chainType: string, signedTx: string, option: any): Promise<string> {
    return await this._request('sendRawTransaction', { chainType, signedTx, ...(option || {}) });
  }

  /**
   * Get the transaction detail via transaction hash on certain chain.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"ETH"</code>,  <code>"WAN"</code>, <code>"BTC"</code>, and other chains.
   * @param {string} txHash - The transaction hash you want to search.
   * @param {any} [option] - A reserved parameter.
   * @returns {Promise<any>} - The transaction detail.
   * @example
   * const ret = await sdk.getTxInfo("WAN", "0xd2a5b1f403594dbc881e466d46a4cac3d6cf202476b1277876f0b24923d032da");
   * console.log(ret);
   * // {
   * //   "txType": "0x1",
   * //   "blockHash": "0xcb76ea6649d801cc45294f4d0858bad1ca0c2b169b20c4beae2852c57a7f69c9",
   * //   "blockNumber": 1137680,
   * //   "from": "0xed1baf7289c0acef52db0c18e1198768eb06247e",
   * //   "gas": 1000000,
   * //   "gasPrice": "320000000000",
   * //   "hash": "0xd2a5b1f403594dbc881e466d46a4cac3d6cf202476b1277876f0b24923d032da",
   * //   "input": "0x642b273754657374206d6573736167650000000000000000000000000000000000000000",
   * //   "nonce": 26,
   * //   "to": "0xda5b90dc89be59365ec44f3f2d7af8b6700d1167",
   * //   "transactionIndex": 0,
   * //   "value": "0",
   * //   "v": "0x1b",
   * //   "r": "0xe3a5a5d73d0b6512676723bc4bab4f7ffe01476f8cbc9631976890e175d487ac",
   * //   "s": "0x3a79e17290fe2a9f4e5b5c5431eb322882729d68ca0d736c5d9b1f3285c9169e"
   * // }
   */
  public async getTxInfo(chainType: string, txHash: string, option: any): Promise<any> {
    return await this._request('getTxInfo', { chainType, txHash, ...(option || {}) });
  }

  /**
   * Get the transaction mined result on certain chain.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"ETH"</code>,  <code>"WAN"</code>, and other chains.
   * @param {number} waitBlocks - The confirm-block-number you want to set.
   * @param {string} txHash - The transaction hash you want to search.
   * @param {any} [option] - Optional.
   * <br>&nbsp;&nbsp;<code>version</code> - The result format version you want to search, using <code>undefined</code> that means legacy format as default.
   * @returns {Promise<any>} - The transaction mined result.
   * @example
   * const ret = await sdk.getTransactionConfirm("WAN", 6, "0xd2a5b1f403594dbc881e466d46a4cac3d6cf202476b1277876f0b24923d032da");
   * console.log(ret);
   * // {
   * //   "blockHash": "0xcb76ea6649d801cc45294f4d0858bad1ca0c2b169b20c4beae2852c57a7f69c9",
   * //   "blockNumber": 1137680,
   * //   "contractAddress": null,
   * //   "cumulativeGasUsed": 29572,
   * //   "from": "0xed1baf7289c0acef52db0c18e1198768eb06247e",
   * //   "gasUsed": 29572,
   * //   "logs": [{
   * //     "address": "0xda5b90dc89be59365ec44f3f2d7af8b6700d1167",
   * //     "topics": ["0xa4345d0839b39e5a6622a55c68bd8f83ac8a68fad252a8363a2c09dbaf85c793", "0x0000000000000000000000000000000000000000000000000000000000000005"],
   * //     "data": "0x54657374206d6573736167650000000000000000000000000000000000000000",
   * //     "blockNumber": 1137680,
   * //     "transactionHash": "0xd2a5b1f403594dbc881e466d46a4cac3d6cf202476b1277876f0b24923d032da",
   * //     "transactionIndex": 0,
   * //     "blockHash": "0xcb76ea6649d801cc45294f4d0858bad1ca0c2b169b20c4beae2852c57a7f69c9",
   * //     "logIndex": 0,
   * //     "removed": false
   * //   }],
   * //   "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000001000000800000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000200000000000",
   * //   "status": "0x1",
   * //   "to": "0xda5b90dc89be59365ec44f3f2d7af8b6700d1167",
   * //   "transactionHash": "0xd2a5b1f403594dbc881e466d46a4cac3d6cf202476b1277876f0b24923d032da",
   * //   "transactionIndex": 0
   * // }
   */
  public async getTransactionConfirm(chainType: string, waitBlocks: number, txHash: string, option: any): Promise<any> {
    return await this._request('getTransactionConfirm', { chainType, waitBlocks, txHash, ...(option || {}) });
  }

  /**
   * Get the receipt of a transaction by transaction hash on certain chain.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"ETH"</code>,  <code>"WAN"</code>, and other chains.
   * @param {string} txHash - The transaction hash you want to search.
   * @param {any} [option] - Optional.
   * <br>&nbsp;&nbsp;<code>version</code> - The result format version you want to search, using <code>undefined</code> that means legacy format as default.
   * @returns {Promise<any>} - The receipt of a transaction.
   * @example
   * const ret = await sdk.getTransactionReceipt("WAN", "0xc18c4bdf0d40c4bb2f34f0273eaf4dc674171fbf33c3301127e1d4c85c574ebe");
   * console.log(ret);
   * // {
   * //   "logs": [],
   * //   "blockHash": "0x18198d5e42859067db405c9144306f7da87210a8604aac66ef6759b14a199d6b",
   * //   "blockNumber": 2548378,
   * //   "contractAddress": null,
   * //   "cumulativeGasUsed": 21000,
   * //   "from": "0xdcfffcbb1edc98ebbc5c7a6b3b700a6748eca3b0",
   * //   "gasUsed": 21000,
   * //   "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
   * //   "status": "0x1",
   * //   "to": "0x157908807e95f864284e84cc5d307ce6f3574532",
   * //   "transactionHash": "0xc18c4bdf0d40c4bb2f34f0273eaf4dc674171fbf33c3301127e1d4c85c574ebe",
   * //   "transactionIndex": 0
   * // }
   */
  public async getTransactionReceipt(chainType: string, txHash: string, option: any): Promise<any> {
    return await this._request('getTransactionReceipt', { chainType, txHash, ...(option || {}) });
  }

  /**
   * Get transaction information in a given block by block number or block hash on certain chain.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"ETH"</code>,  <code>"WAN"</code>, and other chains.
   * @param {string} blockHashOrBlockNumber - The blockHash or the blockNumber you want to search.
   * @param {any} [option] - A reserved parameter.
   * @returns {Promise<any>} - The transaction information.
   * @example
   * const ret = await sdk.getTransByBlock("WAN", "0xc18c4bdf0d40c4bb2f34f0273eaf4dc674171fbf33c3301127e1d4c85c574ebe");
   * // const ret = await sdk.getTransByBlock("WAN", "984133");
   * console.log(ret);
   * // [
   * //   {
   * //     "blockNumber": 984133,
   * //     "gas": 4700000,
   * //     "nonce": 414,
   * //     "transactionIndex": 0,
   * //     "txType": "0x1",
   * //     "blockHash": "0xaa0fc2a8a868566f2e4888b2942ec05c47c2254e8b81e43d3ea87420a09126c2",
   * //     "from": "0xbb9003ca8226f411811dd16a3f1a2c1b3f71825d",
   * //     "gasPrice": "180000000000",
   * //     "hash": "0x2c6dee69c9cc5676484d80d173d683802a4f761d5785a694b4262fbf39dff8fe",
   * //     "input": "0xfdacd5760000000000000000000000000000000000000000000000000000000000000002",
   * //     "to": "0x92e8ae701cd081ae8f0cb03dcae2e57b9b261667",
   * //     "value": "0",
   * //     "v": "0x29",
   * //     "r": "0x1c1ad7e8ee64fc284adce0910d6f811933af327b20cb8adba392a1b24a15054f",
   * //     "s": "0x690785383bed28c9a951b30329a066cb78062f63febf5aa1ca7e7ef62a2108cb"
   * //   }
   * // ]
   */
  public async getTransByBlock(chainType: string, blockHashOrBlockNumber: string, option: any): Promise<any> {
    const blockOpt = this.checkHash(blockHashOrBlockNumber) ? {blockHash: blockHashOrBlockNumber} : {blockNumber: blockHashOrBlockNumber};
    return await this._request('getTransByBlock', { chainType, ...blockOpt, ...(option || {}) });
  }

  /**
   * Get transaction information via the specified address on certain chain.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"ETH"</code>,  <code>"WAN"</code>, and other chains.
   * @param {string} address - The account's address that you want to search.
   * @param {any} [option] - A reserved parameter.
   * @returns {Promise<any>} - The transaction information.
   * @example
   * const ret = await sdk.getTransByAddress("WAN", "0xbb9003ca8226f411811dd16a3f1a2c1b3f71825d");
   * console.log(ret);
   * // [
   * //   {
   * //     "blockNumber": 1004796,
   * //     "gas": 90000,
   * //     "nonce": 505,
   * //     "transactionIndex": 0,
   * //     "txType": "0x1",
   * //     "blockHash": "0x604e45aa6b67b1957ba793e534878d94bfbacd38eed2eb51990de097595a334e",
   * //     "from": "0xbb9003ca8226f411811dd16a3f1a2c1b3f71825d",
   * //     "gasPrice": "180000000000",
   * //     "hash": "0x353545658d513ff4fe1db9b0f979a24a831ae0949b37bc1afefc8179fc29b358",
   * //     "input": "0x",
   * //     "to": "0x8fbc408bef86476e3098dc539762d4021092bbde",
   * //     "value": "100000000000000000000",
   * //     "v": "0x2a",
   * //     "r": "0xbe8f287930782cff4d2e12e4a55c46765b610b88d13bc1a060a4565f3316e933",
   * //     "s": "0x7a297e96c54fffd124833462e03725ea8d168465d34a3e577afbaa9d05a99cd0"
   * //   },
   * //   {
   * //     "blockNumber": 1004818,
   * //     "gas": 21000,
   * //     "nonce": 0,
   * //     "transactionIndex": 0,
   * //     "txType": "0x1",
   * //     "blockHash": "0xbb5769654036fdb768ede5b1a172298d408808e7dcb78a82b3c8d5ef32fc67cb",
   * //     "from": "0x8fbc408bef86476e3098dc539762d4021092bbde",
   * //     "gasPrice": "200000000000",
   * //     "hash": "0xee3371655a53e6d413c3b9d570fee8852989554989fde51136cf3b9c672e272d",
   * //     "input": "0x",
   * //     "to": "0xc68b75ca4e4bf0b71e3594452a5e47b11d287724",
   * //     "value": "1000000000000000000",
   * //     "v": "0x2a",
   * //     "r": "0x4341dcd4156050b664b9c977644756201a6357c7b12e5db86b370a38b1ed6dfb",
   * //     "s": "0x43b380fc67394e8b9483af97f5de067ef6617b17cfaa75517f07ec8d166f3c65"
   * //   }
   * // ]
   */
  public async getTransByAddress(chainType: string, address: string, option: any): Promise<any> {
    return await this._request('getTransByAddress', { chainType, address, ...(option || {}) });
  }

  /**
   * Get transaction information via the specified address between the specified startBlockNo and endBlockNo on certain chain.
   * <br>Comments:
   * <br>&nbsp;&nbsp;&nbsp;&nbsp;if no <code>startBlockNo</code> given, <code>startBlockNo</code> will be set to 0;
   * <br>&nbsp;&nbsp;&nbsp;&nbsp;if no <code>endBlockNo</code> given, <code>endBlockNo</code> will be set to the newest blockNumber.
   * <br><br><strong>Returns:</strong>
   * <br><font color=&#39;blue&#39;>«Promise,undefined»</font> Returns undefined if used with callback or a promise otherwise.
   * 
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"WAN"</code>.
   * @param {string} address - The account's address that you want to search.
   * @param {number} startBlockNo - The start block number that you want to search from.
   * @param {number} endBlockNo - The end block number that you want to search to.
   * @param {any} [option] - Optional.
   * <br>&nbsp;&nbsp;<code>counterparty</code> - The string of account's address that you want to search. Only for <code>"XRP"</code>. If provided, only return transactions with this account as a counterparty to the transaction.
   * <br>&nbsp;&nbsp;<code>earliestFirst</code> - Boolean. Only for <code>"XRP"</code>. If true, sort transactions so that the earliest ones come first. By default, the newest transactions will come first.
   * <br>&nbsp;&nbsp;<code>initiated</code> - Boolean. Only for <code>"XRP"</code>. If true, return only transactions initiated by the account specified by address. If false, return only transactions not initiated by the account specified by address.
   * <br>&nbsp;&nbsp;<code>limit</code> - Number. Only for <code>"XRP"</code>. If specified, return at most this many transactions.
   * <br>&nbsp;&nbsp;<code>types</code> - Array. Only for <code>"XRP"</code>. Only return transactions of the specified Transaction Types. Currently supports <code>"payment"</code>, <code>"order"</code>, <code>"orderCancellation"</code>, <code>"trustline"</code>, <code>"settings"</code>, <code>"escrowCreation"</code>, <code>"escrowCancellation"</code>, <code>"escrowExecution"</code>, <code>"checkCreate"</code>, <code>"checkCancel"</code>, <code>"checkCash"</code>, <code>"paymentChannelCreate"</code>, <code>"paymentChannelFund"</code>, <code>"paymentChannelClaim"</code>, <code>"ticketCreate"</code>.
   * <br>&nbsp;&nbsp;<code>version</code> - The result format version you want to search, using <code>undefined</code> that means legacy format as default.
   * @returns {Promise<any>} - The transaction information.
   * @example
   * const ret = await sdk.getTransByAddressBetweenBlocks("WAN", "0xbb9003ca8226f411811dd16a3f1a2c1b3f71825d", 984119, 984120);
   * console.log(ret);
   * // [
   * //   {
   * //     "blockNumber": 984119,
   * //     "gas": 4700000,
   * //     "nonce": 407,
   * //     "transactionIndex": 0,
   * //     "txType": "0x1",
   * //     "blockHash": "0xdf59acacabe8c1b64ca6ff611c629069731d9dae60f4b0cc753c4a0571ea7f27",
   * //     "from": "0xbb9003ca8226f411811dd16a3f1a2c1b3f71825d",
   * //     "gasPrice": "180000000000",
   * //     "hash": "0xf4610446d836b95d577ba723e1df55258e4f602cfa26d5ada3b50fa2fe82b469",
   * //     "input": "0x6060604052341561000f57600080fd5b336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506102d78061005e6000396000f300606060405260043610610062576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680630900f01014610067578063445df0ac146100a05780638da5cb5b146100c9578063fdacd5761461011e575b600080fd5b341561007257600080fd5b61009e600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610141565b005b34156100ab57600080fd5b6100b3610220565b6040518082815260200191505060405180910390f35b34156100d457600080fd5b6100dc610226565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b341561012957600080fd5b61013f600480803590602001909190505061024b565b005b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16141561021c578190508073ffffffffffffffffffffffffffffffffffffffff1663fdacd5766001546040518263ffffffff167c010000000000000000000000000000000000000000000000000000000002815260040180828152602001915050600060405180830381600087803b151561020b57600080fd5b5af1151561021857600080fd5b5050505b5050565b60015481565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614156102a857806001819055505b505600a165627a7a72305820de682f89b485041a9206a7304a95a151cd2363297029280359a4ca996dcaeda20029",
   * //     "to": null,
   * //     "value": "0",
   * //     "v": "0x29",
   * //     "r": "0xd14dfde02e305a945e6a09b6dbd5fe1f1bd5a6dc0721c15f72732aa10a3829b3",
   * //     "s": "0x56923b20a15f02633295b415ae52161529d560580dfcd62a97bc394c841bea37"
   * //   }
   * // ]
   */
  public async getTransByAddressBetweenBlocks(chainType: string, address: string, startBlockNo: number, endBlockNo: number, option: any): Promise<any> {
    return await this._request('getTransByAddressBetweenBlocks', { chainType, address, startBlockNo, endBlockNo, ...(option || {}) });
  }

  /**
   * Get the block information about a block by block number on certain chain.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"ETH"</code>,  <code>"WAN"</code>, and other chains.
   * @param {number|string} blockNumber - The blockNumber you want to search.
   * @param {any} [option] - A reserved parameter.
   * @returns {Promise<any>} - The block information.
   * @example
   * const ret = await sdk.getBlockByNumber("WAN", "670731");
   * console.log(ret);
   * // {
   * //   "size": 727,
   * //   "timestamp": 1522575814,
   * //   "transactions": ["0x4dcfc82728b5a9307f249ac095c8e6fcc436db4f85a094a0c5a457255c20f80f"],
   * //   "uncles": [],
   * //   "difficulty": "5812826",
   * //   "extraData": "0xd783010004846765746887676f312e392e32856c696e75780000000000000000de43ad982c5ccfa922f701d9ac91d47ceaaeeea7e1cc092b1ff6c3c5dcce70a07cf5a79886ff0cc02254ec0de51f1a6881a69a38cd2866a5c0dddbe0dd0f2ce301",
   * //   "gasLimit": 4712388,
   * //   "gasUsed": 21000,
   * //   "hash": "0xeb3b437d765d4da9210481c2dd612fa9d0c51e0e83120ee7f573ed9d6296e9a8",
   * //   "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
   * //   "miner": "0x321a210c019790308abb948360d144e7e00b7dc5",
   * //   "mixHash": "0x691299af763a758e94200545b8a5fe9d4f2cedbbfea031a1bbc540cbde4631d1",
   * //   "nonce": "0x2c8dd099eda5b188",
   * //   "number": 670731,
   * //   "parentHash": "0xd907820c7a46ba668a7e5bda8c6a23ec250877b853a85d8343688337f967b2d9",
   * //   "receiptsRoot": "0x056b23fbba480696b65fe5a59b8f2148a1299103c4f57df839233af2cf4ca2d2",
   * //   "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
   * //   "stateRoot": "0xafbfae425a7fed863662f88d64819132079b43ac4d85988ab6cce7f9342348af",
   * //   "totalDifficulty": "3610551057115",
   * //   "transactionsRoot": "0x96fc902544191c38f1c9a2725ea2ae29e34246fb4e95728f3e72added7c9574b"
   * // }
   */
  public async getBlockByNumber(chainType: string, blockNumber: string, option: any): Promise<any> {
    return await this._request('getBlockByNumber', { chainType, blockNumber, ...(option || {}) });
  }

  /**
   * Get the block information about a block by block number on certain chain.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"ETH"</code>,  <code>"WAN"</code>, and other chains.
   * @param {string} blockHash - The blockHash you want to search.
   * @param {any} [option] - A reserved parameter.
   * @returns {Promise<any>} - The block information.
   * @example
   * const ret = await sdk.getBlockByHash("WAN", "0xeb3b437d765d4da9210481c2dd612fa9d0c51e0e83120ee7f573ed9d6296e9a8");
   * console.log(ret);
   * // {
   * //   "size": 727,
   * //   "timestamp": 1522575814,
   * //   "transactions": ["0x4dcfc82728b5a9307f249ac095c8e6fcc436db4f85a094a0c5a457255c20f80f"],
   * //   "uncles": [],
   * //   "difficulty": "5812826",
   * //   "extraData": "0xd783010004846765746887676f312e392e32856c696e75780000000000000000de43ad982c5ccfa922f701d9ac91d47ceaaeeea7e1cc092b1ff6c3c5dcce70a07cf5a79886ff0cc02254ec0de51f1a6881a69a38cd2866a5c0dddbe0dd0f2ce301",
   * //   "gasLimit": 4712388,
   * //   "gasUsed": 21000,
   * //   "hash": "0xeb3b437d765d4da9210481c2dd612fa9d0c51e0e83120ee7f573ed9d6296e9a8",
   * //   "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
   * //   "miner": "0x321a210c019790308abb948360d144e7e00b7dc5",
   * //   "mixHash": "0x691299af763a758e94200545b8a5fe9d4f2cedbbfea031a1bbc540cbde4631d1",
   * //   "nonce": "0x2c8dd099eda5b188",
   * //   "number": 670731,
   * //   "parentHash": "0xd907820c7a46ba668a7e5bda8c6a23ec250877b853a85d8343688337f967b2d9",
   * //   "receiptsRoot": "0x056b23fbba480696b65fe5a59b8f2148a1299103c4f57df839233af2cf4ca2d2",
   * //   "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
   * //   "stateRoot": "0xafbfae425a7fed863662f88d64819132079b43ac4d85988ab6cce7f9342348af",
   * //   "totalDifficulty": "3610551057115",
   * //   "transactionsRoot": "0x96fc902544191c38f1c9a2725ea2ae29e34246fb4e95728f3e72added7c9574b"
   * // }
   */
  public async getBlockByHash(chainType: string, blockHash: string, option: any): Promise<any> {
    return await this._request('getBlockByHash', { chainType, blockHash, ...(option || {}) });
  }

  /**
   * Get the number of transaction in a given block by block number or block hash on certain chain.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"ETH"</code>,  <code>"WAN"</code>, and other EVM chains.
   * @param {string} blockHashOrBlockNumber - The blockHash or the blockNumber you want to search.
   * @param {any} [option] - A reserved parameter.
   * @returns {Promise<number>} - The block transaction count.
   * @example
   * const ret = await sdk.getBlockTransactionCount("WAN", "0xeb3b437d765d4da9210481c2dd612fa9d0c51e0e83120ee7f573ed9d6296e9a8");
   * // const ret = await sdk.getBlockTransactionCount("WAN", "670731");
   * console.log(ret);
   * // 1
   */
  public async getBlockTransactionCount(chainType: string, blockHashOrBlockNumber: string, option: any): Promise<number> {
    const blockOpt = this.checkHash(blockHashOrBlockNumber) ? {blockHash: blockHashOrBlockNumber} : {blockNumber: blockHashOrBlockNumber};
    return await this._request('getBlockTransactionCount', { chainType, ...blockOpt, ...(option || {}) });
  }

  /**
   * Get transaction count on certain chain.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"WAN"</code>.
   * @param {any} [option] - Optional.
   * <br>&nbsp;&nbsp;<code>address</code> - The account's address that you want to search.
   * <br>&nbsp;&nbsp;<code>startBlockNo</code> - The start block number that you want to search from.
   * <br>&nbsp;&nbsp;<code>endBlockNo</code> - The end block number that you want to search to.
   * @returns {Promise<number>} - The transaction count.
   * @example
   * const ret = await sdk.getTransCount("WAN", {"address":"0x0b80f69fcb2564479058e4d28592e095828d24aa", "startBlockNo":3607100, "endBlockNo":3607130});
   * console.log(ret);
   * // 1
   */
  public async getTransCount(chainType: string, option: any): Promise<number> {
    return await this._request('getTransCount', { chainType, ...(option || {}) });
  }

  /**
   * Returns an object with serializedTransaction(buffer) and empty signatures for the given actions with blocksBehind and expireSeconds.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried. Currently supports <code>'EOS'</code> or <code>'XRP'</code>.
   * @param {any} tx - The transaction to be packed.
   * <br>&nbsp;&nbsp;<code>actions</code> - required Array of objects (Action).
   * <br>&nbsp;&nbsp;<code>blocksBehind</code> - Optional, default is 3.
   * <br>&nbsp;&nbsp;<code>expireSeconds</code> - Optional, default is 30.
   * <br> If <code>blocksBehind</code> and <code>expireSeconds</code> are set, the block <code>blocksBehind</code> the head block retrieved from JsonRpc's <code>get_info</code> is set as the reference block and the transaction header is serialized using this reference block and the expiration field.
   * @param {any} [option] - Optional.
   * <br>&nbsp;&nbsp;<code>version</code> - The result format version you want to search, using <code>undefined</code> that means legacy format as default.
   * @returns {Promise<any>} - The packed transaction.
   * @example
   * const ret = await sdk.packTransaction("EOS", {"actions":[{"account":"eosio","name":"delegatebw","authorization":[{"actor":"aarontestnet","permission":"active"}],"data":{"from":"aarontestnet","receiver":"aarontestnet","stake_net_quantity":"0.0001 EOS","stake_cpu_quantity":"0.0001 EOS","transfer":false}}]});
   * console.log(ret);
   * // {
   * //   "serializedTransaction": {
   * //     "0": 177,
   * //     "1": 226,
   * //     "2": 138,
   * //     "3": 94,
   * //     "4": 122,
   * //     "5": 95,
   * //     "...": "...",
   * //     "98": 0
   * //   },
   * //   "signatures": []
   * // }
   */
  public async packTransaction(chainType: string, tx: object, option: any): Promise<any> {
    return await this._request('packTransaction', { chainType, tx, ...(option || {}) });
  }

  /**
   * Get the specific public parameter value of one contract on certain chain.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"WAN"</code>, <code>'ETH'</code> and other EVM chain.
   * @param {string} scAddr - The token contract address for the specified token.
   * @param {string} name - The name of the specific contract parameter.
   * @param {Array} abi - The ABI of the specific contract.
   * @returns {Promise<any>} - The specific public parameter value.
   * @example
   * const ret = await sdk.getScVar("WAN", "0x55ba61f4da3166487a804bccde7ee4015f609f45", "addr", [/The Abi of the contracts/]);
   * console.log(ret);
   * // "0x2ecb855170c941f239ffe3495f3e07cceabd8421"
   */
  public async getScVar(chainType: string, scAddr: string, name: string, abi: Array<any>, version: string): Promise<any> {
    return await this._request('getScVar', { chainType, scAddr, name, abi, version });
  }

  /**
   * Get the specific public map value of one contract on certain chain.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"WAN"</code>, <code>'ETH'</code> and other EVM chain.
   * @param {string} scAddr - The token contract address for the specified token.
   * @param {string} name - The name of the specific contract parameter.
   * @param {string} key - The key of parameter of the specific contract public map.
   * @param {Array} abi - The ABI of the specific contract.
   * @returns {Promise<any>} - The specific public map value.
   * @example
   * const ret = await sdk.getScMap("WAN", "0x55ba61f4da3166487a804bccde7ee4015f609f45", "mapAddr", "key", [/The Abi of the contracts/]);
   * console.log(ret);
   * // "0x2ecb855170c941f239ffe3495f3e07cceabd8421"
   */
  public async getScMap(chainType: string, scAddr: string, name: string, key: string, abi: Array<any>, version: string): Promise<any> {
    return await this._request('getScMap', { chainType, scAddr, name, key, abi, version });
  }

  /**
   * Call the specific public function of one contract on certain chain.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"WAN"</code>, <code>'ETH'</code> and other EVM chain.
   * @param {string} scAddr - The token contract address for the specified token.
   * @param {string} name - The name of the specific contract parameter.
   * @param {Array} args - The parameters array a of the specific contract public function.
   * @param {Array} abi - The ABI of the specific contract.
   * @param {any} [option] - A reserved parameter.
   * @returns {Promise<any>} - The result to call the specific public function.
   * @example
   * const ret = await sdk.callScFunc("WAN", "0x55ba61f4da3166487a804bccde7ee4015f609f45", "getPriAddress", [], [/The Abi of the contracts/]);
   * console.log(ret);
   * // "0x8cc420e422b3fa1c416a14fc600b3354e3312524"
   */
  public async callScFunc(chainType: string, scAddr: string, name: string, args: Array<any>, abi: Array<any>, version: string, option: any): Promise<any> {
    return await this._request('callScFunc', { chainType, scAddr, name, args, abi, version, ...(option || {}) });
  }

  /**
   * Get the x value of p2sh by hash(x) from BTC.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"BTC"</code>.
   * @param {string} hashX - The certain hashX that you want to search.
   * @returns {Promise<any>} - The x value of p2sh by hash(x).
   * @example
   * const ret = await sdk.getP2shxByHashx("BTC", "d2a5b1f403594dbc881e466d46a4cac3d6cf202476b1277876f0b24923d032da");
   * console.log(ret);
   * // "2ecb855170c941f239ffe3495f3e07cceabd8421"
   */
  public async getP2shxByHashx(chainType: string, hashX: string): Promise<string> {
    return await this._request('getP2shxByHashx', { chainType, hashX });
  }

  /**
   * Send a <code>'import address'</code> command to Bitcoin-like chain.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"BTC"</code>.
   * @param {string} address - The BTC account address you want to import to the node to scan transactions.
   * @returns {Promise<any>}
   * @example
   * const ret = await sdk.importAddress("BTC", "mmmmmsdfasdjflaksdfasdf");
   * console.log(ret);
   * // "success"
   */
  public async importAddress(chainType: string, address: string): Promise<string> {
    return await this._request('importAddress', { chainType, address });
  }

  /**
   * Query a <code>'estimatesmartfee'</code> command to Bitcoin-like chain.
   * @since 1.3.0
   * @param {string} chainType - The chain name that you want to search, should be <code>"BTC"</code>, <code>"LTC"</code> and <code>"DOGE"</code>.
   * @param {any} [option] - Optional:
   * <br>&nbsp;&nbsp;<code>target</code> - The numeric of confirmation target in blocks (1 - 1008).
   * <br>&nbsp;&nbsp;<code>mode</code> - The string of fee estimate mode.
   * <br>&nbsp;&nbsp;<code>version</code> - The result format version you want to search, using <code>undefined</code> that means legacy format as default.
   * @returns {Promise<any>} - The result of <code>'estimatesmartfee'</code>.
   * @example
   * const ret = await sdk.estimateSmartFee("BTC");
   * console.log(ret);
   * // "10500000000000"
   */
  public async estimateSmartFee(chainType: string, option: any): Promise<any> {
    return await this._request('estimateSmartFee', { chainType, ...(option || {}) });
  }

  /**
   * Get the information of tokens which are supported for cross-chain ability.
   * @since 1.3.0
   * @param {string} crossChain - The cross-chain name that you want to search, should be <code>"ETH"</code>.
   * @param {any} [option] - A reserved parameter.
   * @returns {Promise<any>} - The information of tokens.
   * @example
   * const ret = await sdk.getRegTokens("ETH");
   * console.log(ret);
   * // [
   * //   {
   * //     "tokenOrigAddr": "0x54950025d1854808b09277fe082b54682b11a50b",
   * //     "tokenWanAddr": "0x67f3de547c7f3bc77095686a9e7fe49397e59cdf",
   * //     "ratio": "15000000",
   * //     "minDeposit": "10000000000000000000",
   * //     "origHtlc": "0x149f1650f0ff097bca88118b83ed58fb1cfc68ef",
   * //     "wanHtlc": "0x27feb1785f61504619a105faa00f57c49cc4d9c3",
   * //     "withdrawDelayTime": "259200",
   * //     "tokenHash": "0xe6bb4913c8cfb38d44a01360bb7874c58812e14b9154543bb67783e611e0475b",
   * //     "name": "Wanchain MKR Crosschain Token",
   * //     "symbol": "MKR",
   * //     "decimals": "18",
   * //     "iconData": "/9j/4AAQ...",
   * //     "iconType": "jpg"
   * //   },
   * //   {
   * //     "tokenOrigAddr": "0xdbf193627ee704d38495c2f5eb3afc3512eafa4c",
   * //     "tokenWanAddr": "0xda16e66820a3c64c34f2b35da3f5e1d1742274cb",
   * //     "ratio": "20000",
   * //     "minDeposit": "10000000000000000000",
   * //     "origHtlc": "0x149f1650f0ff097bca88118b83ed58fb1cfc68ef",
   * //     "wanHtlc": "0x27feb1785f61504619a105faa00f57c49cc4d9c3",
   * //     "withdrawDelayTime": "259200",
   * //     "tokenHash": "0x0cfee48dd8c8e32ad342c0f4ee723df9c2818d02734e28897ad0295bb458d4bc",
   * //     "name": "Wanchain SAI Crosschain Token",
   * //     "symbol": "SAI",
   * //     "decimals": "18",
   * //     "iconData": "/9j/4AAQ...",
   * //     "iconType": "jpg"
   * //   }
   * // ]
   */
  public async getRegTokens(crossChain: string, option: any): Promise<any> {
    return await this._request('getRegTokens', { crossChain, ...(option || {}) });
  }

  /**
   * Token exchange ratio,such as 1 token to 880 WANs, the precision is 10000, the ratio is 880*precision = 880,0000. The ratio would be changed accoring to the market value ratio periodically.
   * @since 1.3.0
   * @param {string} crossChain - The cross-chain name that you want to search, should be <code>"ETH"</code>.
   * @param {string} tokenScAddr - The token contract address for the specified token.
   * @returns {Promise<string>} - The result of ratio.
   * @example
   * const ret = await sdk.getToken2WanRatio("ETH", "0x00f58d6d585f84b2d7267940cede30ce2fe6eae8");
   * console.log(ret);
   * // "3000"
   */
  public async getToken2WanRatio(crossChain: string, tokenScAddr: string): Promise<string> {
    return await this._request('getToken2WanRatio', { crossChain, tokenScAddr });
  }

  /**
   * Returns an array about OTA mix set.
   * @since 1.3.0
   * @param {string} address - The OTA address
   * @param {number} num - The privateTx:ringSize.
   * @param {string} chainType - Optional, the chain being queried. Currently supports <code>'WAN'</code>.
   * @returns {Array<string>} - The array about OTA mix set.
   * @example
   * const ret = await sdk.getOTAMixSet("0x02539dD49A75d6Cf4c5cc857bc87BC3836E74F1c845A08eC5E009A4dCa59D47C7c0298697d22cfa7d35A670B45C3531ea9D3aAc39E58c929d440Ac1392BDeB8926e7", 8);
   * console.log(ret);
   * // [ '0x02a0ab76c74fc379743bdc958d806c9062f3fc68b097fe8e91453d7324f7ae648702a20af02d1fe495036b38ab8c44b5676c1c0158f0057b6500150374b6f19ab2ba',
   * //   '0x020317c92daac5ad9cc5377bc4f493197772e9459fb737e1c26c7e6f030f21b7d002c5d50ef420e818f58c87a3f57cb1167adf268911021e9d0c3cf9aea7e06ac1ad',
   * //   '0x02c6fa830d978e20bff8e993356d3456aa6c6f1dab966d20953bac55b7526ab0f203719139be2bc3660a8841fcf3d34d9043693e48b6cfebeaa4447cb1d72f809139',
   * //   '0x03039ca6d4c95e75b7b6e131bf2af3d84b8d1807c34ed04fc637e57e45f5b590e503db2ce78d660ed6e230feb4ea91d8f7662315731d625d4a7d771cf82b686fb0a9',
   * //   '0x03f0ee5da723151435e287a616e4502642315c9ed933569402ad0f838db0fd597a0325b3cb82275a6aa6cc1f1edc9675fc7201f5e9e589a34ed676f4400f2a081129',
   * //   '0x038b3c1fada7710a519c4bb7929c8d08a8e9e17fcf7ea510043d00a6844a06155c02ec1e571a8f3a1471461cf74ecc4568d4009a3fc910c29c30bfdfb05f79924b12',
   * //   '0x036d369b2a0e4fbd0e270c5d78e8fc53c1b0f1d58878f1a106812380325493fec3020f00e39b4e76169433289f92ee0fea44e1e0f26b87420c6f897489f6975621b6',
   * //   '0x03bf32510e236f8bafd3127a3598f9c36f60612371f798ed766214183d1d2c3f1b027de375bc1112030300b843172f39031a735fc626f76e823e6b3e0367d89b269d'
   * // ]
   */
  public async getOTAMixSet(address: string, num: number, chainType: string ): Promise<Array<string>> {
    return await this._request('getOTAMixSet', { address, number: num, chainType });
  }

  /**
   * Executes a message call or transaction and returns the amount of the gas used.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried, should be <code>"ETH"</code>,  <code>"WAN"</code>, and other EVM chains.
   * @param {object} tx - The transaction object see eth.sendTransaction, with the difference that for calls the from property is optional as well.
   * @param {any} [option] - A reserved parameter.
   * @returns {Array<string>} - The estimated gas.
   * @example
   * const ret = await sdk.estimateGas("WAN", {from:'0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe', to:'0x11f4d0A3c12e86B4b5F39B213F7E19D048276DAe', value:'1000000000000000'});
   * console.log(ret);
   * // 21000
   */
  public async estimateGas(chainType: string, tx: object, option: any): Promise<number | string> {
    return await this._request('estimateGas', { chainType, ...tx, ...(option || {}) });
  }

  /**
   * Returns an object containing various details about the blockchain.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried. Currently supports <code>'EOS'</code>.
   * @param {any} [option] - A reserved parameter.
   * @returns {Array<any>} - The blockchain info.
   * @example
   * const ret = await sdk.estimateGas("WAN", {from:'0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe', to:'0x11f4d0A3c12e86B4b5F39B213F7E19D048276DAe', value:'1000000000000000'});
   * console.log(ret);
   * // {
   * //   server_version: 'aa60b9ca',
   * //   chain_id: 'e70aaab8997e1dfce58fbfac80cbbb8fecec7b99cf982a9444273cbc64c41473',
   * //   head_block_num: 84031197,
   * //   last_irreversible_block_num: 84030870,
   * //   last_irreversible_block_id: '05023596ebe1b775a39a0ab380a0fd95bf435fbe9eccbf2b3e38c44a0cdc6a0d',
   * //   head_block_id: '050236dd683c4f98c9f5965910bf941d67b8fe6469a149114a3f0053779461da',
   * //   head_block_time: '2020-04-02T11:35:25.000',
   * //   head_block_producer: 'five.cartel',
   * //   virtual_block_cpu_limit: 500000000,
   * //   virtual_block_net_limit: 524288000,
   * //   block_cpu_limit: 499990,
   * //   block_net_limit: 524288,
   * //   server_version_string: 'v2.0.2',
   * //   fork_db_head_block_num: 84031197,
   * //   fork_db_head_block_id: '050236dd683c4f98c9f5965910bf941d67b8fe6469a149114a3f0053779461da',
   * //   server_full_version_string: 'v2.0.2-aa60b9caf9b7e2bd2411bb199c0c1d9fd8f085d5'
   * // }
   */
  public async getChainInfo(chainType: string, option: any): Promise<any> {
    return await this._request('getChainInfo', { chainType, ...(option || {}) });
  }

  /**
   * Returns an object with one member labeled as the symbol you requested, the object has three members: supply (Symbol), max_supply (Symbol) and issuer (Name).
   * @since 1.3.0
   * @group EOS
   * @param {string} chainType - The chain being queried. Currently supports <code>'EOS'</code>.
   * @param {string} tokenScAddr - EOS contract code.
   * @param {string} symbol - A string representation of an EOSIO symbol.
   * @param {any} [option] - A reserved parameter.
   * @returns {Array<any>} - The stats info.
   * @example
   * const ret = await sdk.getStats("EOS", "eosio.token", "EOS");
   * console.log(ret);
   * // {
   * //   "supply": "10756688680.6257 EOS",
   * //   "max_supply": "100000000000.0000 EOS",
   * //   "issuer": "eosio"
   * // }
   */
  public async getStats(chainType: string, tokenScAddr: string, symbol: string, option: any): Promise<any> {
    return await this._request('getCurrencyStats', { chainType, tokenScAddr, symbol, ...(option || {}) });
  }

  /**
   * Returns an object containing various details about a specific account on the blockchain.
   * @since 1.3.0
   * @param {string} chainType - The chain being queried. Currently supports <code>'EOS'</code> and <code>'XRP'</code>.
   * @param {string} address - The account code.
   * @param {any} [option] - Optional.
   * <br>&nbsp;&nbsp;<code>version</code> - The result format version you want to search, using <code>undefined</code> that means legacy format as default.
   * @returns {Array<any>} - The account info.
   * @example
   * const ret = await sdk.getAccountInfo("EOS", "aarontestnet");
   * console.log(ret);
   * // {
   * //   "account_name": "aarontestnet",
   * //   "head_block_num": 84039011,
   * //   "head_block_time": "2020-04-02T12: 40: 32.000",
   * //   "privileged": false,
   * //   "last_code_update": "1970-01-01T00: 00: 00.000",
   * //   "created": "2019-04-22T03: 47: 11.500",
   * //   "core_liquid_balance": "148.3494 EOS",
   * //   "ram_quota": 7517,
   * //   "net_weight": 340000,
   * //   "cpu_weight": 2230000,
   * //   "net_limit": {
   * //     "used": 520,
   * //     "available": 2188721,
   * //     "max": 2189241
   * //   },
   * //   "cpu_limit": {
   * //     "used": 935,
   * //     "available": 13184853,
   * //     "max": 13185788
   * //   },
   * //   "ram_usage": 3894,
   * //   "permissions": [
   * //     {
   * //       "perm_name": "active",
   * //       "parent": "owner",
   * //       "required_auth": [Object]
   * //     },
   * //     {
   * //       "perm_name": "owner",
   * //       "parent": "",
   * //       "required_auth": [Object]
   * //     }
   * //   ],
   * //   "total_resources": {
   * //     "owner": "aarontestnet",
   * //     "net_weight": "34.0000 EOS",
   * //     "cpu_weight": "223.0000 EOS",
   * //     "ram_bytes": 6117
   * //   },
   * //   "self_delegated_bandwidth": {
   * //     "from": "aarontestnet",
   * //     "to": "aarontestnet",
   * //     "net_weight": "24.0000 EOS",
   * //     "cpu_weight": "73.0000 EOS"
   * //   },
   * //   "refund_request": null,
   * //   "voter_info": {
   * //     "owner": "aarontestnet",
   * //     "proxy": "",
   * //     "producers": [],
   * //     "staked": 2010000,
   * //     "last_vote_weight": "0.00000000000000000",
   * //     "proxied_vote_weight": "0.00000000000000000",
   * //     "is_proxy": 0,
   * //     "flags1": 0,
   * //     "reserved2": 0,
   * //     "reserved3": "0"
   * //   },
   * //   "rex_info": null
   * // }
   */
  public async getAccountInfo(chainType: string, address: string, option: any): Promise<any> {
    return await this._request('getAccountInfo', { chainType, address, ...(option || {}) });
  }

  /**
   * Returns an array containing account names which is related to the public key, or owned by the given account.
   * @since 1.3.0
   * @group EOS
   * @param {string} chainType - The chain being queried. Currently supports <code>'EOS'</code>.
   * @param {string} addressOrPublicKey - The account name or the public key.
   * <br>&nbsp;&nbsp;<code>version</code> - The result format version you want to search, using <code>undefined</code> that means legacy format as default.
   * @returns {Array<any>} - The accounts.
   * @example
   * const ret = await sdk.getAccounts("EOS", "EOS6yEsFdisRXLpk4xg4AEnYJDW5bLrjwBDoHNREsDsxcwFEncErK");
   * // const ret = await sdk.getAccounts("EOS", "aarontestnet");
   * console.log(ret);
   * // [ "wanchainbbbb", "wanchainaaaa" ]
   */
  public async getAccounts(chainType: string, addressOrPublicKey: string): Promise<any> {
    const option = (addressOrPublicKey.startsWith("EOS")) ? { publicKey: addressOrPublicKey } : { address: addressOrPublicKey };
    return await this._request('getAccounts', { chainType, ...option});
  }

  /**
   * Returns the required keys needed to sign a transaction.
   * @since 1.3.0
   * @group EOS
   * @param {string} chainType - The chain being queried. Currently supports <code>'EOS'</code>.
   * @param {object} txArgs - Optional, transaction arguments.
   * <br>&nbsp;&nbsp;<code>expiration</code> - required string (DateTime) ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$ Time that transaction must be confirmed by.
   * <br>&nbsp;&nbsp;<code>ref_block_num</code> - required integer.
   * <br>&nbsp;&nbsp;<code>ref_block_prefix</code> - required integer.
   * <br>&nbsp;&nbsp;<code>max_net_usage_words</code> - required string or integer (WholeNumber) A whole number.
   * <br>&nbsp;&nbsp;<code>max_cpu_usage_ms</code> - required string or integer (WholeNumber) A whole number.
   * <br>&nbsp;&nbsp;<code>delay_sec</code> - required integer.
   * <br>&nbsp;&nbsp;<code>context_free_actions</code> - required Array of objects (Action).
   * <br>&nbsp;&nbsp;<code>actions</code> - required Array of objects (Action).
   * <br>&nbsp;&nbsp;<code>transaction_extensions</code> - Array of Array of integers or strings (Extension).
   * <br>&nbsp;&nbsp;<code>available_keys</code> - Array of strings (PublicKey) Provide the available keys.
   * @returns {Array<any>} - The required keys.
   * @example
   * const ret = await sdk.getRequiredKeys("EOS", {"transaction":{"expiration":"2020-04-03T06:06:41","ref_block_num":15105,"ref_block_prefix":2116318876,"max_net_usage_words":"","max_cpu_usage_ms":"","delay_sec":0,"context_free_actions":[],"actions":[{"account":"eosio.token","name":"transfer","authorization":[{"actor":"cuiqiangtest","permission":"active"}],"data":"90D5CC58E549AF3180626ED39986A6E1010000000000000004454F530000000000"}],"transaction_extensions":[]},"available_keys":["EOS7MiJnddv2dHhjS82i9SQWMpjLoBbxP1mmpDmwn6ALGz4mpkddv"]});
   * console.log(ret);
   * // ['PUB_K1_69X3383RzBZj41k73CSjUNXM5MYGpnDxyPnWUKPEtYQmVzqTY7']
   */
  public async getRequiredKeys(chainType: string, txArgs: object, option: any): Promise<any> {
    return await this._request('getRequiredKeys', { chainType, txArgs, ...(option || {}) });
  }

  /**
   * Retrieves raw code and ABI for a contract based on account name.
   * @since 1.3.0
   * @group EOS
   * @param {string} chainType - The chain being queried. Currently supports <code>'EOS'</code>.
   * @param {string} scAddr - The contract account name.
   * @returns {Array<any>} - The raw code and ABI.
   * @example
   * const ret = await sdk.getRawCodeAndAbi("EOS", "wanchainhtlc");
   * console.log(ret);
   * // { "account_name": "wanchainhtlc", "wasm": "...", "abi": "..." }
   */
  public async getRawCodeAndAbi(chainType: string, scAddr: string): Promise<any> {
    return await this._request('getRawCodeAndAbi', { chainType, scAddr });
  }

  /**
   * Retrieves the ABI for a contract based on its account name.
   * @since 1.3.0
   * @group EOS
   * @param {string} chainType - The chain being queried. Currently supports <code>'EOS'</code>.
   * @param {string} scAddr - The contract account name.
   * @returns {Array<any>} - The ABI.
   * @example
   * const ret = await sdk.getAbi("EOS", "wanchainhtlc");
   * console.log(ret);
   * // {
   * //   "version": "eosio::abi/1.1",
   * //   "types": [
   * //     {
   * //       "new_type_name": "time_t",
   * //       "type": "uint32"
   * //     }
   * //   ],
   * //   "structs": [
   * //     {
   * //       "name": "asset_t",
   * //       "base": "",
   * //       "fields": ["Array"]
   * //     },
   * //     {
   * //       "name": "debt_t",
   * //       "base": "",
   * //       "fields": ["Array"]
   * //     },
   * //     {
   * //       "name": "fee_t",
   * //       "base": "",
   * //       "fields": ["Array"]
   * //     },
   * //     {
   * //       "name": "inlock",
   * //       "base": "",
   * //       "fields": ["Array"]
   * //     },
   * //     {
   * //       "name": "inredeem",
   * //       "base": "",
   * //       "fields": ["Array"]
   * //     },
   * //     {
   * //       "name": "inrevoke",
   * //       "base": "",
   * //       "fields": ["Array"]
   * //     },
   * //     {
   * //       "name": "lockdebt",
   * //       "base": "",
   * //       "fields": ["Array"]
   * //     },
   * //     {
   * //       "name": "num64_t",
   * //       "base": "",
   * //       "fields": ["Array"]
   * //     },
   * //     {
   * //       "name": "outlock",
   * //       "base": "",
   * //       "fields": ["Array"]
   * //     },
   * //     {
   * //       "name": "outredeem",
   * //       "base": "",
   * //       "fields": ["Array"]
   * //     },
   * //     {
   * //       "name": "outrevoke",
   * //       "base": "",
   * //       "fields": ["Array"]
   * //     },
   * //     {
   * //       "name": "pk_t",
   * //       "base": "",
   * //       "fields": ["Array"]
   * //     },
   * //     {
   * //       "name": "redeemdebt",
   * //       "base": "",
   * //       "fields": ["Array"]
   * //     },
   * //     {
   * //       "name": "regsig",
   * //       "base": "",
   * //       "fields": ["Array"]
   * //     },
   * //     {
   * //       "name": "revokedebt",
   * //       "base": "",
   * //       "fields": ["Array"]
   * //     },
   * //     {
   * //       "name": "setratio",
   * //       "base": "",
   * //       "fields": ["Array"]
   * //     },
   * //     {
   * //       "name": "signature_t",
   * //       "base": "",
   * //       "fields": ["Array"]
   * //     },
   * //     {
   * //       "name": "transfer_t",
   * //       "base": "",
   * //       "fields": ["Array"]
   * //     },
   * //     {
   * //       "name": "unregsig",
   * //       "base": "",
   * //       "fields": ["Array"]
   * //     },
   * //     {
   * //       "name": "updatesig",
   * //       "base": "",
   * //       "fields": ["Array"]
   * //     },
   * //     {
   * //       "name": "withdraw",
   * //       "base": "",
   * //       "fields": ["Array"]
   * //     }
   * //   ],
   * //   "actions": [
   * //     {
   * //       "name": "inlock",
   * //       "type": "inlock",
   * //       "ricardian_contract": ""
   * //     },
   * //     {
   * //       "name": "inredeem",
   * //       "type": "inredeem",
   * //       "ricardian_contract": ""
   * //     },
   * //     {
   * //       "name": "inrevoke",
   * //       "type": "inrevoke",
   * //       "ricardian_contract": ""
   * //     },
   * //     {
   * //       "name": "lockdebt",
   * //       "type": "lockdebt",
   * //       "ricardian_contract": ""
   * //     },
   * //     {
   * //       "name": "outlock",
   * //       "type": "outlock",
   * //       "ricardian_contract": ""
   * //     },
   * //     {
   * //       "name": "outredeem",
   * //       "type": "outredeem",
   * //       "ricardian_contract": ""
   * //     },
   * //     {
   * //       "name": "outrevoke",
   * //       "type": "outrevoke",
   * //       "ricardian_contract": ""
   * //     },
   * //     {
   * //       "name": "redeemdebt",
   * //       "type": "redeemdebt",
   * //       "ricardian_contract": ""
   * //     },
   * //     {
   * //       "name": "regsig",
   * //       "type": "regsig",
   * //       "ricardian_contract": ""
   * //     },
   * //     {
   * //       "name": "revokedebt",
   * //       "type": "revokedebt",
   * //       "ricardian_contract": ""
   * //     },
   * //     {
   * //       "name": "setratio",
   * //       "type": "setratio",
   * //       "ricardian_contract": ""
   * //     },
   * //     {
   * //       "name": "unregsig",
   * //       "type": "unregsig",
   * //       "ricardian_contract": ""
   * //     },
   * //     {
   * //       "name": "updatesig",
   * //       "type": "updatesig",
   * //       "ricardian_contract": ""
   * //     },
   * //     {
   * //       "name": "withdraw",
   * //       "type": "withdraw",
   * //       "ricardian_contract": ""
   * //     }
   * //   ],
   * //   "tables": [
   * //     {
   * //       "name": "assets",
   * //       "index_type": "i64",
   * //       "key_names": [],
   * //       "key_types": [],
   * //       "type": "asset_t"
   * //     },
   * //     {
   * //       "name": "debts",
   * //       "index_type": "i64",
   * //       "key_names": [],
   * //       "key_types": [],
   * //       "type": "debt_t"
   * //     },
   * //     {
   * //       "name": "fees",
   * //       "index_type": "i64",
   * //       "key_names": [],
   * //       "key_types": [],
   * //       "type": "fee_t"
   * //     },
   * //     {
   * //       "name": "longlongs",
   * //       "index_type": "i64",
   * //       "key_names": [],
   * //       "key_types": [],
   * //       "type": "num64_t"
   * //     },
   * //     {
   * //       "name": "pks",
   * //       "index_type": "i64",
   * //       "key_names": [],
   * //       "key_types": [],
   * //       "type": "pk_t"
   * //     },
   * //     {
   * //       "name": "signer",
   * //       "index_type": "i64",
   * //       "key_names": [],
   * //       "key_types": [],
   * //       "type": "signature_t"
   * //     },
   * //     {
   * //       "name": "transfers",
   * //       "index_type": "i64",
   * //       "key_names": [],
   * //       "key_types": [],
   * //       "type": "transfer_t"
   * //     }
   * //   ],
   * //   "ricardian_clauses": [],
   * //   "error_messages": [],
   * //   "abi_extensions": [],
   * //   "variants": []
   * // }
   */
  public async getAbi(chainType: string, scAddr: string): Promise<any> {
    return await this._request('getAbi', { chainType, scAddr });
  }

  /**
   * Returns an object containing buffer ABI for a contract based on its account name.
   * @since 1.3.0
   * @group EOS
   * @param {string} chainType - The chain being queried. Currently supports <code>'EOS'</code>.
   * @param {string} scAddr - The contract account name.
   * @returns {ArraPromise<any>} - The accounts.
   * @example
   * const ret = await sdk.getRawAbi("EOS", "wanchainhtlc");
   * console.log(ret);
   * // {
   * //   "0": 14,
   * //   "1": 101,
   * //   "2": 111,
   * //   "3": 115,
   * //   "…": "...",
   * //   "1557": 0
   * // }
   */
  public async getRawAbi(chainType: string, scAddr: string, option: any): Promise<any> {
    return await this._request('getRawAbi', { chainType, scAddr, ...(option || {}) });
  }

  /**
   * Returns an array of actions based on notified account..
   * @since 1.3.0
   * @group EOS
   * @param {string} chainType - The chain being queried. Currently supports <code>'EOS'</code>.
   * @param {string} address - The account name you want to query.
   * @param {any} option - Optional, the filter for actions.
   * <br>&nbsp;&nbsp;<strong>For eosjs 16.0.0</strong>:
   * <br>&nbsp;&nbsp;&nbsp;&nbsp;<code>pos</code> - An int32 that is absolute sequence positon, -1 is the end/last action.
   * <br>&nbsp;&nbsp;&nbsp;&nbsp;<code>offset</code> - The number of actions relative to pos, negative numbers return [pos-offset,pos), positive numbers return [pos,pos+offset).
   * 
   * <br>&nbsp;&nbsp;<strong>For eosjs 20</strong>:
   * <br>&nbsp;&nbsp;&nbsp;&nbsp;<code>filter</code> - The string for code::name filter.
   * <br>&nbsp;&nbsp;&nbsp;&nbsp;<code>skip</code> - The number to skip [n] actions (pagination).
   * <br>&nbsp;&nbsp;&nbsp;&nbsp;<code>limit</code> - The number to limit of [n] actions per page.
   * <br>&nbsp;&nbsp;&nbsp;&nbsp;<code>sort</code> - The string to sort direction.
   * <br>&nbsp;&nbsp;&nbsp;&nbsp;<code>after</code> - The string to filter after specified date (ISO8601).
   * <br>&nbsp;&nbsp;&nbsp;&nbsp;<code>before</code> - The string to filter before specified date (ISO8601).
   * <br>&nbsp;&nbsp;&nbsp;&nbsp;<code>transfer_to</code> - The string to transfer filter to.
   * <br>&nbsp;&nbsp;&nbsp;&nbsp;<code>transfer_from</code> - The string to transfer filter from. 
   * <br>&nbsp;&nbsp;&nbsp;&nbsp;<code>transfer_symbol</code> - The string to transfer filter symbol.
   * <br>&nbsp;&nbsp;&nbsp;&nbsp;<code>act_name</code> - The string for act name. 
   * <br>&nbsp;&nbsp;&nbsp;&nbsp;<code>act_account</code> - The string for act account. 
   * @returns {Promise<any>} - The actions.
   * @example
   * const ret = await sdk.getActions("EOS", "wanchainhtlc", {filter: "wanchainhtlc:outlock", limit: 2});
   * console.log(ret);
   * // [
   * //   {
   * //     "act": { "authorization": [Array],
   * //     "data": [Object],
   * //     "account": "wanchainhtlc",
   * //     "name": "outlock"
   * //   },
   * //   "cpu_usage_us": 504,
   * //   "net_usage_words": 65,
   * //   "account_ram_deltas": [ [Object] ],
   * //   "global_sequence": 564872608,
   * //   "@timestamp": "2020-02-20T03:19:58.500",
   * //   "block_num": 76739261,
   * //   "producer": "eight.cartel",
   * //   "trx_id": "20bd931ce948c57614f9c6b617532f806a59314ebfe0cacea13be461e0806034",
   * //   "action_ordinal": 1,
   * //   "creator_action_ordinal": 0,
   * //   "notified": [ "wanchainhtlc" ]
   * //   }
   * // ]
   */
  public async getActions(chainType: string, address: string, option: any): Promise<any> {
    return await this._request('getActions', { chainType, address, ...(option || {}) });
  }

  /**
   * Returns an object containing rows from the specified table eosio.table.global.
   * @since 1.3.0
   * @group EOS
   * @param {string} chainType - The chain being queried. Currently supports <code>'EOS'</code>.
   * @returns {Promise<any>} - The resource info.
   * @example
   * const ret = await sdk.getResource("EOS");
   * console.log(ret);
   * // {
   * //   "max_block_net_usage": 524288,
   * //   "target_block_net_usage_pct": 1000,
   * //   "max_transaction_net_usage": 524287,
   * //   "base_per_transaction_net_usage": 12,
   * //   "net_usage_leeway": 500,
   * //   "context_free_discount_net_usage_num": 20,
   * //   "context_free_discount_net_usage_den": 100,
   * //   "max_block_cpu_usage": 500000,
   * //   "target_block_cpu_usage_pct": 10,
   * //   "max_transaction_cpu_usage": 200000,
   * //   "min_transaction_cpu_usage": 10,
   * //   "max_transaction_lifetime": 3600,
   * //   "deferred_trx_expiration_window": 600,
   * //   "max_transaction_delay": 3888000,
   * //   "max_inline_action_size": 524287,
   * //   "max_inline_action_depth": 16,
   * //   "max_authority_depth": 6,
   * //   "max_ram_size": "68719476736",
   * //   "total_ram_bytes_reserved": "31287726990",
   * //   "total_ram_stake": "8358873421",
   * //   "last_producer_schedule_update": "2020-04-05T13:19:05.500",
   * //   "last_pervote_bucket_fill": "2020-04-05T13:12:01.000",
   * //   "pervote_bucket": 2472797114,
   * //   "perblock_bucket": "2207987466943",
   * //   "total_unpaid_blocks": 13819603,
   * //   "total_activated_stake": "2480152949826",
   * //   "thresh_activated_stake_time": "2018-11-23T17:21:01.000",
   * //   "last_producer_schedule_size": 21,
   * //   "total_producer_vote_weight": "460825067195145191424.00000000000000000",
   * //   "last_name_close": "2020-04-04T13:37:20.500"
   * // }
   */
  public async getResource(chainType: string): Promise<any> {
    return await this._request('getResource', { chainType });
  }

  /**
   * Returns an object containing net/cpu/ram price(cpu in ms/EOS, net/ram in KB/EOS) by provide one producer's account.
   * @since 1.3.0
   * @group EOS
   * @param {string} chainType - The chain being queried. Currently supports <code>'EOS'</code>.
   * @param {string} address - The producer's account.
   * @returns {Promise<any>} - The resource price.
   * @example
   * const ret = await sdk.getResourcePrice("EOS", "junglesweden");
   * console.log(ret);
   * // { "net": "0.005301073461471487", "cpu": "0.005637367015436455", "ram": "0.050223917691993435" }
   */
  public async getResourcePrice(chainType: string, address: string): Promise<any> {
    return await this._request('getResourcePrice', { chainType, address });
  }

  /**
   * Returns an object containing net/cpu price(cpu in ms/EOS, net in KB/EOS) by provide one producer's account.
   * @since 1.3.0
   * @group EOS
   * @param {string} chainType - The chain being queried. Currently supports <code>'EOS'</code>.
   * @param {string} address - The producer's account.
   * @returns {Promise<any>} - The bandwidth price.
   * @example
   * const ret = await sdk.getBandwidthPrice("EOS", "junglesweden");
   * console.log(ret);
   * // { "net": "0.005301073461471487", "cpu": "0.005637367015436455" }
   */
  public async getBandwidthPrice(chainType: string, address: string): Promise<any> {
    return await this._request('getBandwidthPrice', { chainType, address });
  }

  /**
   * Returns ram price(in KB/EOS).
   * @since 1.3.0
   * @group EOS
   * @param {string} chainType - The chain being queried. Currently supports <code>'EOS'</code>.
   * @returns {Promise<any>} - The ram price.
   * @example
   * const ret = await sdk.getRamPrice("EOS");
   * console.log(ret);
   * // "0.05022503944229491"
   */
  public async getRamPrice(chainType: string): Promise<any> {
    return await this._request('getRamPrice', { chainType });
  }

  /**
   * Returns an object with one member labeled as 'EOS' you requested, the object has three members: supply (Symbol), max_supply (Symbol) and issuer (Name).
   * @since 1.3.0
   * @group EOS
   * @param {string} chainType - The chain being queried. Currently supports <code>'EOS'</code>.
   * @returns {Promise<any>} - The ram price.
   * @example
   * const ret = await sdk.getTotalSupply("EOS");
   * console.log(ret);
   * // { "supply": "10757681325.5591 EOS", "max_supply": "100000000000.0000 EOS", "issuer": "eosio" }
   */
  public async getTotalSupply(chainType: string): Promise<any> {
    return await this._request('getTotalSupply', { chainType });
  }

  /**
   * Returns current 'EOS' stake amount.
   * @since 1.3.0
   * @group EOS
   * @param {string} chainType - The chain being queried. Currently supports <code>'EOS'</code>.
   * @returns {Promise<any>} - The current 'EOS' stake amount.
   * @example
   * const ret = await sdk.getTotalStaked("EOS");
   * console.log(ret);
   * // "2868049208.8674 EOS"
   */
  public async getTotalStaked(chainType: string): Promise<any> {
    return await this._request('getTotalStaked', { chainType });
  }

  /**
   * Returns an object with current 'EOS' stake info, the object has three members: totalStaked, totalSup and staked percent.
   * @since 1.3.0
   * @group EOS
   * @param {string} chainType - The chain being queried. Currently supports <code>'EOS'</code>.
   * @returns {Promise<any>} - The stake info.
   * @example
   * const ret = await sdk.getTotalStakedPercent("EOS");
   * console.log(ret);
   * // { "totalStaked": 2868049208.8674, "totalSup": 10757681325.5591, "percent": 0.266604774957706 }
   */
  public async getTotalStakedPercent(chainType: string): Promise<any> {
    return await this._request('getTotalStakedPercent', { chainType });
  }

  /**
   * Returns an object containing rows from the specified table.
   * @since 1.3.0
   * @group EOS
   * @param {string} chainType - The chain being queried. Currently supports <code>'EOS'</code>.
   * @param {string} scAddr - The name of the smart contract that controls the provided table.
   * @param {string} scope - The account to which this data belongs.
   * @param {string} table - The name of the table to query.
   * @returns {Promise<any>} - The object containing rows from the specified table.
   * @example
   * const ret = await sdk.getTableRows("EOS", "wanchainhtlc", "wanchainhtlc", "transfers");
   * console.log(ret);
   * // {
   * //   "rows": [
   * //     {
   * //       "id": 0,
   * //       "pid": 0,
   * //       "quantity": "5.0000 EOS",
   * //       "user": "cuiqiangtest",
   * //       "lockedTime": 7200,
   * //       "beginTime": "2019-12-26T13:59:24",
   * //       "status": "inlock",
   * //       "xHash": "e4b7be8900393ef6b09a172a21be3b4f1b814ff580dbaeba130484fa99b2da7c",
   * //       "wanAddr": "25f2845ad9da78ebaa0e077404d35933f75422b8",
   * //       "account": "eosio.token"
   * //     },
   * //     {
   * //       "id": 1,
   * //       "pid": 0,
   * //       "quantity": "5.0000 EOS",
   * //       "user": "cuiqiangtest",
   * //       "lockedTime": 7200,
   * //       "beginTime": "2019-12-30T12:23:25",
   * //       "status": "inlock",
   * //       "xHash": "2be3dee75ddc370d301e55fb74644bab9b1bac9883cb92c4c57a35f4543ce8f6",
   * //       "wanAddr": "25f2845ad9da78ebaa0e077404d35933f75422b8",
   * //       "account": "eosio.token"
   * //     }
   * //   ],
   * //   "more": true,
   * //   "next_key": "3"
   * // }
   */
  public async getTableRows(chainType: string, scAddr: string, scope: string, table: string): Promise<any> {
    return await this._request('getTableRows', { chainType, scAddr, scope, table });
  }

  /**
   * Get the current Epoch ID.
   * @since 1.3.0
   * @group POS
   * @param {string} chainType - The chain being queried. Currently supports <code>'WAN'</code>, default: <code>'WAN'</code>.
   * @param {any} option - A reserved parameter.
   * @returns {Promise<number>} - The current epoch ID.
   * @example
   * const ret = await sdk.getEpochID("WAN");
   * console.log(ret);
   * // 18102
   */
  public async getEpochID(chainType: string, option: any): Promise<number> {
    return await this._request('getEpochID', { chainType, ...(option || {}) });
  }

  /**
   * Get the current epoch slot ID.
   * @since 1.3.0
   * @group POS
   * @param {string} chainType - The chain being queried. Currently supports <code>'WAN'</code>, default: <code>'WAN'</code>.
   * @param {any} option - A reserved parameter.
   * @returns {Promise<number>} - The current epoch slot ID.
   * @example
   * const ret = await sdk.getSlotID("WAN");
   * console.log(ret);
   * // 2541
   */
  public async getSlotID(chainType: string, option: any): Promise<number> {
    return await this._request('getSlotID', { chainType, ...(option || {}) });
  }

  /**
   * Get the public key list of the epoch leaders of the specified EpochID with the input parameter as EpochID.
   * @since 1.3.0
   * @group POS
   * @param {string} chainType - The chain being queried. Currently supports <code>'WAN'</code>, default: <code>'WAN'</code>.
   * @param {number} epochID - The epochID you want to search.
   * @param {any} option - A reserved parameter.
   * @returns {Promise<any>} - The public key list.
   * @example
   * const ret = await sdk.getEpochLeadersByEpochID("WAN", 18102);
   * console.log(ret);
   * // {
   * //   "000000": "046c0979fbcd38b7887076db6b08adbbaae45189ac4239d2c06749b634dbeaafdf2b229b6c4eda1ab6ede7e46cbd9ab3ac35df1ac2a6f650bac39fd8474d85524e",
   * //   "000001": "04dac7b023f0e9fb5be91b48e5d546b2f2eb91029705f6055c24b3c804a49cf83f7cd584a96346ca42a94a02456444b7df4e280d2726971bf267f8182341ff81b9",
   * //   "000002": "042b7d4be32d25769472ea7c8d432bbad5abee051c048e4de425e6feb288fde6f33a16269e4e85fbda4f857a7d5eca8d33793b9249c83517a3214b64475cd50176",
   * //   ... ...
   * //   "000047": "046351650f15b8de869d89c572dc093000794e75e7f4a7c9f10e9b35f24694fa7555c143e4c4dd4548c0d06be2b2e6c536b37acf0c0ad4806e6c48f23ade4e4d9a",
   * //   "000048": "04fdb485b566c2ddb40e2f4341b1e5746479a7c45e3d8101b1360b8bdba6206deee520ceecc9e9897e3b05b53e3ffa6fa659bef47c384984c0bc021a843df10847",
   * //   "000049": "04fdb485b566c2ddb40e2f4341b1e5746479a7c45e3d8101b1360b8bdba6206deee520ceecc9e9897e3b05b53e3ffa6fa659bef47c384984c0bc021a843df10847"
   * // }
   */
  public async getEpochLeadersByEpochID(chainType: string, epochID: number, option: any): Promise<any> {
    return await this._request('getEpochLeadersByEpochID', { chainType, epochID, ...(option || {}) });
  }

  /**
   * Gets Random Number Proposer public keys of the specified epoch.
   * @since 1.3.0
   * @group POS
   * @param {string} chainType - The chain being queried. Currently supports <code>'WAN'</code>, default: <code>'WAN'</code>.
   * @param {number} epochID - The epochID you want to search.
   * @param {any} option - A reserved parameter.
   * @returns {Promise<any>} - The Random Number Proposer public keys.
   * @example
   * const ret = await sdk.getRandomProposersByEpochID("WAN", 18102);
   * console.log(ret);
   * // {
   *   "000000": "29e0660fe921282b2d64c6adaf0b24945eee6d9fcdb419c39f84a551ed44151d27f786e5df7abcff94bbed2cbc2791bc76db21b5be469874be181e4fa234fb3e",
   *   "000001": "26a70d685549ffe982df0d66a88f36ac3fca6e488bf69eb6de62a37b97f3f56e2b6b56f47e817c01225ad5549f1ca9751dc1f65559f1a81639c6a4126c9df3ce",
   *   "000002": "21f4f0c4da56206685e94354acba851aab7dc7c090898f6bbb1fc42df986764b055f09e97ceb4c90976a1219ab749dd0b008d47f9c18b962a6056e66de8d858f",
   *   ... ...
   *   "000022": "1c96a7abf1424d0c5316fc74eb39022648062fc88997896bdeae70c4e008b3700136608e2ab653c037d144979403061d3247d6298bfdf0b26c9829db3175531e",
   *   "000023": "00e0c4fae08f124f7a8fe82988a385d9723bea14c8a6e2996a684846ae8d0d4e27abedb7d2f7150bd42ba830e960774b873de74b1d91d7c5ea1ba349a849e575",
   *   "000024": "2094589617397846c5125cf5922ba993643c401998ae8817d5005fe21245f4bc0fbb25158c54446757d2b03d89da10d7dfbbaa23afa38c6e87115dcebe2a8e4d"
   * }
   */
  public async getRandomProposersByEpochID(chainType: string, epochID: number, option: any): Promise<any> {
    return await this._request('getRandomProposersByEpochID', { chainType, epochID, ...(option || {}) });
  }

  /**
   * Returns an array of validator information for all validators in the specified block number.
   * @since 1.3.0
   * @group POS
   * @param {string} chainType - The chain being queried. Currently supports <code>'WAN'</code>, default: <code>'WAN'</code>.
   * @param {number} blockNumber - The blockNumber you want to search.
   * @param {any} option - A reserved parameter.
   * @returns {Promise<any>} - The specified block staker info.
   * @example
   * const ret = await sdk.getEpochID("WAN");
   * console.log(ret);
   * // [
   * //   {
   * //     "address": "0xa4626e2bb450204c4b34bcc7525e585e8f678c0d",
   * //     "pubSec256": "0x04b7bf8d3868333f70a30041423c7db204b80b9be2e585c344cf3f391cbf77b17fd14f3058d4475d546355bf8c2709ed9ecf5f0cee9d021c90988af0e8cf52001b",
   * //     "pubBn256": "0x289787688eb80c1e223375a71f8d17110d638a9143afa190dc11b3c1e64cf92b21feb02ab7a1dcb31892210dfda458aff890fe9e7508292099ae6256f197b325",
   * //     "amount": "0xa968163f0a57b400000",
   * //     "votingPower": "0x297116712be7b468800000",
   * //     "lockEpochs": 7,
   * //     "maxFeeRate": 1500,
   * //     "nextLockEpochs": 7,
   * //     "from": "0xdbb2d6199457d11288f0097659bcec24738e158f",
   * //     "stakingEpoch": 0,
   * //     "feeRate": 1500,
   * //     "feeRateChangedEpoch": 0,
   * //     "clients": [
   * //       {
   * //         "address": "0xfcc3736dc29bf9af7556fcc1dea10b53edaab51d",
   * //         "amount": "0x56bc75e2d63100000",
   * //         "votingPower": "0x1537da569da5bca00000",
   * //         "quitEpoch": 18071
   * //       }
   * //     ],
   * //     "partners": []
   * //   },
   * //    ... ...
   * // ]
   */
  public async getStakerInfo(chainType: string, blockNumber: number, option: any): Promise<any> {
    return await this._request('getStakerInfo', { chainType, blockNumber, ...(option || {}) });
  }

  /**
   * Get the reward information of the specified epoch, enter epochID, and reward payment details (including RNP reward, EL reward and chunk reward) will be returned for all the verification nodes and clients working in the epoch.
   * @since 1.3.0
   * @group POS
   * @param {string} chainType - The chain being queried. Currently supports <code>'WAN'</code>, default: <code>'WAN'</code>.
   * @param {number} epochID - The epochID you want to search.
   * @param {any} option - A reserved parameter.
   * @returns {Promise<any>} - The reward information.
   * @example
   * const ret = await sdk.getEpochIncentivePayDetail("WAN", 18101);
   * console.log(ret);
   * // [
   * //   {
   * //     "delegators": [
   * //       {
   * //         "address": "0x81ad5c65a815f8dc28e0fd1d17ac4fa38f8a6838",
   * //         "incentive": "0x78b093af02e111",
   * //         "type": "delegator"
   * //       },
   * //       {
   * //         "address": "0x4e6b5f1abdd517739889334df047113bd736c546",
   * //         "incentive": "0x13afa1b719d597636",
   * //         "type": "delegator"
   * //       },
   * //        ... ...
   * //        {
   * //         "address": "0x8bf12b4cd3b41d40b2adfdf2857b2077d4194a44",
   * //         "incentive": "0x1922a4583a858b0",
   * //         "type": "delegator"
   * //       },
   * //       {
   * //         "address": "0x51253d40bb113827781de47e5a2d41f41924431d",
   * //         "incentive": "0x28376d59f73c11",
   * //         "type": "delegator"
   * //       }
   * //     ],
   * //     "address": "0xa4626e2bb450204c4b34bcc7525e585e8f678c0d",
   * //     "stakeInFromAddr": "0xdbb2d6199457d11288f0097659bcec24738e158f",
   * //     "incentive": "0xaf6f730467435b9f",
   * //     "type": "validator"
   * //   },
   * //      ... ...
   * // ]
   */
  public async getEpochIncentivePayDetail(chainType: string, epochID: number, option: any): Promise<any> {
    return await this._request('getEpochIncentivePayDetail', { chainType, epochID, ...(option || {}) });
  }

  /**
   * Get the activity information of the specified epoch. For historical epochs the values are fixed, while the current epoch will update the latest current values in real time.
   * @since 1.3.0
   * @group POS
   * @param {string} chainType - The chain being queried. Currently supports <code>'WAN'</code>, default: <code>'WAN'</code>.
   * @param {number} epochID - The epochID you want to search.
   * @param {any} option - A reserved parameter.
   * @returns {Promise<any>} - The activity information.
   * @example
   * const ret = await sdk.getActivity("WAN", 18102);
   * console.log(ret);
   * // {
   * //   "epLeader":
   * //   [
   * //     "0x28c12c7b51860b9d5aec3a0ceb63c6e187c00aac",
   * //     "0x1a95e85e8ffcfd28eb61ee53a542dc98c57b337a",
   * //     "0x46530055144fe9365eaae87ba623e2f91cd7eff2",
   * //     "0x0e92d125ba28852a11428fcb63b6f0e44a52962f",
   * //     "0xee1ad9c4f9d81f900221e95ee04246b6254b0c6f",
   * //     "0xb58230a7923a6a1941016aa1682e212def899ed1",
   * //     "0xb9d6c1a6e52119026cb5d2a82457f5fd6bc7e0c9",
   * //     "0xdfd7aa554653ca236c197ad746edc2954ca172df",
   * //     "0x1b7740df685f9d34773d5a2aba6ab3a2c1407f40",
   * //     "0xdfd7aa554653ca236c197ad746edc2954ca172df",
   * //     "0x266ddcfdbe3ded75e0e511e6356bca052b221c6b",
   * //     "0x1ae5a38b4a5ca0aefbb1c17fd27073ab00fd2a3f",
   * //     "0x2866bca06ff1d6afe52298f9fc759ea9b80f6902",
   * //     "0xf0e02c3640020f083a314547ae99483aa2c7cd01",
   * //     "0x2a6e8c39d4e9f9152958649fc5dbdb9c68cfcb0b",
   * //     "0x0081a626fecff225cd87d3f23c0dd47a9fe243ac",
   * //     "0x1a95e85e8ffcfd28eb61ee53a542dc98c57b337a",
   * //     "0x1a95e85e8ffcfd28eb61ee53a542dc98c57b337a",
   * //     "0x1a95e85e8ffcfd28eb61ee53a542dc98c57b337a",
   * //     "0xdfd7aa554653ca236c197ad746edc2954ca172df",
   * //     "0x2a6e8c39d4e9f9152958649fc5dbdb9c68cfcb0b",
   * //     "0xa3fb8f5e1fadfe104e4b1da91e8d96aab52faaf3",
   * //     "0x4bf9fd7308d0849a62c3a7dd71c5190e57c28756",
   * //     "0x85dae7e5c7b433a1682c54eee63adf63d835d272"
   * //   ],
   * //   "epActivity":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
   * //   "rpLeader":
   * //   [
   * //     "0x89a7588529eb7aaea0a229f2dfbb277b15649969",
   * //     "0x3dabf8331afbc553a1e458e37a6c9c819c452d55",
   * //     "0x010ee9abdf364972ac8d279ab96fd1d167a4d830",
   * //     "0x7815f56468915a08edb505fffa9d376ad21a9617",
   * //     "0x2c72d7a8c02752fcfafbaea5a63c53056cfaf547",
   * //     "0x9ce4664e9d7346869797b7d9fc8c7a0212d5ff44",
   * //     "0xbdada4f58d17ce602cb0d2db2a55c3e4f47e397f",
   * //     "0xa923ac48439add7124763b3682f4505044c81ae3",
   * //     "0xf1d6ffc8a2276b7e0784973a1a07a26e75200edd",
   * //     "0x5e165460b15f02d84a67f81b29517671989d2492",
   * //     "0x8289e2141c10832e7c9b108317eae0dec2011c67",
   * //     "0xb019a99f0653973ddb2d983a26e0970587d08447",
   * //     "0x8289e2141c10832e7c9b108317eae0dec2011c67",
   * //     "0xa4ebf5bbb131179b69bbf33319257728cdada5cf",
   * //     "0x3dabf8331afbc553a1e458e37a6c9c819c452d55",
   * //     "0x5e165460b15f02d84a67f81b29517671989d2492",
   * //     "0xa4539e1bdffceb3557ffb81f87a92e2159f6d637",
   * //     "0x7815f56468915a08edb505fffa9d376ad21a9617",
   * //     "0xa4626e2bb450204c4b34bcc7525e585e8f678c0d",
   * //     "0xf90cc528e5f4811c8c1f1a69b990b9a58039f7cf",
   * //     "0x1a95e85e8ffcfd28eb61ee53a542dc98c57b337a",
   * //     "0x46530055144fe9365eaae87ba623e2f91cd7eff2",
   * //     "0x93c8ea0326ef334bdc3011e74cd1a6d78ce0594d",
   * //     "0x57dca45124e253bfa93d7571b43555a861c7455f",
   * //     "0x2c72d7a8c02752fcfafbaea5a63c53056cfaf547"
   * //   ],
   * //   "rpActivity":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
   * //   "sltLeader":[],
   * //   "slBlocks":[],
   * //   "slActivity":0,
   * //   "slCtrlCount":0
   * //   }
   */
  public async getActivity(chainType: string, epochID: number, option: any): Promise<any> {
    return await this._request('getActivity', { chainType, epochID, ...(option || {}) });
  }

  /**
   * Get the slot leader activity information of the specified epoch.
   * @since 1.3.0
   * @group POS
   * @param {string} chainType - The chain being queried. Currently supports <code>'WAN'</code>, default: <code>'WAN'</code>.
   * @param {number} epochID - The epochID you want to search.
   * @param {any} option - A reserved parameter.
   * @returns {Promise<any>} - The slot leader activity information.
   * @example
   * const ret = await sdk.getEpochID("WAN");
   * console.log(ret);
   * // {
   * //   "sltLeader":
   * //   [
   * //     "0xdf24acd01f69d93ad440c8e9ccf5ac6a32d672d4",
   * //     "0x3628bf135f36c6e26a824ec9152885505f3fbc2a",
   * //     "0xeb55839c891286d4d5bb11737fca1136797eaf83",
   * //     "0x2c72d7a8c02752fcfafbaea5a63c53056cfaf547",
   * //     "0xee1ad9c4f9d81f900221e95ee04246b6254b0c6f",
   * //     "0xcd54e0c35b122860d8fe2eb41f2e8e3e79c085ba",
   * //     "0x46530055144fe9365eaae87ba623e2f91cd7eff2",
   * //     "0x375369561dd38fd1a8c93cade745443558fff0bb",
   * //     "0xda8fa1aee77709d37f59fb96afd4cf10ccaeb6ce",
   * //     "0x57dca45124e253bfa93d7571b43555a861c7455f",
   * //     "0x2866bca06ff1d6afe52298f9fc759ea9b80f6902",
   * //     "0xbee03f252dfd38f4f8d10d0664fb50c36526a611",
   * //     "0x0081a626fecff225cd87d3f23c0dd47a9fe243ac",
   * //     "0x1a95e85e8ffcfd28eb61ee53a542dc98c57b337a",
   * //     "0x6273ce1f6f32e129f295f138d6e4ba6f0e19333e"
   * //   ],
   * //   "slBlocks": [336, 1085, 359, 671, 693, 366, 349, 53, 74, 70, 364, 347, 339, 337, 339],
   * //   "slActivity": 0.8467013888888889,
   * //   "slCtrlCount": 8849
   * //   }
   */
  public async getSlotActivity(chainType: string, epochID: number, option: any): Promise<any> {
    return await this._request('getSlotActivity', { chainType, epochID, ...(option || {}) });
  }

  /**
   * Get the validator activity information of the Epoch Leaders and Random Number Proposers of the specified epoch. Returns null for the current Epoch or future Epochs.
   * @since 1.3.0
   * @group POS
   * @param {string} chainType - The chain being queried. Currently supports <code>'WAN'</code>, default: <code>'WAN'</code>.
   * @param {number} epochID - The epochID you want to search.
   * @param {any} option - A reserved parameter.
   * @returns {Promise<any>} - The validator activity information.
   * @example
   * const ret = await sdk.getValidatorActivity("WAN", 18102);
   * console.log(ret);
   * // {
   * //   "epLeader":
   * //   [
   * //     "0x880d861a8bb6909885bbc65f9fc255bbd11a5825",
   * //     "0xc7afae3c9e99af27fe3eaa10f6ec73cd2dbe003b",
   * //     "0x882c9c16c05496d7b5374840936aec1af2a16553",
   * //     "0x54945447375e25d03033099c540f0998dfa4152d",
   * //     "0x71d063d48ac747dd9ef455cc5a58272c04660983",
   * //     "0xd5551afd5c976a8eaac478f438f51aea4547eda9",
   * //     "0xdfd7aa554653ca236c197ad746edc2954ca172df",
   * //     "0x2c72d7a8c02752fcfafbaea5a63c53056cfaf547",
   * //     "0x73494477f3a099415348cd33e3d46a07f4052600",
   * //     "0x847437144ab96c6c499cdee9edc4d64032d06c86",
   * //     "0x0b80f69fcb2564479058e4d28592e095828d24aa",
   * //     "0x54945447375e25d03033099c540f0998dfa4152d",
   * //     "0x742d898d2ee28a338f03af79c47762a908281a6a",
   * //     "0x93c8ea0326ef334bdc3011e74cd1a6d78ce0594d",
   * //     "0x5c1f00ff943de649519ff1ff35ac5b4c62b90964",
   * //     "0x2a6e8c39d4e9f9152958649fc5dbdb9c68cfcb0b",
   * //     "0xc46b1935326ba2423a9f4bbabf97f74d47f37d59",
   * //     "0xbeb30b68160d845593f01aeb6ad9b6e3cc2e3277",
   * //     "0x3daddc5a590808694eb1b732636a70194ad3d98e",
   * //     "0x266ddcfdbe3ded75e0e511e6356bca052b221c6b",
   * //     "0xb9d6c1a6e52119026cb5d2a82457f5fd6bc7e0c9",
   * //     "0xb44a825eb3f0539f6593ea05740c9f2686973f3c",
   * //     "0xa4539e1bdffceb3557ffb81f87a92e2159f6d637",
   * //     "0xb64b60ba915bc16dc71ea59c9950c1538dcead9c"
   * //   ],
   * //   "epActivity":[0,1,0,1,0,1,1,1,1,0,1,1,1,1,1,0,1,0,1,0,1,1,0,0],
   * //   "rpLeader":
   * //   [
   * //     "0xee1ad9c4f9d81f900221e95ee04246b6254b0c6f",
   * //     "0xaadb06ebb95f165155f12a38bdcb092ac66e0344",
   * //     "0xdfd7aa554653ca236c197ad746edc2954ca172df",
   * //     "0x4bf9fd7308d0849a62c3a7dd71c5190e57c28756",
   * //     "0xb44a825eb3f0539f6593ea05740c9f2686973f3c",
   * //     "0x3628bf135f36c6e26a824ec9152885505f3fbc2a",
   * //     "0x2866bca06ff1d6afe52298f9fc759ea9b80f6902",
   * //     "0x0b80f69fcb2564479058e4d28592e095828d24aa",
   * //     "0x46530055144fe9365eaae87ba623e2f91cd7eff2",
   * //     "0x36fad9acaf51a13527375b1ffc3d5a749153efdb",
   * //     "0xf8fff523fb1450942dd2cd2b29837eaec2c4c860",
   * //     "0x71d063d48ac747dd9ef455cc5a58272c04660983",
   * //     "0x1b7740df685f9d34773d5a2aba6ab3a2c1407f40",
   * //     "0xb58230a7923a6a1941016aa1682e212def899ed1",
   * //     "0x54945447375e25d03033099c540f0998dfa4152d",
   * //     "0x742d898d2ee28a338f03af79c47762a908281a6a",
   * //     "0x85bbe8f965b1719f7089ee9912e7c9b10fe0a999",
   * //     "0xbee03f252dfd38f4f8d10d0664fb50c36526a611",
   * //     "0x2f13896d55ea42b58578cd835064233f8e80a929",
   * //     "0xf543da34477455ccd0ce9b153baaf344cefd9413",
   * //     "0xef09644a88ace467475c2f333f7bb8ffc9427452",
   * //     "0x0adc1b8d04d3856b394c8a170fbaea68589c4de6",
   * //     "0xaadb06ebb95f165155f12a38bdcb092ac66e0344",
   * //     "0x38550ef70511ff71924c4b58220b54e65720384f",
   * //     "0xda8fa1aee77709d37f59fb96afd4cf10ccaeb6ce"
   * //   ],
   * //   "rpActivity":[1,1,1,1,0,1,1,1,1,0,1,0,0,1,0,0,1,1,0,0,0,0,1,1,1]
   * // }
   */
  public async getValidatorActivity(chainType: string, epochID: number, option: any): Promise<any> {
    return await this._request('getValidatorActivity', { chainType, epochID, ...(option || {}) });
  }

  /**
   * Get the current highest stable block number (no rollback).
   * @since 1.3.0
   * @group POS
   * @param {string} chainType - The chain being queried. Currently supports <code>'WAN'</code>, default: <code>'WAN'</code>.
   * @param {any} option - A reserved parameter.
   * @returns {Promise<number>} - The current highest stable block number.
   * @example
   * const ret = await sdk.getValidatorActivity("WAN", 18102);
   * console.log(ret);
   * // 4018017
   */
  public async getMaxStableBlkNumber(chainType: string, option: any): Promise<number> {
    return await this._request('getMaxStableBlkNumber', { chainType, ...(option || {}) });
  }

  /**
   * Get the random number of the queried epochID and block number.
   * @since 1.3.0
   * @group POS
   * @param {string} chainType - The chain being queried. Currently supports <code>'WAN'</code>, default: <code>'WAN'</code>.
   * @param {number} epochID - The epochID you want to search.
   * @param {number} blockNumber - The blockNumber you want to search. If blockNumber is -1, use the latest block.
   * @param {any} option - A reserved parameter.
   * @returns {Promise<string>} - The current highest stable block number.
   * @example
   * const ret = await sdk.getRandom("WAN", 18102, -1);
   * console.log(ret);
   * // "0x3a4277627fa45c3bf691014d79c05da2427f8eb115a076b71af7690cdb3a0b5e"
   */
  public async getRandom(chainType: string, epochID: number, blockNumber: number, option: any): Promise<string> {
    return await this._request('getRandom', { chainType, epochID, blockNumber, ...(option || {}) });
  }

  /**
   * Get the specified validator info by the validator address.
   * @since 1.3.0
   * @group POS
   * @param {string} chainType - The chain being queried. Currently supports <code>'WAN'</code>, default: <code>'WAN'</code>.
   * @param {string} address - The validator address you want to search.
   * @param {any} option - A reserved parameter.
   * @returns {Promise<any>} - The specified validator info.
   * @example
   * const ret = await sdk.getValidatorInfo("WAN", "0xda8fa1aee77709d37f59fb96afd4cf10ccaeb6ce");
   * console.log(ret);
   * // { "address": "0xda8fa1aee77709d37f59fb96afd4cf10ccaeb6ce", "amount": "5.01e+22", "feeRate": 1500 }
   */
  public async getValidatorInfo(chainType: string, address: string, option: any): Promise<any> {
    return await this._request('getValidatorInfo', { chainType, address, ...(option || {}) });
  }

  /**
   * Get the specified validator staking info by the validator owner's address.
   * @since 1.3.0
   * @group POS
   * @param {string} chainType - The chain being queried. Currently supports <code>'WAN'</code>, default: <code>'WAN'</code>.
   * @param {string} address - The validator owner address you want to search.
   * @param {any} option - A reserved parameter.
   * @returns {Promise<any>} - The specified validator staking info.
   * @example
   * const ret = await sdk.getValidatorStakeInfo("WAN", "0x086b4cfadfd9f232b068c2e8263d608baee85163");
   * console.log(ret);
   * // [
   * //   {
   * //     "partners": [],
   * //     "address": "0xda8fa1aee77709d37f59fb96afd4cf10ccaeb6ce",
   * //     "pubSec256": "0x04c5b937557d0f5f4d75831d746fc0197cba50c5a98cb901e941956240d45ea374c6ba5919bc3e57de69f9813f99f6658dc86433b6d1156298cbf2b7087429dcc1",
   * //     "pubBn256": "0x0effcb9cb449235ff25108e0d8968b24a52402f4c6a8c67e4c0c71ac2558369d1ccd2e2f5b90613ef05d0594b675a5b7326dce01304f3c0c0b35f5bdc4a7f930",
   * //     "amount": "0xa9bed2b4ed2de500000",
   * //     "votingPower": "0x2a4544f88e102dc6c00000",
   * //     "lockEpochs": 10,
   * //     "nextLockEpochs": 10,
   * //     "from": "0x086b4cfadfd9f232b068c2e8263d608baee85163",
   * //     "stakingEpoch": 18098,
   * //     "feeRate": 1500,
   * //     "clients":
   * //     [
   * //     {
   * //       "address": "0xf99a8bc18061812e09652f5855908e35d034154b",
   * //       "amount": "0x3635c9adc5dea00000",
   * //       "votingPower": "0xd42e876228795e400000",
   * //       "quitEpoch": 0
   * //     },
   * //     {
   * //       "address": "0xa078ecadd6011a0d8df127cb0be12b03f2db0599",
   * //       "amount": "0x3635c9adc5dea00000",
   * //       "votingPower": "0xd42e876228795e400000",
   * //       "quitEpoch": 0
   * //     },
   * //     {
   * //       "address": "0xa373c8e5cbbe161cebbaa5d44f991cd265dcf87d",
   * //       "amount": "0x431cb388cb7d980000",
   * //       "votingPower": "0x106ae56b56c7994f00000",
   * //       "quitEpoch": 0
   * //     },
   * //     {
   * //       "address": "0xe57fcb59c510354b414b2c982ae1ddc4b0f3d329",
   * //       "amount": "0x3635c9adc5dea00000",
   * //       "votingPower": "0xd42e876228795e400000",
   * //       "quitEpoch": 0
   * //     },
   * //     ... ...
   * //     ],
   * //     "maxFeeRate": 1500,
   * //     "feeRateChangedEpoch": 18098
   * //   }
   * // ]
   */
  public async getValidatorStakeInfo(chainType: string, address: string, option: any): Promise<any> {
    return await this._request('getValidatorStakeInfo', { chainType, address, ...(option || {}) });
  }

  /**
   * Get the specified validator's total incentives.
   * @since 1.3.0
   * @group POS
   * @param {string} chainType - The chain being queried. Currently supports <code>'WAN'</code>, default: <code>'WAN'</code>.
   * @param {string|Array<string>} address - The validator address you want to search.
   * @param {any} option - A reserved parameter.
   * @returns {Promise<any>} - The specified validator's total incentives.
   * @example
   * const ret = await sdk.getValidatorTotalIncentive("WAN", "0xda8fa1aee77709d37f59fb96afd4cf10ccaeb6ce");
   * console.log(ret);
   * // [
   * //   {
   * //     "address": "0xda8fa1aee77709d37f59fb96afd4cf10ccaeb6ce",
   * //     "amount": "1.828058184231574257465e+21",
   * //     "minEpochId": 18080,
   * //     "epochCount": 21
   * //   }
   * // ]
   */
  public async getValidatorTotalIncentive(chainType: string, address: string, option: any): Promise<any> {
    return await this._request('getValidatorTotalIncentive', { chainType, address, ...(option || {}) });
  }

  /**
   * Get the identified delegator's staking info.
   * @since 1.3.0
   * @group POS
   * @param {string} chainType - The chain being queried. Currently supports <code>'WAN'</code>, default: <code>'WAN'</code>.
   * @param {string} address - The delegator address you want to query.
   * @param {any} option - A reserved parameter.
   * @returns {Promise<any>} - The identified delegator's staking info.
   * @example
   * const ret = await sdk.getDelegatorStakeInfo("WAN", "0xa6de4408d9003ee992b5dc0e1bf27968e48727dc");
   * console.log(ret);
   * // [
   * //   {
   * //     "address": "0x6fcfcd4719f110e77bef0633d31cc046616b4b34",
   * //     "amount": "0xa968163f0a57b400000",
   * //     "quitEpoch": 0
   * //   },
   * //   {
   * //     "address": "0xdfd7aa554653ca236c197ad746edc2954ca172df",
   * //     "amount": "0x3f870857a3e0e3800000",
   * //     "quitEpoch": 0
   * //   },
   * //   {
   * //     "address": "0x4bf9fd7308d0849a62c3a7dd71c5190e57c28756",
   * //     "amount": "0xa968163f0a57b400000",
   * //     "quitEpoch": 0
   * //   },
   * //   {
   * //     "address": "0x93c8ea0326ef334bdc3011e74cd1a6d78ce0594d",
   * //     "amount": "0xa968163f0a57b400000",
   * //     "quitEpoch": 0
   * //   }
   * // ]
   */
  public async getDelegatorStakeInfo(chainType: string, address: string, option: any): Promise<any> {
    return await this._request('getDelegatorStakeInfo', { chainType, address, ...(option || {}) });
  }

  /**
   * Get the identified delegator rewards over a specified range of epochs.
   * @since 1.3.0
   * @group POS
   * @param {string} chainType - The chain being queried. Currently supports <code>'WAN'</code>, default: <code>'WAN'</code>.
   * @param {string} address - The delegator address you want to query.
   * @param {any} option - A reserved parameter.
   * @returns {Promise<any>} - The identified delegator rewards.
   * @example
   * const ret = await sdk.getDelegatorIncentive("WAN", "0xa6de4408d9003ee992b5dc0e1bf27968e48727dc");
   * console.log(ret);
   * // [
   * //   {
   * //     "address": "0x6fcfcd4719f110e77bef0633d31cc046616b4b34",
   * //     "amount": "0x3217e1b255185bf07",
   * //     "epochId": 18088
   * //   },
   * //   {
   * //     "address": "0x6fcfcd4719f110e77bef0633d31cc046616b4b34",
   * //     "amount": "0x19029a8c0503573f2",
   * //     "epochId": 18090
   * //   },
   * //   ... ...
   * // ]
   */
  public async getDelegatorIncentive(chainType: string, address: string, option: any): Promise<any> {
    return await this._request('getDelegatorIncentive', { chainType, address, ...(option || {}) });
  }

  /**
   * Get the identified delegator's total incentives.
   * @since 1.3.0
   * @group POS
   * @param {string} chainType - The chain being queried. Currently supports <code>'WAN'</code>, default: <code>'WAN'</code>.
   * @param {string} address - The delegator address you want to query.
   * @param {any} option - Optional.
   * <br>&nbsp;&nbsp;<code>validatorAddress</code> - The validator's address you want to query.
   * <br>&nbsp;&nbsp;<code>from</code> - The number that starting epochID you want to query.
   * <br>&nbsp;&nbsp;<code>to</code> - The number that ending epochID you want to query.
   * @returns {Promise<any>} - The identified delegator's total incentives.
   * @example
   * const ret = await sdk.getDelegatorTotalIncentive("WAN", "0xa6de4408d9003ee992b5dc0e1bf27968e48727dc");
   * console.log(ret);
   * // [
   * //   {
   * //     "address": "0x1a95e85e8ffcfd28eb61ee53a542dc98c57b337a",
   * //     "amount": "233401766511923724414",
   * //     "minEpochId": 18080,
   * //     "epochCount": 6
   * //   },
   * //   {
   * //     "address": "0x4bf9fd7308d0849a62c3a7dd71c5190e57c28756",
   * //     "amount": "516430866915939128625",
   * //     "minEpochId": 18088,
   * //     "epochCount": 12
   * //   },
   * //   ... ...
   * // ]
   */
  public async getDelegatorTotalIncentive(chainType: string, address: string, option: any): Promise<any> {
    return await this._request('getDelegatorTotalIncentive', { chainType, address, ...(option || {}) });
  }

  /**
   * Get the Epoch Leader and Random Number Proposer addresses and public key lists in the specified epoch.
   * @since 1.3.0
   * @group POS
   * @param {string} chainType - The chain being queried. Currently supports <code>'WAN'</code>, default: <code>'WAN'</code>.
   * @param {number} epochID - The epochID you want to search.
   * @param {any} option - A reserved parameter.
   * @returns {Promise<any>} - The Epoch Leader and Random Number Proposer addresses and public key lists.
   * @example
   * const ret = await sdk.getLeaderGroupByEpochID("WAN", 18102);
   * console.log(ret);
   * // [
   * //   {
   * //     "pubBn256": "0x0342c5f001e6970037de3d9de692cb89284435df28e63657f88c8e99893be7960006f8cf93c699856ff8aeffcd64531ce0071cdf09a38d043b33bbbf4cd469ed",
   * //     "pubSec256": "0x046c0979fbcd38b7887076db6b08adbbaae45189ac4239d2c06749b634dbeaafdf2b229b6c4eda1ab6ede7e46cbd9ab3ac35df1ac2a6f650bac39fd8474d85524e",
   * //     "secAddr": "0x28c12c7b51860b9d5aec3a0ceb63c6e187c00aac",
   * //     "type": 0
   * //   },
   * //   {
   * //     "pubBn256": "0x093e87d8f1cf8d967be90fc841b73180e8185e480e5b1937c5bd0bf5b47288500598f33d4142bf226b2c8ddaf7358c3093423efdeb1b0a74bfba9d5749ecdf9c",
   * //     "pubSec256": "0x04dac7b023f0e9fb5be91b48e5d546b2f2eb91029705f6055c24b3c804a49cf83f7cd584a96346ca42a94a02456444b7df4e280d2726971bf267f8182341ff81b9",
   * //     "secAddr": "0x1a95e85e8ffcfd28eb61ee53a542dc98c57b337a",
   * //     "type": 0
   * //   },
   * //   {
   * //     "pubBn256": "0x00e0c4fae08f124f7a8fe82988a385d9723bea14c8a6e2996a684846ae8d0d4e27abedb7d2f7150bd42ba830e960774b873de74b1d91d7c5ea1ba349a849e575",
   * //     "pubSec256": "0x047aa28ac3bf36c51e7781984e2843bdb78bf7d78e3e3f2fe5522581e8f94725749d81b6f2dd3068a02f95b9dddb5e3a97f9c6e22edf5a78e25339c3c94aeb31f1",
   * //     "secAddr": "0x57dca45124e253bfa93d7571b43555a861c7455f",
   * //     "type": 1
   * //   },
   * //   {
   * //     "pubBn256": "0x2094589617397846c5125cf5922ba993643c401998ae8817d5005fe21245f4bc0fbb25158c54446757d2b03d89da10d7dfbbaa23afa38c6e87115dcebe2a8e4d",
   * //     "pubSec256": "0x04428597d2d6ab60894c592951337243424637c8b65cc0057215f481dcb78b3e96268365c9bac17bc32b6c08e2c135ca231f636653040f995e8d4e03f6d4b8d812",
   * //     "secAddr": "0x2c72d7a8c02752fcfafbaea5a63c53056cfaf547",
   * //     "type": 1
   * //   },
   * //   ... ...
   * // ]
   */
  public async getLeaderGroupByEpochID(chainType: string, epochID: number, option: any): Promise<any> {
    return await this._request('getLeaderGroupByEpochID', { chainType, epochID, ...(option || {}) });
  }

  /**
   * Get the current epoch info.
   * @since 1.3.0
   * @group POS
   * @param {string} chainType - The chain being queried. Currently supports <code>'WAN'</code>, default: <code>'WAN'</code>.
   * @param {any} option - A reserved parameter.
   * @returns {Promise<any>} - The current epoch info.
   * @example
   * const ret = await sdk.getCurrentEpochInfo("WAN");
   * console.log(ret);
   * // { "blockNumber": 3938057, "slotId": 5661, "epochId": 18102 }
   */
  public async getCurrentEpochInfo(chainType: string, option: any): Promise<any> {
    return await this._request('getCurrentEpochInfo', { chainType, ...(option || {}) });
  }

  /**
   * Returns an array with information on each of the current validators.
   * @since 1.3.0
   * @group POS
   * @param {string} chainType - The chain being queried. Currently supports <code>'WAN'</code>, default: <code>'WAN'</code>.
   * @param {any} option - A reserved parameter.
   * @returns {Promise<any>} - The information on each of the current validators.
   * @example
   * const ret = await sdk.getRandom("WAN", 18102, -1);
   * console.log(ret);
   * // [
   * //   {
   * //     "address": "0xa4626e2bb450204c4b34bcc7525e585e8f678c0d",
   * //     "pubSec256": "0x04b7bf8d3868333f70a30041423c7db204b80b9be2e585c344cf3f391cbf77b17fd14f3058d4475d546355bf8c2709ed9ecf5f0cee9d021c90988af0e8cf52001b",
   * //     "pubBn256": "0x289787688eb80c1e223375a71f8d17110d638a9143afa190dc11b3c1e64cf92b21feb02ab7a1dcb31892210dfda458aff890fe9e7508292099ae6256f197b325",
   * //     "amount": "0xa968163f0a57b400000",
   * //     "votingPower": "0x297116712be7b468800000",
   * //     "lockEpochs": 7,
   * //     "maxFeeRate": 1500,
   * //     "nextLockEpochs": 7,
   * //     "from": "0xdbb2d6199457d11288f0097659bcec24738e158f",
   * //     "stakingEpoch": 0,
   * //     "feeRate": 1500,
   * //     "feeRateChangedEpoch": 0,
   * //     "clients":
   * //     [
   * //       {
   * //         "address": "0xfcc3736dc29bf9af7556fcc1dea10b53edaab51d",
   * //         "amount": "0x56bc75e2d63100000",
   * //         "votingPower": "0x1537da569da5bca00000",
   * //         "quitEpoch": 18071
   * //       }
   * //     ],
   * //     "partners": []
   * //   },
   * //   ... ...
   * // ]
   */
  public async getCurrentStakerInfo(chainType: string, option: any): Promise<any> {
    return await this._request('getCurrentStakerInfo', { chainType, ...(option || {}) });
  }

  /**
   * Returns the total number of slots in an epoch. This is a constant.
   * @since 1.3.0
   * @group POS
   * @param {string} chainType - The chain being queried. Currently supports <code>'WAN'</code>, default: <code>'WAN'</code>.
   * @param {any} option - A reserved parameter.
   * @returns {Promise<number>} - The total number of slots in an epoch.
   * @example
   * const ret = await sdk.apiTest.getSlotCount("WAN");
   * console.log(ret);
   * // 17280
   */
  public async getSlotCount(chainType: string, option: any): Promise<number> {
    return await this._request('getSlotCount', { chainType, ...(option || {}) });
  }

  /**
   * Get the time span of a slot in seconds.
   * @since 1.3.0
   * @group POS
   * @param {string} chainType - The chain being queried. Currently supports <code>'WAN'</code>, default: <code>'WAN'</code>.
   * @param {any} option - A reserved parameter.
   * @returns {Promise<number>} - The the time span of a slot in seconds.
   * @example
   * const ret = await sdk.getSlotTime("WAN");
   * console.log(ret);
   * // 5
   */
  public async getSlotTime(chainType: string, option: any): Promise<number> {
    return await this._request('getSlotTime', { chainType, ...(option || {}) });
  }

  /**
   * Returns the specified epoch's start time in UTC time seconds.
   * @since 1.3.0
   * @group POS
   * @param {string} chainType - The chain being queried. Currently supports <code>'WAN'</code>, default: <code>'WAN'</code>.
   * @param {number} epochID - The epochID you want to search.
   * @param {any} option - A reserved parameter.
   * @returns {Promise<string>} - The specified epoch's start time in UTC time seconds.
   * @example
   * const ret = await sdk.getTimeByEpochID("WAN", 18108);
   * console.log(ret);
   * // 1564531200
   */
  public async getTimeByEpochID(chainType: string, epochID: number, option: any): Promise<number> {
    return await this._request('getTimeByEpochID', { chainType, epochID, ...(option || {}) });
  }

  /**
   * Calculates the Epoch ID according to the time. Enter the UTC time in seconds to get the corresponding Epoch ID.
   * @since 1.3.0
   * @group POS
   * @param {string} chainType - The chain being queried. Currently supports <code>'WAN'</code>, default: <code>'WAN'</code>.
   * @param {number} time - The UTC time seconds you want to query.
   * @param {any} option - A reserved parameter.
   * @returns {Promise<number>} - The current highest stable block number.
   * @example
   * const ret = await sdk.getEpochIDByTime("WAN", 1564550000);
   * console.log(ret);
   * // 18108
   */
  public async getEpochIDByTime(chainType: string, time: number, option: any): Promise<number> {
    return await this._request('getEpochIDByTime', { chainType, time, ...(option || {}) });
  }

  /**
   * Get records of registered validators information.
   * @since 1.3.0
   * @group Service
   * @param {string|Array<string>|undefined} [address] - The validator address you want to search.
   * @param {number|undefined} [after] - The timestamp after you want to search.
   * @returns {Promise<Array<any>>} - The records of registered validators information.
   * @example
   * const ret = await sdk.getRegisteredValidator();
   * console.log(ret);
   * // [
   * //   {
   * //     "address": "0x17d47c6ac4f72d43420f5e9533b526b2dee626a6",
   * //     "name": "MatPool",
   * //     "iconData": "iVBORw0KGgoAAAANSUhEUgAAAEwAAABQCAYAAACzg5PLAAAABGd ... ...",
   * //     "iconType": "png",
   * //     "url": "https://matpool.io/",
   * //     "updatedAt": 1563780889497
   * //   },
   * //   ... ...
   * // ]
   */
  public async getRegisteredValidator(address: string|Array<string>|undefined, after: number|undefined): Promise<Array<any>> {
    return await this._request('getRegisteredValidator', { address, after });
  }

  public async getRegisteredToken(option: {tokenOrigAccount?: string, after?: number}): Promise<Array<object>> {
    return await this._request('getRegisteredToken', { ...(option || {})});
  }

  public async getRegisteredDapp(option: any): Promise<Array<object>> {
    return await this._request('getRegisteredDapp', { ...(option || {})});
  }

  public async getRegisteredAds(option: any): Promise<Array<object>> {
    return await this._request('getRegisteredAds', { ...(option || {})});
  }

  public async getRegisteredCoinGecko(option: any): Promise<Array<object>> {
    return await this._request('getRegisteredCoinGecko', { ...(option || {})});
  }

  public async getPosInfo(chainType: string, option: any): Promise<object> {
    return await this._request('getPosInfo', { chainType, ...(option || {}) });
  }

  public async getMaxBlockNumber(chainType: string, epochID: number, option: any): Promise<Array<object>> {
    return await this._request('getMaxBlockNumber', { chainType, epochID, ...(option || {}) });
  }

  public async getValidatorSupStakeInfo(chainType: string, address: string, option: any): Promise<Array<object>> {
    return await this._request('getValidatorSupStakeInfo', { chainType, address, ...(option || {}) });
  }

  public async getDelegatorSupStakeInfo(chainType: string, address: string, option: any): Promise<Array<object>> {
    return await this._request('getDelegatorSupStakeInfo', { chainType, address, ...(option || {}) });
  }

  public async getEpochIncentiveBlockNumber(chainType: string, epochID: number, option: any): Promise<number> {
    return await this._request('getEpochIncentiveBlockNumber', { chainType, epochID, ...(option || {}) });
  }

  public async getEpochStakeOut(chainType: string, epochID: number, option: any): Promise<Array<object>> {
    return await this._request('getEpochStakeOut', { chainType, epochID, ...(option || {}) });
  }

  public async checkOTAUsed(chainType: string, image: string, option: any): Promise<boolean> {
    return await this._request('checkOTAUsed', { chainType, image, ...(option || {}) });
  }

  public async fetchService(srvType: string, funcName: string, type: string, option: any): Promise<object> {
    return await this._request('fetchService', { srvType, funcName, type, ...(option || {}) });
  }

  public async fetchSpecialService(url: string, type: string, option: any): Promise<object> {
    return await this._request('fetchSpecialService', { url, type, ...(option || {}) });
  }

  public async getRegisteredOrigToken(chainType: string, option: any): Promise<Array<object>> {
    return await this._request('getRegisteredOrigToken', { chainType, ...(option || {}) });
  }

  public async getRegisteredTokenLogo(chainType: string, option: any): Promise<Array<object>> {
    return await this._request('getRegisteredTokenLogo', { chainType, ...(option || {}) });
  }

  public async getRegisteredChainLogo(option: any): Promise<Array<object>> {
    return await this._request('getRegisteredChainLogo', { ...(option || {})} );
  }

  public async getRegisteredMultiChainOrigToken(option: any): Promise<Array<object>> {
    return await this._request('getRegisteredMultiChainOrigToken', { ...(option || {})} );
  }

  public async getRegisteredMapToken(chainType: string, option: any): Promise<Array<object>> {
    return await this._request('getRegisteredMapToken', { chainType, ...(option || {}) } );
  }

  public async getRegisteredSubgraph(option: any): Promise<Array<object>> {
    return await this._request('getRegisteredSubgraph', { ...(option || {})} );
  }

  public async getRegisteredTokenIssuer(option: any): Promise<Array<object>> {
    return await this._request('getRegisteredTokenIssuer', { ...(option || {})} );
  }

  public async getRegisteredTokenList(option: any): Promise<Array<object>> {
    return await this._request('getRegisteredTokenList', { ...(option || {})} );
  }

  public async getStoremanGroupList(option: any): Promise<Array<object>> {
    return await this._request('getStoremanGroupList', { ...(option || {})} );
  }

  public async getStoremanGroupActivity(groupId: string, option: any): Promise<object> {
    return await this._request('getStoremanGroupActivity', { groupId, ...(option || {}) } );
  }

  public async getStoremanGroupQuota(chainType: string, groupId: string, symbol: Array<string>, option: any): Promise<Array<object>> {
    return await this._request('getStoremanGroupQuota', { chainType, groupId, symbol, ...(option || {}) } );
  }

  public async getStoremanGroupInfo(groupId: string, option: any): Promise<object> {
    return await this._request('getStoremanGroupInfo', { groupId, ...(option || {}) } );
  }

  public async getMultiStoremanGroupInfo(groupId: string, symbol: Array<string>, option: any): Promise<Array<object>> {
    return await this._request('getMultiStoremanGroupInfo', { groupId, symbol, ...(option || {}) } );
  }

  public async getStoremanGroupConfig(groupId: string, option: any): Promise<object> {
    return await this._request('getStoremanGroupConfig', { groupId, ...(option || {}) } );
  }

  public async getStoremanInfo(wkAddr: string, option: any): Promise<object> {
    return await this._request('getStoremanInfo', { wkAddr, ...(option || {}) } );
  }

  public async getMultiStoremanInfo(wkAddr: Array<string>, option: any): Promise<Array<object>> {
    return await this._request('getMultiStoremanInfo', { wkAddr, ...(option || {}) } );
  }

  public async getStoremanConf(option: any): Promise<object> {
    return await this._request('getStoremanConf', { ...(option || {})} );
  }

  public async getStoremanCandidates(groupId: string, option: any): Promise<Array<object>> {
    return await this._request('getStoremanCandidates', { groupId, ...(option || {}) } );
  }

  public async getStoremanCandidatesV2(groupId: string, option: any): Promise<Array<object>> {
    return await this._request('getStoremanCandidatesV2', { groupId, ...(option || {}) } );
  }

  public async getStoremanGroupMember(groupId: string, option: any): Promise<Array<object>> {
    return await this._request('getStoremanGroupMember', { groupId, ...(option || {}) } );
  }

  public async getStoremanGroupMemberV2(groupId: string, option: any): Promise<Array<object>> {
    return await this._request('getStoremanGroupMemberV2', { groupId, ...(option || {}) } );
  }

  public async getStoremanStakeInfo(option: any): Promise<Array<object>> {
    return await this._request('getStoremanStakeInfo', { ...(option || {})} );
  }

  public async getStoremanStakeTotalIncentive(option: any): Promise<Array<object>> {
    return await this._request('getStoremanStakeTotalIncentive', { ...(option || {})} );
  }

  public async getStoremanDelegatorInfo(option: any): Promise<Array<object>> {
    return await this._request('getStoremanDelegatorInfo', { ...(option || {})} );
  }

  public async getStoremanDelegatorTotalIncentive(option: any): Promise<Array<object>> {
    return await this._request('getStoremanDelegatorTotalIncentive', { ...(option || {})} );
  }

  public async getStoremanGpkSlashInfo(option: any): Promise<Array<object>> {
    return await this._request('getStoremanGpkSlashInfo', { ...(option || {})} );
  }

  public async getStoremanSignSlashInfo(option: any): Promise<Array<object>> {
    return await this._request('getStoremanSignSlashInfo', { ...(option || {})} );
  }

  public async getTokenPairs(option: any): Promise<Array<object>> {
    return await this._request('getTokenPairs', { ...(option || {})} );
  }

  public async getTokenPairInfo(id: string, option: any): Promise<object> {
    return await this._request('getTokenPairInfo', { id, ...(option || {}) } );
  }

  public async getTokenPairAncestorInfo(id: string, option: any): Promise<object> {
    return await this._request('getTokenPairAncestorInfo', { id, ...(option || {}) } );
  }

  public async getTokenPairIDs(option: any): Promise<Array<string>> {
    return await this._request('getTokenPairIDs', { ...(option || {})} );
  }

  public async getChainConstantInfo(option: any): Promise<Array<string | number>> {
    return await this._request('getChainConstantInfo', { ...(option || {})} );
  }

  public async getSupportedChainInfo(option: any): Promise<Array<object>> {
    return await this._request('getSupportedChainInfo', { ...(option || {})} );
  }

  public async getPrdInctMetric(option: any): Promise<Array<object>> {
    return await this._request('getPrdInctMetric', { ...(option || {})} );
  }

  public async getSelectedSmInfo(option: any): Promise<Array<object>> {
    return await this._request('getSelectedSmInfo', { ...(option || {})} );
  }

  public async getSelectedStoreman(option: any): Promise<Array<string>> {
    return await this._request('getSelectedStoreman', { ...(option || {})} );
  }

  public async getSmDelegatorInfo(option: any): Promise<Array<string>> {
    return await this._request('getSmDelegatorInfo', { ...(option || {})} );
  }

  public async getRewardRatio(option: any): Promise<Array<string>> {
    return await this._request('getRewardRatio', { ...(option || {})} );
  }

  public async multiCall(chainType: string, calls: Array<object>, option: any): Promise<Array<string>> {
    return await this._request('multiCall', { chainType, calls, ...(option || {}) } );
  }

  public async multiCall2(chainType: string, calls: Array<object>, option: any): Promise<Array<string>> {
    return await this._request('multiCall2', { chainType, calls, ...(option || {}) } );
  }

  public async getCode(chainType: string, address: string, option: any): Promise<string> {
    return await this._request('getCode', { chainType, address, ...(option || {}) } );
  }

  public async estimateNetworkFee(chainType: string, feeType: 'lock' | 'release', option: any): Promise<any> {
    return await this._request('estimateNetworkFee', { chainType, feeType, ...(option || {}) });
  }

  public async getLedgerVersion(chainType: string, option: any): Promise<string | number> {
    return await this._request('getLedgerVersion', { chainType, ...(option || {}) } );
  }

  public async getLedger(chainType: string, option: any): Promise<any> {
    return await this._request('getLedger', { chainType, ...(option || {}) });
  }

  public async getServerInfo(chainType: string, option: any): Promise<number | string | any> {
    return await this._request('getServerInfo', { chainType, ...(option || {}) });
  }

  public async getCrossChainFees(chainType: string, chainIds: [number | string, number | string], option: any): Promise<any> {
    return await this._request('getCrossChainFees', { chainType, chainIds, ...(option || {}) });
  }

  public async getMinCrossChainAmount(crossChain: string, symbol: string, option: any): Promise<number | string | any> {
    return await this._request('getMinCrossChainAmount', { crossChain, symbol, ...(option || {}) });
  }

  public async estimateCrossChainOperationFee(chainType: string, targetChainType: string, option: any): Promise<any> {
    return await this._request('estimateCrossChainOperationFee', { chainType, targetChainType, ...(option || {}) });
  }

  public async estimateCrossChainNetworkFee(chainType: string, targetChainType: string, option: any): Promise<any> {
    return await this._request('estimateCrossChainNetworkFee', { chainType, targetChainType, ...(option || {}) });
  }

  public async getLatestBlock(chainType: string, option: any): Promise<any> {
    return await this._request('getLatestBlock', { chainType, ...(option || {}) });
  }

  public async getEpochParameters(chainType: string, option: any): Promise<any> {
    return await this._request('getEpochParameters', { chainType, ...(option || {}) });
  }

  public async getCostModelParameters(chainType: string, option: any): Promise<any> {
    return await this._request('getCostModelParameters', { chainType, ...(option || {}) });
  }

  public async getTokenPairsHash(option: any): Promise<string> {
    return await this._request('getTokenPairsHash', { ...(option || {})} );
  }

  public async getGateWayBalances(chainType: string, address: string, option: any): Promise<any> {
    return await this._request('getGateWayBalances', { chainType, address, ...(option || {}) });
  }

  public async getTrustLines(chainType: string, address: string, option: any): Promise<Array<object>> {
    return await this._request('getTrustLines', { chainType, address, ...(option || {}) });
  }

  public async getCrossChainReservedQuota(option: any): Promise<any> {
    return await this._request('getCrossChainReservedQuota', { ...(option || {})});
  }

  public async hasHackerAccount(address: Array<string>, image: string, option: any): Promise<boolean> {
    return await this._request('hasHackerAccount', { address, image, ...(option || {}) });
  }

  public async getChainParameters(chainType: string, option: any): Promise<Array<object>> {
    return await this._request('getChainParameters', { chainType, ...(option || {}) });
  }

  public async getChainQuotaHiddenFlags(option: any): Promise<Array<object>> {
    return await this._request('getChainQuotaHiddenFlags', { ...(option || {})});
  }

  public async getChainQuotaHiddenFlagDirectionally(option: any): Promise<Array<object>> {
    return await this._request('getChainQuotaHiddenFlagDirectionally', { ...(option || {})});
  }

  public async getWanBridgeDiscounts(option: any): Promise<Array<object>> {
    return await this._request('getWanBridgeDiscounts', { ...(option || {})});
  }



  /**
   * Manually close the connection
   * 
   * - Stops all auto-reconnect
   * - Rejects all pending requests
   * - Emits 'closed' event
   */
  close() {
    this.manuallyClosed = true;
    console.log("close")
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    this.clearPending('Connection closed by client');
    this.ws?.close(1000, 'Client manual close');

    this.removeAllListeners();
    this.emit('closed');
  }
  /**
   * Manually reconnect after calling close()
   */
  reconnectManually() {
    if (this.manuallyClosed) {
      this.manuallyClosed = false;
      this.createWebSocket().catch(e => this.emit('error', e));
    }
  }
}
