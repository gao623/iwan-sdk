// ========================================================
// iWan SDK - TypeScript Rewrite (v2.2.0 - Final Optimized)
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
  clientVersion: '2.2.0',
  timeout: 30000,
  pingTime: 30000,
  maxTries: 3,
  reconnTime: 2000,
} as const;

// ====================== TYPES ======================
export interface IwanClientOptions {
  url?: string;
  port?: number;
  flag?: string;
  version?: string;
  clientType?: string;
  clientVersion?: string;
  timeout?: number;
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

// ====================== CRYPTO (Node + Browser) ======================
async function generateSignature(secret: string, msg: string): Promise<string> {
  const encoder = new TextEncoder();
  if (typeof window !== 'undefined' && window.crypto?.subtle) {
    const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(msg));
    const arr = Array.from(new Uint8Array(sig));
    return btoa(String.fromCharCode(...arr));
  }
  const { createHmac } = await import('crypto');
  return createHmac('sha256', secret).update(msg).digest('base64');
}

async function signPayload(payload: RPCMessage, secretKey: string): Promise<RPCMessage> {
  const newPayload = { ...payload };
  newPayload.params.timestamp = Date.now();
  newPayload.params.signature = await generateSignature(secretKey, JSON.stringify(newPayload));
  return newPayload;
}

// ====================== WS CORE ======================
export class IwanClient extends EventEmitter {
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

  constructor(apiKey: string, secretKey: string, option: IwanClientOptions = {}) {
    super();

    if (!apiKey || !secretKey) throw new IWanError('APIKEY and SECRETKEY are both required');

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

    this.ws = new WSConstructor(this.wsUrl);

    this.ws.onopen = () => this.emit('open');
    this.ws.onmessage = (event: any) => this.handleMessage(event.data ?? event);
    this.ws.onerror = (err: any) => this.emit('error', err);
    this.ws.onclose = () => this.reconnect();

    if (!this.isBrowser) {
      this.ws.on('pong', () => { this.ws.isAlive = true; });
    }

    this.ws.isAlive = true;
    this.startHeartbeat();
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
      if (!this.isOpen() || this.isBrowser) return;
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
    if (this.lockReconnect) return;
    this.lockReconnect = true;
    setTimeout(() => {
      this.tries = DEFAULT_CONFIG.maxTries;
      this.createWebSocket().catch(e => this.emit('error', e));
      this.lockReconnect = false;
    }, DEFAULT_CONFIG.reconnTime);
  }

  private isOpen(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  private async _request<T>(method: string, params: any = {}): Promise<T> {
    if (!this.isOpen()) throw new IWanError('WebSocket not connected');

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

  // ====================== PUBLIC API ======================
  async call<T = any>(method: string, params: any = {}): Promise<T> {
    return this._request(method, params);
  }

  async getBalance(chainType: string, address: string): Promise<string> {
    return this._request('getBalance', { chainType, address });
  }

  async monitorEvent(chainType: string, address: string, topics: string[]): Promise<any> {
    return this._request('monitorEvent', { chainType, address, topics });
  }

  // ... 继续添加你需要的封装方法

  close() {
    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    this.ws?.close();
    this.pending.clear();
    this.removeAllListeners();
  }
}

export default IwanClient;