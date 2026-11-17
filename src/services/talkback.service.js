'use-strict';

/**
 * Two-way audio (talkback) for Hikvision devices via ISAPI,
 * e.g. Hikvision door stations and OEM devices such as the Metzler VDM10.
 *
 * Flow:
 *   1. (optional) release a ringing call: answer + hangUp, so the speaker is free
 *   2. PUT /ISAPI/System/TwoWayAudio/channels/<ch>/open           -> sessionId
 *   3. PUT /ISAPI/System/TwoWayAudio/channels/<ch>/audioData?sessionId=...
 *      long-running request, G.711 µ-law 8 kHz mono, paced in 20 ms frames,
 *      preceded by a short block of silence so the speaker can start up
 *   4. PUT /ISAPI/System/TwoWayAudio/channels/<ch>/close?sessionId=...
 *
 * The channel is opened lazily when HomeKit starts sending audio and closed
 * again after a short idle period or when the stream stops.
 */

import http from 'http';
import crypto from 'crypto';

import Logger from '../../services/logger/logger.service.js';

const FRAME_BYTES = 160; // 20 ms G.711 @ 8 kHz
const FRAME_MS = 20;
const MAX_QUEUE_BYTES = 32 * 1024;
const CATCH_UP_THRESHOLD = FRAME_BYTES * 10; // > 200 ms queued -> send at 2x real time
const OPEN_RETRY_DELAYS = [50, 100, 200];
const RETRY_COOLDOWN_MS = 5000;
const ULAW_SILENCE = 0xff;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const tagValue = (xml, tag) => xml?.match(new RegExp(`<${tag}>([^<]*)</${tag}>`))?.[1];

/**
 * Extracts host and credentials from an FFmpeg source like
 * "-rtsp_transport tcp -i rtsp://user:pa%21ss@192.168.1.2:554/Streaming/Channels/101"
 */
export const parseSourceCredentials = (source) => {
  const urlString = (source || '').split(/\s+/).find((part) => /^(rtsps?|https?):\/\//i.test(part));

  if (!urlString) {
    return {};
  }

  try {
    const url = new URL(urlString);

    return {
      host: url.hostname,
      username: url.username ? decodeURIComponent(url.username) : undefined,
      password: url.password ? decodeURIComponent(url.password) : undefined,
    };
  } catch {
    return {};
  }
};

export class IsapiClient {
  constructor({ host, port = 80, username, password, timeout = 10000 }) {
    this.host = host;
    this.port = port;
    this.username = username;
    this.password = password;
    this.timeout = timeout;
    this.nc = 0;
  }

  rawRequest(method, path, headers = {}, body) {
    return new Promise((resolve, reject) => {
      const request = http.request(
        { host: this.host, port: this.port, method, path, headers, agent: false },
        (response) => {
          const chunks = [];
          response.on('data', (chunk) => chunks.push(chunk));
          response.on('end', () =>
            resolve({ status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks).toString() })
          );
          response.on('error', reject);
        }
      );

      request.on('error', reject);
      request.setTimeout(this.timeout, () => request.destroy(new Error(`Timeout: ${method} ${path.split('?')[0]}`)));
      request.end(body);
    });
  }

  static parseChallenge(header) {
    if (!header || !/^Digest\s/i.test(header)) {
      return null;
    }

    const parameters = {};

    for (const match of header.slice(7).matchAll(/(\w+)=(?:"([^"]*)"|([^\s,]+))/g)) {
      parameters[match[1].toLowerCase()] = match[2] ?? match[3];
    }

    return parameters;
  }

  digestHeader(challenge, method, path) {
    const algorithm = (challenge.algorithm || 'MD5').toUpperCase();
    const hashName = algorithm.startsWith('SHA-256') ? 'sha256' : 'md5';
    const H = (value) => crypto.createHash(hashName).update(value).digest('hex');

    const cnonce = crypto.randomBytes(8).toString('hex');
    const nc = (++this.nc).toString(16).padStart(8, '0');
    const qop = challenge.qop
      ?.split(',')
      .map((value) => value.trim())
      .includes('auth')
      ? 'auth'
      : undefined;

    let ha1 = H(`${this.username}:${challenge.realm}:${this.password}`);

    if (algorithm.endsWith('-SESS')) {
      ha1 = H(`${ha1}:${challenge.nonce}:${cnonce}`);
    }

    const ha2 = H(`${method}:${path}`);
    const response = qop
      ? H(`${ha1}:${challenge.nonce}:${nc}:${cnonce}:${qop}:${ha2}`)
      : H(`${ha1}:${challenge.nonce}:${ha2}`);

    const parts = [
      `username="${this.username}"`,
      `realm="${challenge.realm}"`,
      `nonce="${challenge.nonce}"`,
      `uri="${path}"`,
      `response="${response}"`,
    ];

    if (challenge.algorithm) parts.push(`algorithm=${challenge.algorithm}`);
    if (challenge.opaque) parts.push(`opaque="${challenge.opaque}"`);
    if (qop) parts.push(`qop=${qop}`, `nc=${nc}`, `cnonce="${cnonce}"`);

    return `Digest ${parts.join(', ')}`;
  }

  // Sends an unauthenticated probe to obtain the challenge and returns the Authorization header (or undefined).
  async authorization(method, path) {
    const probe = await this.rawRequest(method, path, { 'Content-Length': '0' });

    if (probe.status !== 401) {
      return;
    }

    const challenges = [probe.headers['www-authenticate'] || []].flat();
    const digest = challenges.map((header) => IsapiClient.parseChallenge(header)).find(Boolean);

    if (digest) {
      return this.digestHeader(digest, method, path);
    }

    if (challenges.some((header) => /^Basic/i.test(header))) {
      return 'Basic ' + Buffer.from(`${this.username}:${this.password}`).toString('base64');
    }

    throw new Error(`Unsupported authentication scheme: ${challenges.join(' | ')}`);
  }

  async request(method, path, body, contentType) {
    const authorization = await this.authorization(method, path);
    const headers = { 'Content-Length': String(body ? Buffer.byteLength(body) : 0) };

    if (contentType) headers['Content-Type'] = contentType;
    if (authorization) headers.Authorization = authorization;

    return this.rawRequest(method, path, headers, body);
  }

  // Long-running PUT for streaming audio. Hikvision expects "Content-Length: 0" while the body is streamed.
  async openStream(path) {
    const authorization = await this.authorization('PUT', path);
    const headers = { 'Content-Type': 'application/octet-stream', Connection: 'keep-alive', 'Content-Length': '0' };

    if (authorization) headers.Authorization = authorization;

    const request = http.request({ host: this.host, port: this.port, method: 'PUT', path, headers, agent: false });
    request.flushHeaders();

    return request;
  }
}

export default class HikvisionTalkback {
  static isEnabled(videoConfig = {}) {
    return String(videoConfig.returnAudio?.mode || '').toLowerCase() === 'hikvision';
  }

  static fromVideoConfig(cameraName, videoConfig = {}) {
    if (!HikvisionTalkback.isEnabled(videoConfig)) {
      return null;
    }

    const config = videoConfig.returnAudio;
    const fromSource = parseSourceCredentials(videoConfig.source);

    const options = {
      host: config.host || fromSource.host,
      port: Number(config.port) || 80,
      username: config.username || fromSource.username,
      password: config.password ?? fromSource.password ?? '',
      channel: String(config.channel || 1),
      releaseRingingCall: config.releaseRingingCall !== false,
      warmup: Number.isFinite(Number(config.warmup)) ? Number(config.warmup) : 800,
      idleTimeout: Number(config.idleTimeout) > 0 ? Number(config.idleTimeout) : 3000,
    };

    if (!options.host || !options.username) {
      Logger.log.warn(
        'Two-way audio (Hikvision): host/username could not be determined. Set "returnAudio.host" and "returnAudio.username" or use a source URL with credentials.',
        cameraName,
        'Homebridge'
      );
      return null;
    }

    return new HikvisionTalkback(cameraName, options);
  }

  constructor(cameraName, options) {
    this.log = Logger.log;
    this.cameraName = cameraName;
    this.options = options;
    this.client = new IsapiClient(options);

    this.state = 'idle'; // idle | opening | open | closing
    this.stopped = false;
    this.queue = Buffer.alloc(0);
    this.cooldownUntil = 0;
    this.lastData = 0;
    this.request = null;
    this.sessionId = null;
    this.timer = null;
  }

  get basePath() {
    return `/ISAPI/System/TwoWayAudio/channels/${this.options.channel}`;
  }

  // Receives G.711 µ-law audio (8 kHz mono) from FFmpeg.
  write(chunk) {
    if (this.stopped || !chunk?.length) {
      return;
    }

    this.lastData = Date.now();
    this.queue = Buffer.concat([this.queue, chunk]);

    if (this.queue.length > MAX_QUEUE_BYTES) {
      this.queue = this.queue.subarray(this.queue.length - MAX_QUEUE_BYTES);
    }

    if (this.state === 'idle' && Date.now() >= this.cooldownUntil) {
      this.open();
    }
  }

  async open() {
    this.state = 'opening';

    try {
      if (this.options.releaseRingingCall) {
        await this.releaseRingingCall();
      }

      const sessionId = await this.openChannel();

      if (this.stopped) {
        await this.closeChannel(sessionId).catch(() => {});
        this.state = 'idle';
        return;
      }

      const query = sessionId ? `?sessionId=${sessionId}` : '';
      const request = await this.client.openStream(`${this.basePath}/audioData${query}`);

      request.on('response', (response) => {
        response.resume();

        if (response.statusCode !== 200) {
          this.log.warn(
            `Two-way audio (Hikvision): audioData answered with HTTP ${response.statusCode}`,
            this.cameraName,
            'Homebridge'
          );
        }
      });

      request.on('error', (error) => {
        if (this.request === request) {
          this.log.warn(`Two-way audio (Hikvision): stream error: ${error.message}`, this.cameraName, 'Homebridge');
          this.closeSession();
        }
      });

      request.on('close', () => {
        if (this.request === request && this.state === 'open') {
          this.log.debug('Two-way audio (Hikvision): stream closed by device', this.cameraName);
          this.closeSession();
        }
      });

      this.sessionId = sessionId;
      this.request = request;
      this.state = 'open';
      this.warmupFrames = Math.ceil(Math.max(0, this.options.warmup) / FRAME_MS);

      this.log.info('Two-way audio opened (Hikvision ISAPI)', this.cameraName);

      this.startPacer();

      if (this.stopped) {
        await this.closeSession();
      }
    } catch (error) {
      this.log.warn(`Two-way audio (Hikvision) could not be opened: ${error.message}`, this.cameraName, 'Homebridge');

      this.state = 'idle';
      this.queue = Buffer.alloc(0);
      this.cooldownUntil = Date.now() + RETRY_COOLDOWN_MS;
    }
  }

  startPacer() {
    let nextTick = Date.now();

    const tick = () => {
      if (this.state !== 'open' || !this.request) {
        return;
      }

      if (this.warmupFrames > 0) {
        this.warmupFrames--;
        this.request.write(Buffer.alloc(FRAME_BYTES, ULAW_SILENCE));
      } else {
        const frames = this.queue.length > CATCH_UP_THRESHOLD ? 2 : 1;

        for (let index = 0; index < frames; index++) {
          const frame = Buffer.alloc(FRAME_BYTES, ULAW_SILENCE);
          const take = Math.min(FRAME_BYTES, this.queue.length);

          if (take > 0) {
            this.queue.copy(frame, 0, 0, take);
            this.queue = this.queue.subarray(take);
          }

          this.request.write(frame);
        }

        if (this.queue.length === 0 && Date.now() - this.lastData > this.options.idleTimeout) {
          this.log.debug('Two-way audio (Hikvision): no audio received, closing channel', this.cameraName);
          this.closeSession();
          return;
        }
      }

      nextTick += FRAME_MS;
      this.timer = setTimeout(tick, Math.max(0, nextTick - Date.now()));
    };

    tick();
  }

  async closeSession() {
    if (this.state !== 'open') {
      return;
    }

    this.state = 'closing';

    clearTimeout(this.timer);
    this.timer = null;

    const request = this.request;
    const sessionId = this.sessionId;

    this.request = null;
    this.sessionId = null;

    try {
      await this.closeChannel(sessionId);
    } catch (error) {
      this.log.debug(`Two-way audio (Hikvision): close failed: ${error.message}`, this.cameraName);
    }

    request?.destroy();

    this.queue = Buffer.alloc(0);
    this.state = 'idle';

    this.log.info('Two-way audio closed (Hikvision ISAPI)', this.cameraName);
  }

  async stop() {
    this.stopped = true;
    await this.closeSession();
  }

  async openChannel() {
    let lastResponse;

    for (let attempt = 0; attempt <= OPEN_RETRY_DELAYS.length; attempt++) {
      lastResponse = await this.client.request('PUT', `${this.basePath}/open`);

      if (lastResponse.status === 200) {
        return tagValue(lastResponse.body, 'sessionId');
      }

      if (lastResponse.status === 401) {
        throw new Error('authentication failed (check username/password)');
      }

      if (attempt < OPEN_RETRY_DELAYS.length) {
        this.log.debug(
          `Two-way audio (Hikvision): channel busy (HTTP ${lastResponse.status}), retrying in ${OPEN_RETRY_DELAYS[attempt]} ms`,
          this.cameraName
        );
        await sleep(OPEN_RETRY_DELAYS[attempt]);
      }
    }

    const reason = tagValue(lastResponse.body, 'subStatusCode') || tagValue(lastResponse.body, 'statusString') || '';
    throw new Error(`open failed with HTTP ${lastResponse.status} ${reason}`.trim());
  }

  async closeChannel(sessionId) {
    const query = sessionId ? `?sessionId=${sessionId}` : '';
    const response = await this.client.request('PUT', `${this.basePath}/close${query}`);

    if (response.status !== 200) {
      throw new Error(`HTTP ${response.status}`);
    }
  }

  async getCallStatus() {
    try {
      const response = await this.client.request('GET', '/ISAPI/VideoIntercom/callStatus?format=json');
      return JSON.parse(response.body)?.CallStatus?.status || 'idle';
    } catch {
      return 'idle';
    }
  }

  async sendCallSignal(cmdType) {
    return this.client.request(
      'PUT',
      '/ISAPI/VideoIntercom/callSignal?format=json',
      JSON.stringify({ CallSignal: { cmdType } }),
      'application/json'
    );
  }

  // A ringing call keeps the speaker busy. Answer + hang up releases it (stops the ringing at the indoor station).
  async releaseRingingCall() {
    if ((await this.getCallStatus()) !== 'ring') {
      return;
    }

    this.log.info('Two-way audio (Hikvision): doorbell is ringing, releasing call', this.cameraName);

    try {
      await this.sendCallSignal('answer');
    } catch (error) {
      this.log.debug(`Two-way audio (Hikvision): answer failed: ${error.message}`, this.cameraName);
    }

    try {
      await this.sendCallSignal('hangUp');
    } catch (error) {
      this.log.debug(`Two-way audio (Hikvision): hangUp failed: ${error.message}`, this.cameraName);
    }

    for (let index = 0; index < 20; index++) {
      if ((await this.getCallStatus()) === 'idle') {
        return;
      }

      await sleep(100);
    }

    this.log.debug('Two-way audio (Hikvision): call still active after release attempt', this.cameraName);
  }
}
