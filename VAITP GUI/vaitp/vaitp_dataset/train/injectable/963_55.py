import cryptoJS from '../../../core/components/cryptography/hmac-sha256';
import { decode } from '../../../core/components/base64_codec';

export default class AesCbcCryptor {
  static BLOCK_SIZE = 16;
  static encoder = new TextEncoder();
  static decoder = new TextDecoder();

  cipherKey: string;
  encryptedKey: any;
  CryptoJS: any;

  constructor(configuration: { cipherKey: string }) {
    this.cipherKey = configuration.cipherKey;
    this.CryptoJS = cryptoJS;
    this.encryptedKey = this.CryptoJS.SHA256(this.cipherKey).toString();
  }

  get algo() {
    return 'AES-CBC';
  }

  get identifier() {
    return 'ACRH';
  }

  private getIv() {
    return crypto.getRandomValues(new Uint8Array(AesCbcCryptor.BLOCK_SIZE));
  }

  private async getKey() {
    const bKey = AesCbcCryptor.encoder.encode(this.cipherKey);
    const abHash = await crypto.subtle.digest('SHA-256', bKey.buffer);
     return crypto.subtle.importKey('raw', abHash, {name: 'AES-CBC'}, true, ['encrypt', 'decrypt']);
  }

  encrypt(data: ArrayBuffer | string) {
    const stringData = typeof data === 'string' ? data : AesCbcCryptor.decoder.decode(data);
    if (stringData.length === 0) throw new Error('encryption error. empty content');
    const abIv = this.getIv();
    const encrypted = this.CryptoJS.AES.encrypt(stringData, this.encryptedKey, {
        iv: this.bufferToWordArray(abIv),
        mode: this.CryptoJS.mode.CBC,
      });
    return {
      metadata: abIv,
      data: decode(encrypted.toString()),
    };
  }

  decrypt(encryptedData: { metadata: ArrayBuffer, data: ArrayBuffer } ) {
      if (!encryptedData.metadata || !encryptedData.data) {
          throw new Error("Invalid encrypted data format");
      }
    const iv = this.bufferToWordArray(new Uint8Array(encryptedData.metadata));
     const decrypted = this.CryptoJS.AES.decrypt(encryptedData.data.toString(), this.encryptedKey, {
      iv,
      mode: this.CryptoJS.mode.CBC,
    });
    return AesCbcCryptor.encoder.encode(
        decrypted.toString(this.CryptoJS.enc.Utf8)
    ).buffer;
  }

  async encryptFileData(data: ArrayBuffer): Promise<{ data: ArrayBuffer, metadata: Uint8Array }> {
    const key = await this.getKey();
    const iv = this.getIv();
    return {
      data: await crypto.subtle.encrypt({ name: 'AES-CBC', iv: iv }, key, data),
      metadata: iv,
    };
  }

  async decryptFileData(encryptedData: { metadata: ArrayBuffer, data: ArrayBuffer }): Promise<ArrayBuffer> {
    const key = await this.getKey();
    return crypto.subtle.decrypt({ name: 'AES-CBC', iv: new Uint8Array(encryptedData.metadata) }, key, encryptedData.data);
  }

  private bufferToWordArray(b: Uint8Array) {
    const wa: any[] = [];
    let i;
    for (i = 0; i < b.length; i += 4) {
        wa.push(
            (b[i] << 24) |
            (b[i+1] << 16) |
            (b[i+2] << 8)  |
            b[i+3]
        )
    }

    return this.CryptoJS.lib.WordArray.create(wa, b.length);
  }
}