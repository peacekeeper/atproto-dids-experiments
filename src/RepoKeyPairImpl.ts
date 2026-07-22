import { secp256k1 } from '@noble/curves/secp256k1'
import { p256 } from '@noble/curves/p256'
import { ed25519 } from '@noble/curves/ed25519'
import { base64url } from 'jose';

export class RepoKeyPairImpl {
  readonly privateKey: Uint8Array
  readonly didString: string
  readonly jwtAlgString: string

  constructor(jwk: JsonWebKey) {
    if (!jwk.d) {
      throw new Error('JWK must contain private key')
    }

    this.privateKey = base64url.decode(jwk.d)
    this.keyString = jwk.kid.split("#")[0];;

    if (jwk.kty === 'EC' && jwk.crv === 'P-256') this.jwtAlgString = 'P-256';
    if (jwk.kty === 'EC' && jwk.crv === 'secp256k1') this.jwtAlgString = 'secp256k1';
    if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') this.jwtAlgString = 'Ed25519';
  }

  async sign(msg: Uint8Array): Promise<Uint8Array> {
    switch (this.jwtAlgString) {
      case 'secp256k1': return secp256k1.sign(msg, this.privateKey).toCompactRawBytes();
      case 'P-256': return p256.sign(msg, this.privateKey).toCompactRawBytes();
      case 'Ed25519': return ed25519.sign(msg, this.privateKey);
      default: throw new Error(`Unsupported algorithm: ${this.jwtAlgString}`)
    }
  }

  did(): string {
    return this.keyString
  }

  jwtAlg(): string {
    switch (this.jwtAlgString) {
      case 'P-256': return 'P-256';
      case 'secp256k1': return 'secp256k1';
      case 'Ed25519': return 'EdDSA';
      default: throw new Error(`Unsupported algorithm: ${this.jwtAlgString}`);
    }
  }
}