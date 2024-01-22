import { sha256, sha512 } from 'multiformats/hashes/sha2'
import { CID } from 'multiformats/cid'
import * as json from 'multiformats/codecs/json'
import * as raw from 'multiformats/codecs/raw'
import { base64, base64pad, base64url, base64urlpad } from "multiformats/bases/base64"
import { base10 } from 'multiformats/bases/base10'
import { base16 } from 'multiformats/bases/base16'
import { base2 } from 'multiformats/bases/base2'
// next import required to satisfy typescript
import { Codec } from 'node_modules/multiformats/dist/src/bases/base.js'
import * as dagPb from '@ipld/dag-pb'
import * as dagJson from '@ipld/dag-json'
import * as dagCbor from '@ipld/dag-cbor'
import {Stream} from 'stream'
import { decode as multihashDecode, create as multihashCreate, Digest } from 'multiformats/hashes/digest';

export * as Block from 'multiformats/block'
export { TextEncoder, TextDecoder } from "util"
export { CID } from "multiformats"

export const codecs = {
    json: json,
    raw: raw,
    dagPb: dagPb,
    dagJson: dagJson,
    dagCbor: dagCbor
}

export const hashes = {
    sha256: sha256,
    sha512: sha512
}

export const bases = {
    base64: base64,
    base64pad: base64pad,
    base64url: base64url,
    base64urlpad: base64urlpad,
    base10: base10,
    base16: base16,
    base2: base2
}

export const cidToString = (cid: CID, base) => {
    return cid.toString(base.encoder)
}

export const stringToCid = (hash: string, base) => {
    return CID.parse(hash, base.decoder)
}

export const getCIDOfData = async (data, codec) => {
    const bytes = codec.encode(data)

    const hash = await sha256.digest(bytes)
    const cid = CID.create(1, codec.code, hash)
    return cid
}

export function streamToString (stream): Promise<string> {
    const chunks = [];
    return new Promise((resolve, reject) => {
      stream.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
      stream.on('error', (err) => reject(err));
      stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    })
}

export function streamFromString(raw) {
    const Readable = Stream.Readable;
    const s = new Readable();
    s._read = function noop() {};
    s.push(raw);
    s.push(null);
    return s;
}

export async function getSha256Hash(input: Uint8Array): Promise<Digest<number, number>> {
    return await sha256.digest(input)
}

export async function getCIDV1OfBytes(input: Uint8Array, codec?: any): Promise<CID> {
    const code = codecs.raw.code
    return CID.createV1(code, await getSha256Hash(input))
}

export function getCIDV0OfBytes(input: Uint8Array, codec?: any): CID {
    return CID.createV0(multihashCreate(18, input))
}