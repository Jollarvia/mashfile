import type { Helia } from '@helia/interface';
import type { ByteStream } from 'ipfs-unixfs-importer'
import { json } from '@helia/json'
import { sha256, sha512 } from 'multiformats/hashes/sha2'
import { CID } from 'multiformats/cid';
import { strings } from '@helia/strings'
import { dagJson } from '@helia/dag-json'
import { dagCbor } from '@helia/dag-cbor'
import { unixfs, AddOptions } from '@helia/unixfs'
import { Readable, Stream } from 'stream';
import { Digest } from 'multiformats/hashes/digest';
import * as rawCodec from 'multiformats/codecs/raw';
import * as jsonCodec from 'multiformats/codecs/json';
import { HeliaInit } from 'helia';

export {ByteStream}
export class IpfsService {
  constructor(private heliaInit: HeliaInit = null){

  }

  private helia?: Helia

  async getHelia(): Promise<Helia> {
    if (this.helia == null) {
      const { createHelia } = await import('helia');
      this.helia = await createHelia(this.heliaInit || {})
    }

    return this.helia
  }

  async has(immutableAddress: CID): Promise<boolean> {
    return (await this.getHelia()).blockstore.has(immutableAddress)
  }

  async get(immutableAddress: CID){
    return (await this.getHelia()).blockstore.get(immutableAddress)
  }

  async pin(immutableAddress: CID){
    return (await this.getHelia()).pins.add(immutableAddress)
  }

  async unpin(immutableAddress: CID){
    return (await this.getHelia()).pins.rm(immutableAddress)
  }

  async isPinned(immutableAddress: CID){
    return ((await this.getHelia()).pins.isPinned(immutableAddress))
  }

  async addAsString(_object){
    return await this.addAs(strings, _object)
  }

  async getFromString(immutableAddress: CID){
    return await this.getFrom(strings, immutableAddress)
  }

  async addAsJson(_object){
    return await this.addAs(json, _object)
  }

  async getFromJson(immutableAddress: CID){
    return await this.getFrom(json, immutableAddress)
  }

  async addAsDAGJson(_object){
    return await this.addAs(dagJson, _object)
  }

  async getFromDAGJson(immutableAddress: CID){
    return await this.getFrom(dagJson, immutableAddress)
  }

  async addAsDAGCbor(_object){
    return await this.addAs(dagCbor, _object)
  }

  async getFromDAGCbor(immutableAddress: CID){
    return await this.getFrom(dagCbor, immutableAddress)
  }

  async getAsBytesAsync(cid: CID): Promise<Readable>{
    const fs = unixfs(await this.getHelia())

    return Stream.Readable.from(fs.cat(cid))
  }

  async addAsBytesAsync(bytes: ByteStream, options: Partial<AddOptions>|null = null): Promise<CID>{
    const fs = unixfs(await this.getHelia())
    const cid = await fs.addByteStream(bytes, options)
    return cid as CID
  }

  async remove(immutableAddress: CID){
    (await this.getHelia()).blockstore.delete(immutableAddress)
  }

  async stop(): Promise<void> {
    if (!!this.helia) {
      await this.helia.stop()
    }
  }

  private async addAs(instance, _object){
    const helia = instance(await this.getHelia())

    const immutableAddress = await helia.add(_object)
    return immutableAddress as CID
  }

  private async getFrom(instance, immutableAddress: CID){
    const helia = instance(await this.getHelia())

    return await helia.get(immutableAddress)
  }
}