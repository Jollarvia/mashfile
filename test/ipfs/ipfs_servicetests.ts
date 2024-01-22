import { expect } from "chai"
import { IpfsService } from "src/ipfs/ipfs_service.js"
import type { ByteStream } from 'ipfs-unixfs-importer'
import { streamFromString, streamToString } from "src/ipfs/ipfs_helpers.js"
describe("IpfsService", () => {
    describe("getHelia|stop", function() {
        this.timeout(15000)
        it("should return helia instance", async() => {
            const service = new IpfsService(null)
            const helia = await service.getHelia()
            expect(helia).to.exist
            await helia.stop()
        })
    })

    describe("addAsJson|getAsJson|remove|has", function() {
        this.timeout(15000)
        it("should add object successfully", async() => {
            const service = new IpfsService(null)
            const obj = {a:1, b:2}
            const cid = await service.addAsJson(obj)
            const read = await service.getFromJson(cid)
            expect(read["a"]).to.equal(1)
            const exists = await service.has(cid)
            expect(exists).to.equal(true)
            await service.remove(cid)
            expect(await service.has(cid)).to.equal(false)
            await service.stop()
        })
    })

    describe("addAsString|getAsString", function() {
        this.timeout(15000)
        it("should add object successfully", async() => {
            const service = new IpfsService(null)
            const obj = "x"
            const cid = await service.addAsString(obj)
            const read = await service.getFromString(cid)
            expect(read).to.equal("x")
            await service.remove(cid)
            await service.stop()
        })
    })

    describe("addAsDAGJson|getAsDAGJson", function() {
        this.timeout(15000)
        it("should add object successfully", async() => {
            const service = new IpfsService(null)
            const obj = {a:1, b:2}
            const cid = await service.addAsDAGJson(obj)
            const read = await service.getFromDAGJson(cid)
            expect(read["a"]).to.equal(1)
            await service.remove(cid)
            await service.stop()
        })
    })

    describe("addAsDAGCbor|getAsDAGCbor", function() {
        this.timeout(15000)
        it("should add object successfully", async() => {
            const service = new IpfsService(null)
            const obj = {a:1, b:2}
            const cid = await service.addAsDAGCbor(obj)
            const read = await service.getFromDAGCbor(cid)
            expect(read["a"]).to.equal(1)
            await service.remove(cid)
            await service.stop()
        })
    })

    describe("addAsBytesAsync|getAsBytesAsync", function() {
        this.timeout(15000)
        it("should add object successfully", async() => {
            const service = new IpfsService(null)
            const obj = {a:1, b:2}
            const json = JSON.stringify(obj)
            const bytes = new TextEncoder().encode(json)
            const s = streamFromString(bytes)
            const cid = await service.addAsBytesAsync(s)
            const read = await service.getAsBytesAsync(cid)
            const resultString = await streamToString(read)
            const result = JSON.parse(resultString)
            expect(result["a"]).to.equal(1)
            await service.remove(cid)
            await service.stop()
        })
    })

    describe("pin|unpin|isPinned", function() {
        this.timeout(15000)
        it("should pin successfully", async() => {
            const service = new IpfsService(null)
            const obj = {x:1, y:2}
            const cid = await service.addAsJson(obj)
            await service.pin(cid);
            expect(await service.isPinned(cid)).to.equal(true)
            await service.unpin(cid)
            expect(await service.isPinned(cid)).to.equal(false)
            await service.remove(cid)
            await service.stop()
        })
    })
})