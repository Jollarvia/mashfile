import { stringToCid, getCIDOfData, codecs, bases, cidToString, getSha256Hash, getCIDV0OfBytes, getCIDV1OfBytes, CID } from '../../src/ipfs/ipfs_helpers.js'
import { expect } from "chai"
describe("IpfsHelper", () => {
    describe("getCIDOfData", () => {
        it("should return a CID", async() => {
            const bytes = codecs.json.encode({ hello: 'world' })
            const cid = await getCIDOfData(bytes, codecs.json)
            expect(cid.toString()).to.equal('bagaaierar5hqacsnb4smsl7ddqgncyypqv4z3b3qpimvleayrk6vpdzlj6ja')
        })
    })

    describe("stringToCid", () => {
        it("should return a CID", async() => {
            const bytes = codecs.json.encode({ hello: 'world' })
            const cid = await getCIDOfData(bytes, codecs.json)
            const base64Cid = cid.toString(bases.base64)
            const builtCid = stringToCid(base64Cid, bases.base64)
            expect(builtCid.toString()).to.equal(cid.toString())
        })
    })

    describe("cidToString", () => {
        it("should create string from cid successfully", async() => {
            const bytes = codecs.json.encode({ hello: 'world' })
            const cid = await getCIDOfData(bytes, codecs.json)
            const base64Cid = cid.toString(bases.base64)
            const cidAsString = cidToString(cid, bases.base64)
        })
    })

    describe("getSha256Hash", () => {
        it("should create hash successfully", async() => {
            const string = "{ hello: 'world' }"
            const bytes = codecs.json.encode(string)
            const hash = await getSha256Hash(bytes)
            expect(hash).to.exist
        })
    })

    describe("getCIDV0OfBytes", async() => {
        const string = "{ hello: 'world' }"
        const bytes = codecs.json.encode(string)
        const cid = await getCIDV0OfBytes(bytes)
        expect(cid).to.exist
    })

    describe("getCIDV1OfBytes", async() => {
        const string = "{ hello: 'world' }"
        const bytes = codecs.json.encode(string)
        const cid = await getCIDV1OfBytes(bytes)
        expect(cid).to.exist
    })
})