import { convertPayloadToString, convertPayloadFromString, convertPayloadFromStringAsType} from 'src/serialization/serialization.js'
import { Mashfile, Root, TreeMetadata, TreeType, File, FileMetadata } from 'src/entities/entities.js'
import { expect } from 'chai'
import { IMashfile } from 'src/interfaces/interfaces.js'

const stringPayload = "This is a test"
const objectPayload = {a: "b", c: "d"}
const numberPayload = 789

describe("serialization", () => {
    describe("convertPayloadToString", () => {
        it("should convert string payload successfully", () => {
            const mashfile = new Mashfile<string>()
            const payload = stringPayload
            mashfile.payload = payload
            const result = convertPayloadToString(mashfile)
            expect(result).to.equal(payload)
        })

        it("should convert number payload successfully", () => {
            const mashfile = new Mashfile<number>()
            const payload = numberPayload
            mashfile.payload = payload
            const result = convertPayloadToString(mashfile)
            expect(result).to.equal(payload.toString())
        })

        it("should convert object payload successfully", () => {
            const mashfile = new Mashfile<{}>()
            const payload = objectPayload
            mashfile.payload = payload
            const result = convertPayloadToString(mashfile)
            const obj = JSON.parse(result)
            expect(obj.a).to.equal("b")
            expect(obj.c).to.equal("d")
        })  
    })

    describe("convertPayloadFromString", () => {
        it("should convert to number successfully", () => {
            const mashfile = new Mashfile()
            const payload = numberPayload.toString()
            mashfile.payload = payload
            const result = convertPayloadFromString(mashfile)
            expect(result).to.be.equal(numberPayload)
        })

        it("should convert to Root successfully", () => {
            const mashfile = new Root()
            mashfile.payload.treeType = TreeType.unknown
            const result = convertPayloadFromString(mashfile)
            expect(result["treeType"]).to.be.equal(TreeType.unknown)
        })

        it("should convert to File successfully", () => {
            const mashfile = new File()
            mashfile.payload.author = "xxx"
            const result = convertPayloadFromString(mashfile)
            expect(result["author"]).to.be.equal("xxx")
        })
    })

    describe("convertPayloadFromStringAsType", () => {
        it("should convert to new type successfully", () => {
            const mashfile = new File()
            mashfile.payload.author = "xxx"
            const mashfileAsIMashfile = mashfile as IMashfile
            mashfileAsIMashfile.payload = convertPayloadToString(mashfile)
            const result = convertPayloadFromStringAsType<FileMetadata>(mashfileAsIMashfile, () => new FileMetadata())
            expect(result.author).to.be.equal("xxx")
        })
    })
})