import { expect } from "chai"
import { createRandomAES_256_key, randomUUID } from "src/cryptography/cryptography.js"
import { 
    AES256_EncryptionManager, 
    EncryptionManagerStore, 
    SHA256_HashManager, 
    SHA256_SignatureManager, 
    SignatureManagerStore, 
    createNewPrivateKeyFromPemInput, 
    createNewPublicKeyFromPemInput 
} from "../../src/cryptography/cryptography.js"
import { Mashfile, MashfileType, MashfileValidationStatus, Root, createTreeMetadata } from "../../src/entities/entities.js"
import { GraphEngine, MashfileEngine, MashfileTypeEngine } from "../../src/engines/engines.js"
import { privateKey, publicKey } from "../cryptography/cryptographytesthelpers.js"

describe("MashfileTypeEngine", () => {
    describe("validate", () => {
        it("should validate successfully - previously unencrypted with no signature", async() => {
            const mashfile = new Mashfile<string>()
            mashfile.payload = payload
            mashfile.hash = hash
            mashfile.id = id
            const result = await testTypeEngine.validate(mashfile)
            expect(result.length).to.equal(0)
        })

        it("should validate successfully - encrypted with no signature", async() => {
            const mashfile = new Mashfile<string>()
            mashfile.payload = encryptedPayload
            mashfile.hash = hash
            mashfile.id = id
            mashfile.encrypted = true
            const result = await testTypeEngine.validate(mashfile)
            expect(result.length).to.equal(0)
            const unencryptedPayload = await testTypeEngine.getUnencryptedPayload(mashfile)
            expect(unencryptedPayload).to.equal(payload)
        })

        it("should validate successfully - no encryption with no signature", async() => {
            const mashfile = new Mashfile<string>()
            mashfile.payload = payload2
            mashfile.hash = hash2
            mashfile.id = id2
            const result = await testTypeEngine.validate(mashfile)
            expect(result.length).to.equal(0)
        })

        it("should return hash error (encryption error) - encrypted with no signature", async() => {
            const mashfile = new Mashfile<string>()
            mashfile.payload = encryptedPayload
            mashfile.hash = "unknownhash"
            mashfile.id = id
            mashfile.encrypted = true
            const result = await testTypeEngine.validate(mashfile)
            expect(result.length).to.equal(1)
            expect(result[0]).to.equal(MashfileValidationStatus.encryptionFailed)
        })

        it("should return signature error - encrypted with signature", async() => {
            const mashfile = new Mashfile<string>()
            mashfile.payload = encryptedPayload
            mashfile.hash = hash
            mashfile.id = id
            mashfile.signature = "unknownsignature"
            mashfile.encrypted = true
            const result = await testTypeEngine.validate(mashfile)
            expect(result.length).to.equal(1)
            expect(result[0]).to.equal(MashfileValidationStatus.signatureInvalid)
        })

        it("should validate successfully - encrypted with signature", async() => {
            const mashfile = new Mashfile<string>()
            mashfile.payload = encryptedPayload
            mashfile.hash = hash
            mashfile.id = id
            mashfile.signature = signature
            mashfile.encrypted = true
            const result = await testTypeEngine.validate(mashfile)
            const unencryptedPayload = await testTypeEngine.getUnencryptedPayload(mashfile)
            expect(result.length).to.equal(0)
            expect(unencryptedPayload).to.equal(payload)
        })

        it("should validate successfully - unencrypted with signature", async() => {
            const mashfile = new Mashfile<string>()
            mashfile.payload = payload
            mashfile.hash = hash
            mashfile.id = id
            mashfile.signature = signature
            mashfile.encrypted = false
            const result = await testTypeEngine.validate(mashfile)
            expect(result.length).to.equal(0)
            expect(mashfile.payload).to.equal(payload)
        })
    })

    describe("secure", () => {
        it("should secure successfully", async () => {
            const mashfile = new Mashfile<string>()
            mashfile.payload = payload3
            mashfile.id = id3
            const result = await testTypeEngine.secure(mashfile)
            const unencryptedPayload = await testTypeEngine.getUnencryptedPayload(mashfile)
            expect(result.length).to.equal(0)
            expect(mashfile.hash).to.equal(hash3)
            expect(unencryptedPayload).to.equal(payload3)
            expect(mashfile.signature).to.equal(signature3)
        })
    })
})

class TestTypeEngine extends MashfileTypeEngine{

}


const hashManager = new SHA256_HashManager()
const payload = "hello world!"
const id = randomUUID()
const hash = hashManager.createHash(payload)
const payload2 = "goodbye cruel world!"
const id2 = randomUUID()
const hash2 = hashManager.createHash(payload2)
const payload3 = 'This is a test'
const hash3 = hashManager.createHash(payload3)
const id3 = randomUUID()
const key = createRandomAES_256_key()
const encryptionManager = new AES256_EncryptionManager(key)
const encryptedPayload = await encryptionManager.encryptText(payload)
const encryptionStore = new EncryptionManagerStore()
encryptionStore.add(id, {name: id, value: encryptionManager})
encryptionStore.add(id3, {name: id3, value: encryptionManager})
const privKey = createNewPrivateKeyFromPemInput(privateKey)
const pubKey = createNewPublicKeyFromPemInput(privateKey)
const signatureManager = new SHA256_SignatureManager(privKey, pubKey)
const signature = signatureManager.signPayload(payload)
const signature3 = signatureManager.signPayload(payload3)
const signatureStore = new SignatureManagerStore()
signatureStore.add(id, {name: id, value: signatureManager})
signatureStore.add(id3, {name: id3, value: signatureManager})

const testTypeEngine = new TestTypeEngine(encryptionStore, signatureStore, hashManager)
const mashfileEngine = new MashfileEngine(encryptionStore, signatureStore, hashManager)

describe("MashfileEngine", () => {
    describe("validate", () => {
        it("should validate a mashfile successfully", async() => {
            const m = new Mashfile()
            m.type = MashfileType.plain
            m.payload = payload
            m.id = id
            await mashfileEngine.hash(m)
            const result = await mashfileEngine.validate(m)

            expect(result.length).to.equal(0)
        })
    })

    describe("secure", () => {
        it("should secure a mashfile successfully", async() => {
            const m = new Mashfile()
            m.type = MashfileType.plain
            m.payload = payload
            m.id = id
            await mashfileEngine.hash(m)
            const result = await mashfileEngine.secure(m)

            expect(result.length).to.equal(0)
        })
    })

    describe("unsecure", () => {
        it("should unsecure a mashfile successfully", async() => {
            const m = new Mashfile()
            m.type = MashfileType.plain
            m.hash = hash
            m.id = id
            m.payload = encryptedPayload
            m.encrypted = true
            
            await mashfileEngine.unsecure(m)

            expect(m.payload).to.equal(payload)
        })
    })
})

const getGraphEngine = () => new GraphEngine(mashfileEngine)

describe("GraphEngine", () => {
    describe("mergeNode", () => {
        it("should add a node successfully", async() => {
            const m = new Mashfile()
            m.payload = payload
            m.type = MashfileType.plain
            m.id = id
            const graphEngine = getGraphEngine()
            await graphEngine.mergeNode(m)
            const mashfile = graphEngine.getNode(m.id)
            expect(mashfile).to.exist
            expect(mashfile.payload).to.equal(m.payload)
        })
        /*
        it("should refuse to secure an encrypted node without a hash", async() => {
            const m = new Mashfile()
            m.payload = encryptedPayload
            m.encrypted = true
            m.type = MashfileType.plain
            m.hash = null
            expect(async () => await graphEngine.addNode(m)).to.throw()
        })
        */
    })

    describe("removeNode", () => {
        it("should remove node successfully", async() => {
            const m = new Mashfile()
            m.payload = payload
            m.id = id
            m.type = MashfileType.plain
            const graphEngine = getGraphEngine()
            await graphEngine.mergeNode(m)
            await graphEngine.removeNode(m)
            const node = graphEngine.getNode(m.id)
            expect(node).to.not.exist
        })
    })

    describe("connectNodes", () => {
        it("should connect 2 nodes successfully", async() => {
            const m = new Mashfile()
            m.payload = payload
            m.id = id
            m.type = MashfileType.root
            const graphEngine = getGraphEngine()
            await graphEngine.mergeNode(m)
            const m2 = new Mashfile()
            m2.payload = payload2
            m2.type = MashfileType.plain
            await graphEngine.connectNodes(m, m2)
            const mashfile = graphEngine.getNode(m2.id)
            expect(mashfile).to.exist
            expect(mashfile.payload).to.equal(m2.payload)
        })
    })

    describe("validate", () => {
        it("should validate successfully", async() => {
            const m = new Mashfile()
            m.payload = payload
            m.id = id
            m.type = MashfileType.root
            const graphEngine = getGraphEngine()
            await graphEngine.mergeNode(m)
            const m2 = new Mashfile()
            m2.payload = payload2
            m2.type = MashfileType.plain
            await graphEngine.connectNodes(m, m2)
            const m3 = new Mashfile()
            m3.payload = payload3
            m3.type = MashfileType.file
            await graphEngine.connectNodes(m, m3)
            const result = await graphEngine.validate()
            expect(result.length).to.equal(0)
        })

        it("should return error on invalid encryption chain", async() => {
            const m = new Mashfile()
            m.hash = hash
            m.id = id
            m.payload = encryptedPayload
            m.encrypted = true
            m.type = MashfileType.root
            const graphEngine = getGraphEngine()
            await graphEngine.mergeNode(m)
            const m2 = new Mashfile()
            m2.payload = payload2
            m2.id = id2
            m2.type = MashfileType.plain
            await graphEngine.connectNodes(m, m2)
            const m3 = new Mashfile()
            m3.payload = payload3
            m3.id = id3
            m3.type = MashfileType.file
            await graphEngine.connectNodes(m, m3)
            const m4 = new Mashfile()
            m4.payload = "other"
            m4.id = m4.payload.toString()
            m4.type = MashfileType.root
            await graphEngine.connectNodes(m, m4)
            const m5 = new Mashfile()
            m5.payload = "other2"
            m5.id = m5.payload.toString()
            m5.type = MashfileType.file
            await graphEngine.connectNodes(m4, m5)
            const result = await graphEngine.validate()
            expect(result.length).to.equal(4)
            result.forEach(element => {
                expect(element.error).to.equal(MashfileValidationStatus.encryptionChainInvalid)
            }); 
        })
    })

    describe("secure", () => {
        it("should secure mashfiles successfully", async() => {
            const m = new Mashfile()
            m.payload = payload
            m.id = id
            m.type = MashfileType.root
            const graphEngine = getGraphEngine()
            await graphEngine.mergeNode(m)
            const m2 = new Mashfile()
            m2.payload = payload2
            m2.id = id2
            m2.type = MashfileType.plain
            await graphEngine.connectNodes(m, m2)
            const m3 = new Mashfile()
            m3.payload = payload3
            m3.id = id3
            m3.type = MashfileType.file
            await graphEngine.connectNodes(m, m3)
            await graphEngine.validate()
            var result = await graphEngine.secure()
            expect(result.length).to.equal(0)
            expect(m.payload).to.not.equal(payload)
        })
    })

    describe("unsecure", () => {
        it("should unsecure mashfile successfully", async() => {
            const m = new Mashfile()
            m.payload = payload
            m.id = id
            m.type = MashfileType.root
            const graphEngine = getGraphEngine()
            await graphEngine.mergeNode(m)
            const m2 = new Mashfile()
            m2.payload = payload2
            m2.id = id2
            m2.type = MashfileType.plain
            await graphEngine.connectNodes(m, m2)
            const m3 = new Mashfile()
            m3.id = id3
            m3.payload = payload3
            m3.type = MashfileType.file
            await graphEngine.connectNodes(m, m3)
            await graphEngine.validate()
            await graphEngine.secure()
            await graphEngine.unsecure()
            const result = graphEngine.getNode(m.id)
            expect(result.payload).to.equal(payload)
        })
    })
})