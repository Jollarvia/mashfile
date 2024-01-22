import { expect } from "chai"
import { HeliaInit } from "helia"
import { AES256_EncryptionManager, SHA256_SignatureManager, createNewPrivateKeyFromPemInput, createNewPublicKeyFromPemInput, randomUUID } from "src/cryptography/cryptography.js"
import { File, Root, StandardEncryptionManagerType, StandardSignatureManagerType, createTreeMetadata } from "src/entities/entities.js"
import { IMashfile, MashfilerOptions } from "src/interfaces/interfaces.js"
import { bases, cidToString, streamToString, stringToCid } from "src/ipfs/ipfs_helpers.js"
import { Mashfiler } from "src/mashfiler/mashfiler.js"
import { privateKey } from "test/cryptography/cryptographytesthelpers.js"
import { createReadStream } from "node:fs"

describe("mashfiler", () => {

    describe("constructor", () => {
        it ("should construct with limited options", () => {
            const options = {}
            const mashfiler = new Mashfiler(options)
            expect(mashfiler).to.exist
            expect(mashfiler._hashManager).to.exist
            expect(mashfiler.encryptionStore).to.exist
            expect(mashfiler.signatureStore).to.exist
            expect(mashfiler._ipfsService).to.exist
        })

        it ("should construct with ipfs options", () => {
            const init = {} as HeliaInit
            const options = {
                ipfsOptions: {heliaInit: init}
            }
            const mashfiler = new Mashfiler(options)
            expect(mashfiler).to.exist
            expect(mashfiler._hashManager).to.exist
            expect(mashfiler.encryptionStore).to.exist
            expect(mashfiler.signatureStore).to.exist
            expect(mashfiler._ipfsService).to.exist
        })

        it ("should construct with encryption options", () => {
            const options = {} as MashfilerOptions
            options.encryptionOptions = {
                encryptionManagers: [
                    {
                        name: "enc1",
                        type: StandardEncryptionManagerType.AES256_EncryptionManager,
                        key: "secretAES256KeyPaddedTo32BitsLen"
                    },
                    function(){
                        const buffer = Buffer.from("secretAES256KeyPaddedTo32BitsLen")
                        return {name: "enc2", value: new AES256_EncryptionManager(buffer)}
                    }
                ]
            }
            const mashfiler = new Mashfiler(options)
            expect(mashfiler).to.exist
            expect(mashfiler._hashManager).to.exist
            expect(mashfiler.encryptionStore).to.exist
            expect(mashfiler.signatureStore).to.exist
            expect(mashfiler._ipfsService).to.exist
            expect(mashfiler.encryptionStore.get("enc1")).to.exist
            expect(mashfiler.encryptionStore.get("enc2")).to.exist
        })

        it ("should construct with signature options", () => {
            const options = {} as MashfilerOptions
            options.signatureOptions = {
                signatureManagers: [
                    {
                        type: StandardSignatureManagerType.SHA256_SignatureManager,
                        name: "sig1",
                        privateKey: privateKey
                    },
                    function(){
                        const privateKeyObject = createNewPrivateKeyFromPemInput(privateKey)
                        const publicKeyObject = createNewPublicKeyFromPemInput(privateKey)
                        return {name: "sig2", value: new SHA256_SignatureManager(privateKeyObject, publicKeyObject)}
                    },
                    function(){
                        const privateKeyObject = createNewPrivateKeyFromPemInput(privateKey)
                        return {name: "sig3", value: new SHA256_SignatureManager(privateKeyObject, null)}
                    }
                ]
            }
            const mashfiler = new Mashfiler(options)
            expect(mashfiler).to.exist
            expect(mashfiler._hashManager).to.exist
            expect(mashfiler.encryptionStore).to.exist
            expect(mashfiler.signatureStore).to.exist
            expect(mashfiler._ipfsService).to.exist
            expect(mashfiler.signatureStore.get("sig1")).to.exist
            expect(mashfiler.signatureStore.get("sig2")).to.exist
            expect(mashfiler.signatureStore.get("sig3")).to.exist
        })
    })

    describe("persistGraph", function() {
        this.timeout(15000)
        const fileTest = "should persist single file mashfile successfully"
        it(fileTest, async() => {
            const options = {}
            const mashfiler = new Mashfiler(options)
            const graph = mashfiler.createGraphEngine()
            const mashfile1 = new File()
            mashfile1.detail.description = "this is a test"
            mashfile1.detail.information = fileTest
            mashfile1.id = randomUUID()
            await graph.mergeNode(mashfile1)
            const result = await mashfiler.persistGraph(graph)
            expect(result.idToCID.has(mashfile1.id))
            const mashfile1CidString = result.idToCID.get(mashfile1.id)
            const cid1 = stringToCid(mashfile1CidString, bases.base64)
            const isInIpfs = await mashfiler._ipfsService.has(cid1)
            expect(isInIpfs).to.equal(true)
            await mashfiler.stop()
        })

        const rootTest = "should persist single root mashfile successfully"
        it(rootTest, async() => {
            const options = {}
            const mashfiler = new Mashfiler(options)
            const graph = mashfiler.createGraphEngine()
            const mashfile1 = new Root()
            mashfile1.detail.description = "this is a test"
            mashfile1.detail.information = rootTest
            mashfile1.id = randomUUID()
            await graph.mergeNode(mashfile1)
            const result = await mashfiler.persistGraph(graph)
            expect(result.idToCID.has(mashfile1.id))
            const mashfile1CidString = result.idToCID.get(mashfile1.id)
            const cid1 = stringToCid(mashfile1CidString, bases.base64)
            const isInIpfs = await mashfiler._ipfsService.has(cid1)
            expect(isInIpfs).to.equal(true)
            await mashfiler.stop()
        })

        const rootChildTest = "should persist single root mashfile with existing child CID successfully"
        it(rootChildTest, async() => {
            const options = {}
            const mashfiler = new Mashfiler(options)
            const graph = mashfiler.createGraphEngine()
            const mashfile1 = new Root()
            mashfile1.detail.description = "this is a test"
            mashfile1.detail.information = rootChildTest
            mashfile1.id = randomUUID()
            mashfile1.payload = createTreeMetadata()
            const testCidString = "mAXESIHz4+xiqTFb2nAu0iOIsIWCMBUH/s/10dpO9H5D2ArKF"
            const testCid = stringToCid(testCidString, bases.base64)
            mashfile1.payload.children.push(testCid)
            await graph.mergeNode(mashfile1)
            const result = await mashfiler.persistGraph(graph)
            expect(result.idToCID.has(mashfile1.id))
            const mashfile1CidString = result.idToCID.get(mashfile1.id)
            const cid1 = stringToCid(mashfile1CidString, bases.base64)
            const isInIpfs = await mashfiler._ipfsService.has(cid1)
            expect(isInIpfs).to.equal(true)
            const ipfsMashfile = await mashfiler._ipfsService.getFromDAGCbor(cid1) as IMashfile
            expect(cidToString(ipfsMashfile.payload.children[0], bases.base64)).to.equal(testCidString)
            await mashfiler.stop()
        })

        const multiTest = "should persist multiple mashfiles of different types successfully"
        it(multiTest, async() => {
            const options = {}
            const mashfiler = new Mashfiler(options)
            const graph = mashfiler.createGraphEngine()

            const mashfile1 = new Root()
            mashfile1.detail.description = "mashfile1"
            mashfile1.detail.information = multiTest
            mashfile1.id = randomUUID()

            const mashfile2 = new Root()
            mashfile2.detail.description = "mashfile2"
            mashfile2.detail.information = multiTest
            mashfile2.id = randomUUID()

            const mashfile3 = new File()
            mashfile3.detail.description = "mashfile3"
            mashfile3.detail.information = multiTest
            mashfile3.id = randomUUID()

            const mashfile4 = new File()
            mashfile4.detail.description = "mashfile4"
            mashfile4.detail.information = multiTest
            mashfile4.id = randomUUID()

            const mashfile5 = new File()
            mashfile5.detail.description = "mashfile5"
            mashfile5.detail.information = multiTest
            mashfile5.id = randomUUID()

            await graph.mergeNode(mashfile1)
            await graph.connectNodes(mashfile1, mashfile2)
            await graph.connectNodes(mashfile1, mashfile3)
            await graph.connectNodes(mashfile2, mashfile4)
            await graph.connectNodes(mashfile2, mashfile5)
            const result = await mashfiler.persistGraph(graph)
            expect(result.idToCID.has(mashfile1.id))
            expect(result.idToCID.has(mashfile2.id))
            expect(result.idToCID.has(mashfile3.id))
            expect(result.idToCID.has(mashfile4.id))
            expect(result.idToCID.has(mashfile5.id))
            const assertInIpfs = async(result, mashfile) => {
                const mashfileCidString = result.idToCID.get(mashfile.id)
                const cid1 = stringToCid(mashfileCidString, bases.base64)
                const isInIpfs = await mashfiler._ipfsService.has(cid1)
                expect(isInIpfs).to.equal(true)
            }
            
            await assertInIpfs(result, mashfile1)
            await assertInIpfs(result, mashfile2)
            await assertInIpfs(result, mashfile3)
            await assertInIpfs(result, mashfile4)
            await assertInIpfs(result, mashfile5)

            const getMashfileFromIpfs = async(mashfile: IMashfile) => {
                const mashfile1CidString = result.idToCID.get(mashfile.id)
                const cid1 = stringToCid(mashfile1CidString, bases.base64)
                const ipfsMashfile = await mashfiler._ipfsService.getFromDAGCbor(cid1) as IMashfile
                return ipfsMashfile
            }
            
            const mashfile1Ipfs = await getMashfileFromIpfs(mashfile1) as Root
            const mashfile2Ipfs = await getMashfileFromIpfs(mashfile2) as Root
            const mashfile3Ipfs = await getMashfileFromIpfs(mashfile3) as File
            const mashfile4Ipfs = await getMashfileFromIpfs(mashfile4) as File
            const mashfile5Ipfs = await getMashfileFromIpfs(mashfile5) as File

            const getCIDFromCIDMap = (mashfile) => {
                const mashfile1CidString = result.idToCID.get(mashfile.id)
                const cid = stringToCid(mashfile1CidString, bases.base64)
                return cid
            }

            const cid1 = getCIDFromCIDMap(mashfile1)
            const cid2 = getCIDFromCIDMap(mashfile2)
            const cid3 = getCIDFromCIDMap(mashfile3)
            const cid4 = getCIDFromCIDMap(mashfile4)
            const cid5 = getCIDFromCIDMap(mashfile5)

            expect(cid1).to.exist
            expect(cid2).to.exist
            expect(cid3).to.exist
            expect(cid4).to.exist
            expect(cid5).to.exist
            
            const compareMashfileChildren = (m1: Root, m2: Root) => {
                const m1Children = m1.payload.children.map(cidToString)
                const m2Children = m2.payload.children.map(cidToString)

                expect(m1Children).to.include.members(m2Children)
            }

            compareMashfileChildren(mashfile1, mashfile1Ipfs)
            compareMashfileChildren(mashfile2, mashfile2Ipfs)

            await mashfiler.stop()
        })

        const encryptAfterTest = "should persist single root mashfile with encryption added after construction"
        it(encryptAfterTest, async() => {
            const options = {}
            const mashfiler = new Mashfiler(options)
            const graph = mashfiler.createGraphEngine()
            const mashfile1 = new Root()
            mashfile1.detail.description = "this is a test"
            mashfile1.detail.information = rootTest
            mashfile1.id = randomUUID()
            await graph.mergeNode(mashfile1)
            const attributes = graph.getAttributes(mashfile1)
            attributes.encrypt = {
                name: "enc1",
                type: StandardEncryptionManagerType.AES256_EncryptionManager,
                key: "secretAES256KeyPaddedTo32BitsLen"
            }
            const result = await mashfiler.persistGraph(graph)
            expect(result.idToCID.has(mashfile1.id))
            const mashfile1CidString = result.idToCID.get(mashfile1.id)
            const cid1 = stringToCid(mashfile1CidString, bases.base64)
            const isInIpfs = await mashfiler._ipfsService.has(cid1)
            expect(isInIpfs).to.equal(true)
            expect(mashfiler.encryptionStore.get(attributes.encrypt.name)).to.exist
            const mashfileFromIpfs = await mashfiler._ipfsService.getFromDAGCbor(cid1) as IMashfile
            expect(mashfileFromIpfs.encrypted).to.be.true
            await mashfiler.stop()
        })
    })

    describe("restoreSignaturesFromRepository", () => {
        it("should restore signatures from repository", async () => {
            const options = {repository: "memory"}
            const mashfiler = new Mashfiler(options)
            await mashfiler.repository.signature.put(
                "sig1",
                {
                    type: StandardSignatureManagerType.SHA256_SignatureManager,
                    name: "sig1",
                    privateKey: privateKey
                }
            )
            
            await mashfiler.restoreKeysFromRepository()
            const result = mashfiler.signatureStore.get("sig1")
            expect(result).to.exist
            await mashfiler.stop()
        })
    })

    describe("restoreKeysFromRepository", () => {
        it("should restore keys from repository", async () => {
            const options = {repository: "memory"}
            const mashfiler = new Mashfiler(options)
            await mashfiler.repository.key.put(
                "enc1",
                {
                name: "enc1",
                type: StandardEncryptionManagerType.AES256_EncryptionManager,
                key: "secretAES256KeyPaddedTo32BitsLen"
                }
            )

            await mashfiler.restoreKeysFromRepository()
            const result = mashfiler.encryptionStore.get("enc1")
            expect(result).to.exist
            const clearText = "hello world!"
            const manager = result.value as AES256_EncryptionManager
            let encrypted
            expect(() => encrypted = manager.encryptText(clearText)).to.not.Throw
            expect(encrypted).to.not.equal(clearText)
            await mashfiler.stop()
        })
    })

    describe("getFileStreamFromMashfile", function() {
        this.timeout(15000)
        it("should download file successfully, after uploading to IPFS, from mashfile", async function(){
            const options = {}
            const mashfiler = new Mashfiler(options)
            const graph = mashfiler.createGraphEngine()
            const mashfile1 = new File()
            const resourcePath = "test/resources/unicorns.txt"
            const resource = createReadStream(resourcePath)
            const cid = await mashfiler._ipfsService.addAsBytesAsync(resource)
            mashfile1.detail.description = "this is a test"
            mashfile1.id = randomUUID()
            mashfile1.payload.cid = cid
            await graph.mergeNode(mashfile1)
            const persistResult = await mashfiler.persistGraph(graph)
            const result = await mashfiler.getFileStreamFromMashfile(mashfile1)
            const resultString = await streamToString(result)
            expect(resultString).to.exist
            await mashfiler.stop()
        })
    })
})