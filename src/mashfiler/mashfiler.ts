import { EncryptionManagerStore, SHA256_HashManager, SignatureManagerStore } from "src/cryptography/cryptography.js"
import { MashfileType, Root, createTreeMetadata, 
    resolveStandardEncryptionManagerFromOption, resolveStandardSignatureManagerFromOption } from "src/entities/entities.js"
import { GraphEngine, MashfileEngine } from "src/engines/engines.js"
import { StandardEncryptionManagerOptions, StandardSignatureManagerOptions, EncryptionOptions, 
    IEncryptionManager, ISignatureManager, IpfsOptions, MashfilerOptions, OptionFactoryResolver, 
    SignatureOptions, StandardOptions, IHashManager, IMashfile, PersistGraphResult, IRepository, IFileMetadata } from "src/interfaces/interfaces.js"
import { CID, bases, cidToString, stringToCid } from "src/ipfs/ipfs_helpers.js"
import { ByteStream, IpfsService } from "src/ipfs/ipfs_service.js"
import { topologicalSort } from 'graphology-dag'
import { RepositoryResolver } from "src/repositories/common/repository_helpers.js"


export class Mashfiler{
    public repository: IRepository
    public encryptionStore: EncryptionManagerStore
    public signatureStore: SignatureManagerStore
    public _ipfsService: IpfsService
    public _hashManager: IHashManager
    public _mashfileEngine: MashfileEngine

    constructor(mashfilerOptions: MashfilerOptions){
        this._hashManager = new SHA256_HashManager()
        this.encryptionStore = new EncryptionManagerStore()
        this.signatureStore = new SignatureManagerStore()
        this._mashfileEngine = new MashfileEngine(this.encryptionStore, this.signatureStore, this._hashManager)
        this.resolveEncryptionOptions(mashfilerOptions.encryptionOptions)
        this.resolveSignatureOption(mashfilerOptions.signatureOptions)
        this.resolveIpfs(mashfilerOptions.ipfsOptions)
        const repositoryResolver = new RepositoryResolver()
        this.repository = repositoryResolver.resolveWithFactory(mashfilerOptions.repository)
    }

    async addFromStream(bytes: ByteStream){
        return await this._ipfsService.addAsBytesAsync(bytes)
    }

    async getFileStream(cid: CID){
        return await this._ipfsService.getAsBytesAsync(cid)
    }

    async getFileStreamFromMashfile(mashfile: IMashfile){
        if (mashfile.type != MashfileType.file){
            throw "mashfile.type must be " + MashfileType.file
        }
        await this._mashfileEngine.unsecure(mashfile)
        const payload = mashfile.payload as IFileMetadata
        if (!payload.cid){
            throw "no cid in payload"
        }
        return await this._ipfsService.getAsBytesAsync(payload.cid)
    }

    createGraphEngine(exportedGraph?: string){
        const graphEngine = new GraphEngine(this._mashfileEngine)
        if (!!exportedGraph){
            graphEngine.ingestFromString(exportedGraph)
        }
        return graphEngine
    }

    async stop(){
        this._ipfsService && await this._ipfsService.stop()
    }

    async persistGraph(graphEngine: GraphEngine): Promise<PersistGraphResult>{
        const sortedGraphKeys = topologicalSort(graphEngine.graph)
        const rootMap = new Map<string, Set<string>>()
        const cidMap = new Map<string, string>()
        const mashfileMap = new Map<string, IMashfile>()
        const encryptedIds = new Map<string, string>()
        const signatureIds = new Map<string, string>()
        const nonRoots = new Map<string, IMashfile>()
        const persist = async(key: string, mashfile: IMashfile) => {
            const cid = await this._ipfsService.addAsDAGCbor(mashfile)
            cidMap.set(key, cidToString(cid, bases.base64))
        }

        const getMashfile = (id) => {
            if (mashfileMap.has(id)){
                return mashfileMap.get(id)
            }
            const mashfile = graphEngine.getNode(id)
            const attributes = graphEngine.getAttributes(mashfile)
            if (!!attributes.encrypt){
                const encryptName = this.resolveEncryption(attributes.encrypt)
                if (encryptName != mashfile.id){
                    this.encryptionStore.add(mashfile.id, this.encryptionStore.get(encryptName))
                }
            }
            if (!!attributes.sign){
                const signName = this.resolveSignature(attributes.sign)
                if (signName != mashfile.id){
                    this.signatureStore.add(mashfile.id, this.signatureStore.get(signName))
                }
            }
            mashfileMap.set(id, mashfile)
            return mashfile
        }

        const assureRootMapKey = (id) => {
            if (!rootMap.has(id)){
                rootMap.set(id, new Set())
            }
        }
        const addToRootMap = (id, child) => {
            assureRootMapKey(id)
            const set = rootMap.get(id)
            set.add(child)
        }

        for (let key of sortedGraphKeys) {
            const mashfile = getMashfile(key)
            const attributes = graphEngine.getAttributes(mashfile)
            
            if (!!attributes.encrypt){
                const encrypted = this.resolveEncryption(attributes.encrypt)
                encryptedIds.set(key, encrypted)
            }

            if (!!attributes.sign){
                const signed = this.resolveSignature(attributes.sign)
                signatureIds.set(key, signed)
            }

            switch(mashfile.type){
                case MashfileType.root:
                    assureRootMapKey(key)

                    graphEngine.graph.forEachOutboundNeighbor(key, (neighbor) => {
                        addToRootMap(key, neighbor)
                    })
                    break
                default:
                    nonRoots.set(key, mashfile)
            }
        }

        await graphEngine.secure()

        for (let keyPair of nonRoots){
            await persist(keyPair[0], keyPair[1])
        }

        const unpersistedRoots = new Set<string>()
        for (let [rootId, children] of rootMap){
            const mashfile = getMashfile(rootId)
            const root = mashfile as Root
            if (!root.payload){
                root.payload = createTreeMetadata()
            }
            if (!cidMap.has(rootId)){
                unpersistedRoots.add(rootId)
            }
            for (const childId of children) {
                if (!cidMap.has(childId)){
                    unpersistedRoots.add(childId)
                }
            }
        }

        const tryPersistRoot = async(rootId: string) => {
            const neighbors = rootMap.get(rootId)
            const mashfile = getMashfile(rootId)
            const root = mashfile as Root
            let result = true
            for (let neighbor of neighbors){
                if (!cidMap.has(neighbor)){
                    result = false
                }
            }
            if (result){
                const children = rootMap.get(rootId)
                for (let childId of children){
                    root.payload.children.push(stringToCid(cidMap.get(childId), bases.base64))
                }
                await persist(rootId, mashfile)
                return true
            }
            return false
        }

        while(unpersistedRoots.size > 0){
            for (let rootId of unpersistedRoots){
                const success = await tryPersistRoot(rootId)
                if (success){
                    unpersistedRoots.delete(rootId)
                }
            }
        }

        return {rootIdsToChildren: rootMap, idToCID: cidMap, idToEncryption: encryptedIds, idToSignature: signatureIds}
    }

    async restoreKeysFromRepository(){
        const table = this.repository.key
        for (const key of table.keys()) {
            if (!this.encryptionStore.has(key)){
                const options = await table.get(key)
                this.resolveStandardEncryptionManagerOptions(options)
            }
        }
    }

    async restoreSignaturesFromRepository(){
        const table = this.repository.signature
        for (const key of table.keys()) {
            if (!this.signatureStore.has(key)){
                const options = await table.get(key)
                this.resolveStandardEncryptionManagerOptions(options)
            }
        }
    }

    protected resolveEncryption(option: StandardEncryptionManagerOptions|OptionFactoryResolver<IEncryptionManager>){
        if (typeof(option) == "function"){
            return this.resolveEncryptionManagerFactoryOptions(option)
        }
        else {
            return this.resolveStandardEncryptionManagerOptions(option)
        }
    }

    protected resolveEncryptionOptions(encryptionOptions?: EncryptionOptions){
        if(!encryptionOptions){
            return
        }
        if (!!encryptionOptions.encryptionManagers){
            encryptionOptions.encryptionManagers.forEach(element => {
                this.resolveEncryption(element)
            });
        }

    }

    protected resolveSignature(option: StandardSignatureManagerOptions|OptionFactoryResolver<ISignatureManager>){
        if (typeof(option) == "function"){
            return this.resolveSignatureManagerFactoryOptions(option)
        }
        else {
            return this.resolveStandardSignatureManagerOptions(option)
        }
    }

    protected resolveSignatureOption(signatureOptions?: SignatureOptions){
        if(!signatureOptions){
            return
        }
        if (!!signatureOptions.signatureManagers){
            signatureOptions.signatureManagers.forEach(element => {
                this.resolveSignature(element)
            });
        }
    }

    protected resolveIpfs(ipfsOptions?: IpfsOptions){
        if(!ipfsOptions){
            this._ipfsService = new IpfsService(null)
            return
        }
        if (!!ipfsOptions.heliaInit){
            this._ipfsService = new IpfsService(ipfsOptions.heliaInit)
            return
        }
        this._ipfsService = new IpfsService(null)
    }

    private resolveStandardEncryptionManagerOptions(option: StandardEncryptionManagerOptions){
        this.throwIfEmpty(option, "StandardEncryptionManagerOptions")
        this.validateName(option)
        if (!this.encryptionStore.has(option.name)){
            const encryptionManager = resolveStandardEncryptionManagerFromOption(option.type, option)
            this.encryptionStore.add(option.name, {name: option.name, value: encryptionManager})
        }
        return option.name
    }

    private resolveEncryptionManagerFactoryOptions(option: OptionFactoryResolver<IEncryptionManager>){
        this.throwIfEmpty(option, "OptionFactoryResolver<IEncryptionManager>")
        const managerResult = option()
        if (!this.encryptionStore.has(managerResult.name)){
            this.encryptionStore.add(managerResult.name, {name: managerResult.name, value: managerResult.value})
        }
        return managerResult.name
    }

    private resolveStandardSignatureManagerOptions(option: StandardSignatureManagerOptions){
        this.throwIfEmpty(option, "StandardSignatureManagerOptions")
        this.validateName(option)
        if (!this.signatureStore.has(option.name)){
            const signatureManager = resolveStandardSignatureManagerFromOption(option.type, option)
            this.signatureStore.add(option.name, signatureManager)
        }
        return option.name
    }

    private resolveSignatureManagerFactoryOptions(option: OptionFactoryResolver<ISignatureManager>){
        this.throwIfEmpty(option, "OptionFactoryResolver<ISignatureManager>")
        const managerResult = option()
        if (!this.signatureStore.has(managerResult.name)){
            this.signatureStore.add(managerResult.name, {name: managerResult.name, value: managerResult.value})
        }
        return managerResult.name
    }

    private throwIfEmpty(value, name=null){
        if (!value){
            throw ("Value must not be empty: " + name || value)
        }
    }

    private validateName(option: StandardOptions){
        if (!option.name){
            throw "Option requires name"
        }
    }
}