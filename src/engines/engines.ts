import { IEncryptionManager, IGraphEngine, IHashManager, IMashfile, IMashfileEngine, IMashfileTypeEngine, INodeAttributes, ISignatureManager, OptionFactoryResolver, StandardEncryptionManagerOptions, StandardSignatureManagerOptions } from "src/interfaces/interfaces.js"
import { MashfileValidationStatus, TreeMetadata, FileMetadata, MashfileType, createFileMetadata, createTreeMetadata, resolveStandardSignatureManagerFromOption, resolveStandardEncryptionManagerFromOption} from "src/entities/entities.js"
import { EncryptionManagerStore, SignatureManagerStore } from "src/cryptography/cryptography.js"
import graphology from 'graphology';
import { hasCycle, willCreateCycle } from 'graphology-dag'

const attributeName = "attribute"
const noAttributeError = "No attributes found. Mashfile may not be in graph."

export class GraphEngine implements IGraphEngine{
    constructor(
        public mashfileEngine: IMashfileEngine,
        public graph = new graphology.DirectedGraph({multi: false, allowSelfLoops: false, type: "directed"})){
    }

    /**
     * Returns shallow copy of graph.
     * @returns new graph.
     */
    getCopyOfGraph(){
        return this.graph.copy()
    }

    /**
     * Removes all mashfiles and edges from graph.
     */
    clear(){
        this.graph.clear()
    }

    /**
     * Returns result of whether graph has the mashfile.
     * @param mashfile the mashfile to check
     * @returns boolean whether graph has the mashfile.
     */
    hasNode(mashfile: IMashfile){
        return !!this.getNode(mashfile.id)
    }

    /**
     * Gets the attributes of the @param mashfile. 
     * @param mashfile mashfile in graph
     * @returns instance of INodeAttributes
     * @throws error if mashfile not in graph
     */
    getAttributes(mashfile: IMashfile){
        if (this.hasNode(mashfile)){
            return this.graph.getNodeAttribute(mashfile.id, "attributes") as INodeAttributes
        }
        throw noAttributeError
    }

    /**
     * Updates attributes of mashfile. Mashfile must be in graph. 
     * @param mashfile mashfile in graph
     * @param nodeAttribute replacement attribute
     * @throws error if mashfile not in graph
     */
    updateAttributes(mashfile: IMashfile, nodeAttribute: INodeAttributes){
        const hasNode = this.hasNode(mashfile)
        if (hasNode){
            this.graph.setNodeAttribute(mashfile.id, attributeName, nodeAttribute)
            return
        }
        throw noAttributeError
    }

    /**
     * Sets mashfile to pin when persisted
     * @param mashfile mashfile in graph
     * @throws error if mashfile not in graph
     */
    pinNode(mashfile: IMashfile){
        const attributes = this.getAttributes(mashfile)
        attributes.pin = true
    }

    /**
     * Sets mashfile to encrypt with the provided settings
     * @param mashfile mashfile to encrypt
     * @param setting setting to use when encrypting
     */
    setNodeEncryption(mashfile: IMashfile, setting: StandardEncryptionManagerOptions){
        const attributes = this.getAttributes(mashfile)
        attributes.encrypt = setting
    }

    /**
     * Sets mashfile to sign with the provided settings
     * @param mashfile mashfile to sign
     * @param setting setting to use when signing
     */
    setNodeSignature(mashfile: IMashfile, setting: StandardSignatureManagerOptions){
        const attributes = this.getAttributes(mashfile)
        attributes.sign = setting
    }

    /**
     * Returns a mashfile from the graph if it exists, null otherwise
     * @param id id of mashfile
     * @returns mashfile or null
     */
    getNode(id: string){
        let mashfile: IMashfile = null
        if (this.graph.hasNode(id)){
            const node = this.graph.getNodeAttribute(id, "mashfile")
            if (!!node){
                mashfile = node as IMashfile
            }
        }
        return mashfile
    }

    /**
     * Adds mashfile to graph if doesn't exist. Otherwise it updates the mashfile.
     * @param mashfile the mashfile that will be updated
     * @returns boolean whether successful or not 
     */
    async mergeNode(mashfile: IMashfile){
        const attributes = {mashfile: mashfile, attributes: {}} as INodeAttributes
        const result = this.graph.mergeNode(mashfile.id, attributes)
        return result[1]
    }

    /**
     * Removes mashfile from graph, dropping all connected edges
     * @param mashfile the mashfile that will be removed
     */
    removeNode(mashfile: IMashfile){
        this.graph.dropNode(mashfile.id)
    }

    /**
     * Connects two mashfiles.
     * @param mashfile1 the existing mashfile that will be connected.
     * Since only roots can have children, and all other mashfile types must be leaves, mashfile1 must be a root.
     * @param mashfile2 the existing or new mashfile that will be connected. The mashfile will be added to the graph if it doesn't already exist. 
     */
    async connectNodes(mashfile1: IMashfile, mashfile2: IMashfile){
        // mashfile1 must be Root file
        // mashfile1 ---> mashfile2
        if (mashfile1.type != MashfileType.root){
            throw "mashfile1 must be a root mashfile"
        }
        if (!this.graph.hasNode(mashfile1.id)){
            throw "mashfile1 must exist in graph"
        }
        const mashfile2InGraph = this.graph.hasNode(mashfile2.id)
        if (mashfile2InGraph && willCreateCycle(this.graph, mashfile1.id, mashfile2.id)){
            throw "connecting nodes " + this.getEdgeKey(mashfile1, mashfile2) + " would create a cycle"
        }
        if (!mashfile2InGraph){
            await this.mergeNode(mashfile2)
        }
        this.graph.mergeDirectedEdgeWithKey(this.getEdgeKey(mashfile1, mashfile2) ,mashfile1.id , mashfile2.id)
    }

    /**
     * Disconnects the edge between two mashfiles.
     * @param mashfile1 
     * @param mashfile2 
     */
    disconnectNodes(mashfile1: IMashfile, mashfile2: IMashfile){
        this.graph.dropEdge(this.getEdgeKey(mashfile1, mashfile2))
    }

    /**
     * Validates the graph and all contained mashfiles.
     * @returns a list of errors. If error list is empty then operation was successful.
     */
    async validate(){
        let result =  new Array<any>()
        if (hasCycle(this.graph)){
            result.push(MashfileValidationStatus.hasCycle)
        }
        const encryptedNodes = this.graph.filterNodes((n, a) => {
            const mashfile = a.mashfile as IMashfile
            if (mashfile.encrypted || a.encrypt){
                return true
            }
            return false
        })
        encryptedNodes.forEach((encryptedNode) => {
            const encryptedNodeAttributes = this.graph.getNodeAttributes(encryptedNode)
            const mashfileOfEncryptedNode = encryptedNodeAttributes.mashfile as IMashfile
            const chainResults = this.validateEncryptionChain(mashfileOfEncryptedNode)
            result = result.concat(chainResults)
        })
        this.graph.forEachNode(async (node, attributes) => {
            const mashfile = attributes.mashfile as IMashfile
            const mashfileResult = await this.mashfileEngine.validate(mashfile)
            if (mashfileResult.length > 0){
                result = result.concat({ mashfileId: mashfile.id, error: mashfileResult})
            }
        })
        return result
    }

    /**
     * Secures all mashfiles in graph, adding signature, hash, and encryption where required.
     * @returns a list of errors. If error list is empty then operation was successful.
     */
    async secure(){
        const result =  new Array<any>()

        this.graph.forEachNode(async (node, attributes) => {
            const mashfile = attributes.mashfile as IMashfile
            const mashfileResult = await this.mashfileEngine.secure(mashfile)
            if (mashfileResult.length > 0){
                result.push({ mashfileHash: mashfile.id, error: mashfileResult})
            }
        })
        result.concat(await this.validate())
        return result
    }

    /**
     * Removes encryption from all mashfiles in graph so that they are all legible.
     */
    async unsecure(): Promise<void>{
        this.graph.forEachNode(async (node, attributes) => {
            const mashfile = attributes.mashfile as IMashfile
            return await this.mashfileEngine.unsecure(mashfile)
        })
    }

    /**
     * Returns serialized version of graph, used for distribution and storage if graph.
     * @returns serialized JSON string
     */
    toString(){
        return JSON.stringify(this.graph.export())
    }

    /**
     * Deserializes result from @method toString() which is processed into current graph.
     * @param graph the serialized graph string result from @method toString()
     */
    ingestFromString(graph: string){
        this.graph.import(JSON.parse(graph))
    }

    /**
     * Returns key for edges created by conflating the hashes of mashfile1 and mashfile2.
     * @param mashfile1 id of mashfile appears before '|' symbol. 
     * @param mashfile2 id of mashfile appears after '|' symbol.
     * @returns key for edge, used for creating edge in @method connectNodes()
     */
    protected getEdgeKey(mashfile1: IMashfile, mashfile2: IMashfile){
        return mashfile1.id + '|' + mashfile2.id
    }

    /**
     * Checks that all children and ancestors are encrypted if mashfile is encrypted.
     * Encrypted mashfiles cannot have unencrypted children.
     * @param mashfile the mashfile whos children will be checked
     * @throws if mashfile does not exist in graph
     */
    public validateEncryptionChain(mashfile: IMashfile){
        this.assertMashfileExistsInGraph(mashfile)
        const attributes = this.graph.getNodeAttributes(mashfile.id)
        if (mashfile.encrypted || attributes.encrypt){
            return this.validateEncryptionChainChildren(mashfile)
        }
        return []
    }

    protected validateEncryptionChainChildren(mashfile: IMashfile): Array<any>{
        let result = []
        this.graph.forEachOutboundNeighbor(mashfile.id, (neighbor, neighborAttributes) => {
            const neighborMashfile = neighborAttributes.mashfile as IMashfile
            if (!(neighborMashfile.encrypted || neighborAttributes.encrypt)){
                result.push({mashfile: mashfile.id, error: MashfileValidationStatus.encryptionChainInvalid})
            }
            const innerResults = this.validateEncryptionChainChildren(neighborMashfile)
            result = result.concat(innerResults)
        })
        return result
    }

    private assertMashfileExistsInGraph(mashfile: IMashfile){
        if (!mashfile || !this.graph.hasNode(mashfile.id)){
            throw "mashfile is missing from graph - id=" + mashfile.id
        }
    }
}

export abstract class MashfileTypeEngine implements IMashfileTypeEngine {
    constructor(
        private encryptionStore: EncryptionManagerStore,
        private signatureStore: SignatureManagerStore,
        private hashManager: IHashManager
    ){}

    hasEncryption(mashfile: IMashfile){
        return !!this.encryptionStore.get(mashfile.id)
    }

    hasSignature(mashfile: IMashfile){
        return !!this.signatureStore.get(mashfile.id)
    }

    removeEncryption(mashfile: IMashfile){
        if (this.hasEncryption(mashfile)){
            this.encryptionStore.remove(mashfile.id)
        }
    }

    removeSignature(mashfile: IMashfile){
        if (this.hasSignature(mashfile)){
            this.signatureStore.remove(mashfile.id)
        }
    }

    async addEncryption(mashfile: IMashfile, option: StandardEncryptionManagerOptions|OptionFactoryResolver<IEncryptionManager>): Promise<void>{
        let manager;
        if (typeof(option) == "function"){
            manager = option()
        } else {
            manager = resolveStandardEncryptionManagerFromOption(option.type, option)
        }
        this.encryptionStore.add(mashfile.id, manager)
    }

    async addSignature(mashfile: IMashfile, option: StandardSignatureManagerOptions|OptionFactoryResolver<ISignatureManager>): Promise<void>{
        let manager;
        if (typeof(option) == "function"){
            manager = option()
        } else {
            manager = resolveStandardSignatureManagerFromOption(option.type, option)
        }

        this.signatureStore.add(mashfile.id, manager)
    }

    async hash(mashfile: IMashfile): Promise<void>{
        if (!mashfile.hash){
            if (mashfile.encrypted){
                throw "mashfile must be unencrypted to hash"
            }
            await this.hashManager.hash(mashfile)
        }
    }

    async validate(mashfile: IMashfile): Promise<Array<string>> {
        const aggregateResults = new Array<string>()
        try {
            const encrypted = mashfile.encrypted
            const payload = await this.encryptionStore.decrypt(mashfile)
            if (!payload){
                aggregateResults.push(MashfileValidationStatus.encryptionFailed)
            }
            if (!await this.signatureStore.validate(mashfile)){
                aggregateResults.push(MashfileValidationStatus.signatureInvalid)
            }
            const hashMatch = await this.hashManager.validate(mashfile)
            if (!hashMatch){
                aggregateResults.push(MashfileValidationStatus.encryptionFailed)
            }
            if (encrypted){
                this.encryptionStore.encrypt(mashfile)
            }
        }
        catch (error){
            aggregateResults.push(MashfileValidationStatus.unknown + ": " + error)
        }
        return aggregateResults
    }

    async secure(mashfile: IMashfile): Promise<Array<string>> {
        if (mashfile.encrypted){
            throw 'mashfile already encrypted'
        }
        await this.hashManager.hash(mashfile)
        await this.signatureStore.sign(mashfile)
        await this.encryptionStore.encrypt(mashfile)
        return await this.validate(mashfile)
    }

    async unsecure(mashfile: IMashfile): Promise<void>{
        await this.encryptionStore.decrypt(mashfile)
    }

    async getUnencryptedPayload(mashfile: IMashfile): Promise<any>{
        const unencryptedPayload = await this.encryptionStore.decrypt(mashfile)
        return unencryptedPayload
    }
}

export abstract class MashfileTypeEngineWithType<PayloadType> extends MashfileTypeEngine{
    abstract createPayload(): PayloadType
    async getUnencryptedPayload(mashfile: IMashfile): Promise<PayloadType> {
        var payload = super.getUnencryptedPayload(mashfile)
        return Object.assign(this.createPayload(), payload)
    }
}

export class RootEngine extends MashfileTypeEngineWithType<TreeMetadata>{
    createPayload = createTreeMetadata
}

export class FileEngine extends MashfileTypeEngineWithType<FileMetadata>{
    createPayload = createFileMetadata
}

export class PlainEngine extends MashfileTypeEngineWithType<any>{
    createPayload = () => {}
}

export class MashfileEngine implements IMashfileEngine{
    constructor(
        private encryptionStore: EncryptionManagerStore,
        private signatureStore: SignatureManagerStore,
        private hashManager: IHashManager,
        private engines: Map<string, IMashfileTypeEngine> = new Map()){
        this.initialize()
    }
    hasEncryption(mashfile: IMashfile): boolean {
        const engine = this.getEngineOfType(mashfile.type)
        return engine.hasEncryption(mashfile)
    }
    hasSignature(mashfile: IMashfile): boolean {
        const engine = this.getEngineOfType(mashfile.type)
        return engine.hasSignature(mashfile)
    }
    removeEncryption(mashfile: IMashfile): void {
        const engine = this.getEngineOfType(mashfile.type)
        return engine.removeEncryption(mashfile)
    }
    removeSignature(mashfile: IMashfile): void {
        const engine = this.getEngineOfType(mashfile.type)
        return engine.removeSignature(mashfile)
    }

    async hash(mashfile: IMashfile): Promise<void>{
        const engine = this.getEngineOfType(mashfile.type)
        await engine.hash(mashfile)
    }

    async validate(mashfile: IMashfile){
        const engine = this.getEngineOfType(mashfile.type)
        return await engine.validate(mashfile)
    }

    async unsecure(mashfile: IMashfile): Promise<void> {
        const engine = this.getEngineOfType(mashfile.type)
        await engine.unsecure(mashfile)
    }

    async secure(mashfile: IMashfile): Promise<Array<string>>{
        const engine = this.getEngineOfType(mashfile.type)
        return await engine.secure(mashfile)
    }

    getEngine(string: string): IMashfileTypeEngine{
        return this.engines[string] || null
    }

    setEngine(string: string, engine: IMashfileTypeEngine): void {
        this.engines[string] = engine
    }

    private initialize(){
        this.setEngine(MashfileType.root, new RootEngine(this.encryptionStore, this.signatureStore, this.hashManager))
        this.setEngine(MashfileType.file, new FileEngine(this.encryptionStore, this.signatureStore, this.hashManager))
        this.setEngine(MashfileType.plain, new PlainEngine(this.encryptionStore, this.signatureStore, this.hashManager))
    }

    private getEngineOfType(type:string){
        const engine = this.getEngine(type)
        if (!engine){
            throw "engine missing for mashfile of type " + type
        }
        return engine
    }
}