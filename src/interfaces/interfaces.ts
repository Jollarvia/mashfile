import { HeliaInit } from "helia";
import { CID } from "multiformats";

import { Description } from "src/entities/entities.js";

export interface INodeMetadata{
    mashfile: IMashfile
    attributes: INodeAttributes
}

export interface INodeAttributes{
    pin?: boolean
    encrypt?: StandardEncryptionManagerOptions|OptionFactoryResolver<IEncryptionManager>
    sign?: StandardSignatureManagerOptions|OptionFactoryResolver<ISignatureManager>
}

export interface ITreeMetadata {
    children?: Array<CID>;
	treeType?: string;
    childHash?: string;
}

export interface IFileMetadata{
    cid: CID;
    metadataAuthor?: string;
    referenceFrom?: string;
    referenceTo?: string;
    fileName: string;
    contentType?: string;
    contentDisposition?: string;
    extension?: string;
    MIMEtype?: string;
    size?: number;
    dateCreated?: Date;
    dateModified?: Date;
    author?: string;
    title?: string;
    description?: string;
    tags?: Array<string>;
    location?: string;
    copyright?: string;
    source?: string;
    categories?: Array<string>;
    associatedSoftware?: string;
    duration?: string;
    related?: Array<string>;
    encryptionMethod?: string;
    hash?: string;
    hashAlgorithm?: string;
    signature?: string;
}

export interface IMashfileDetail extends Description{
    author?: string;
    version?: string;
}

export interface IMashfile {
    detail?: IMashfileDetail;
    id: string;
    type: string;
    encrypted?: boolean;
    encryptionMethod?: string;
    payload?: any;
    signature?: string;
    hash?: string;
    hashAlgorithm?: string;
    mashfileVersion?: string;
}

export interface IEngine {
    
}

export interface IGraphEngine extends IEngine {
    // validates and builds graphs of mashfiles
}

export interface IMashfileEngineBase extends IEngine {
    hash(mashfile: IMashfile): Promise<void>
    validate(mashfile: IMashfile): Promise<Array<string>>
    unsecure(mashfile: IMashfile): Promise<void>
    secure(mashfile: IMashfile): Promise<Array<string>>
    hasEncryption(mashfile: IMashfile): boolean
    hasSignature(mashfile: IMashfile): boolean
    removeEncryption(mashfile: IMashfile): void
    removeSignature(mashfile: IMashfile): void
}

export interface IMashfileEngine extends IMashfileEngineBase {
    // validates and builds mashfiles
    getEngine(string: string): IMashfileTypeEngine
    setEngine(string: string, engine: IMashfileTypeEngine): void
}

export interface IMashfileTypeEngine extends IMashfileEngineBase {
    // validates and builds a mashfile of a certain type
    getUnencryptedPayload(mashfile: IMashfile): Promise<any>
}

export interface IMashfileTypeEngineWithType<PayloadType> extends IMashfileTypeEngine {
    // validates and builds mashfile of specific type
    validate(mashfile: IMashfile): Promise<Array<string>>
    getUnencryptedPayload(mashfile: IMashfile): Promise<PayloadType>
}

export interface IHashManager {
    hash(mashfile: IMashfile): Promise<void>
    validate(mashfile: IMashfile): Promise<boolean>
}

export interface INamedData<ValueType>{
    value: ValueType
    name: string
}

export interface ISignatureManager {
    sign(mashfile: IMashfile): Promise<void>
    validate(mashfile: IMashfile): Promise<boolean>
}

export interface IEncryptionManager{
    encrypt(mashfile: IMashfile): Promise<void>
    decrypt(mashfile: IMashfile): Promise<any>
    getDecryptedPayload(mashfile: IMashfile): Promise<any>
}

export interface IEncryptionManagerWithType<PayloadType> extends IEncryptionManager{
    encrypt(mashfile: IMashfile): Promise<void>
    decrypt(mashfile: IMashfile): Promise<PayloadType>
    getDecryptedPayload(mashfile: IMashfile): Promise<PayloadType>
}

export interface IMashfileSerializer{
    serialize: (mashfile: IMashfile) => string
    deserialize: (mashfile: IMashfile) => any 
}

export interface ITable<RecordType> {
    get: (key: string) => Promise<RecordType>
    put: (key: string, record: RecordType) => Promise<void>
    delete: (key: string) => Promise<void>
    keys: () => IterableIterator<string>
}

export interface IDataStore {
    get: (key: string) => Promise<any>
    put: (key: string, record: any) => Promise<void>
    delete: (key: string) => Promise<void>
    has: (key: string) => Promise<boolean>
}

export interface IRepository{
    key: ITable<StandardEncryptionManagerOptions>
    signature: ITable<StandardSignatureManagerOptions>
}

/*** configuration ***/
export interface StandardOptions{
    name: string
    type: string
}

export interface EncryptionOptions{
    encryptionManagers?: Array<StandardEncryptionManagerOptions|OptionFactoryResolver<IEncryptionManager>>
}

export interface StandardEncryptionManagerOptions extends StandardOptions{
    key?: string
    url?: string
}

export type StandardSignatureManagerOptions = HMAC_SignatureManagerOptions|SHA256_SignatureManagerOptions

export interface SignatureOptions{
    signatureManagers?: Array<StandardSignatureManagerOptions|OptionFactoryResolver<ISignatureManager>>
}

export interface IpfsOptions{
    heliaInit?: HeliaInit
}

export interface MashfilerOptions{
    encryptionOptions?: EncryptionOptions
    signatureOptions?: SignatureOptions
    ipfsOptions?: IpfsOptions
    repository?: string|(()=> IRepository)
}

export interface OptionFactoryResolverResult<OptionType>{
    name: string,
    value: OptionType
}

export interface OptionFactoryResolver<OptionType> {
    (): OptionFactoryResolverResult<OptionType>
}

export interface HMAC_SignatureManagerOptions extends StandardOptions{
    key?: string
    url?: string
    algorithm: string
}

export interface SHA256_SignatureManagerOptions extends StandardOptions{
    privateKey?: string
    privateKeyUrl?: string
    publicKey?: string
    publicKeyUrl?: string
}

/* data transfer objects */
export interface PersistGraphResult{
    rootIdsToChildren: Map<string, Set<string>>
    idToCID: Map<string, string>
    idToEncryption: Map<string, string>
    idToSignature: Map<string, string>
}

