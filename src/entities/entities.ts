import { HMAC_SignatureManagerOptions, IEncryptionManager, IFileMetadata, IMashfile, IMashfileDetail, ITreeMetadata, SHA256_SignatureManagerOptions, StandardEncryptionManagerOptions } from "src/interfaces/interfaces.js";
import { AES256_EncryptionManager, HMAC_SignatureManager, SHA256_SignatureManager, SHA256_SignatureManager_PrivateKeyInput_Provider, SHA256_SignatureManager_PublicKeyInput_Provider, SHA512_SignatureManager, randomUUID } from "src/cryptography/cryptography.js";
import { CID } from "multiformats";

export enum MashfileVersion{
    unknown = "unknown",
    one = "1.0"
}

export const currentMashfileVersion: MashfileVersion = MashfileVersion.one

export enum MashfileValidationStatus{
    unknown = "unknown",
    signatureInvalid = "signature invalid",
    encryptionFailed = "encryption failed",
    hasCycle = "graph has cycle",
    encryptionChainInvalid = "encryption chain is invalid"
}

export enum MashfileType {
    unknown = "unknown",
    root = "root",
    file = "file",
    plain = "plain"
}

export enum TreeType {
    unknown = "unknown",
    dag = "dag"
}

export enum StandardEncryptionManagerType{
    AES256_EncryptionManager = "AES256_EncryptionManager"
}

export enum StandardSignatureManagerType{
    SHA256_SignatureManager = "SHA256_SignatureManager",
    SHA512_SignatureManager = "SHA512_SignatureManager",
    HMAC_SignatureManager = "HMAC_SignatureManager"
}

export function resolveStandardEncryptionManagerFromOption(type: string, option: StandardEncryptionManagerOptions): IEncryptionManager{
    switch(type){
        case StandardEncryptionManagerType.AES256_EncryptionManager:
            return new AES256_EncryptionManager(option.key)
        default:
            throw "Cannot construct encryption manager; No standard encryption manager with name " + type
    }
}

export function resolveStandardSignatureManagerFromOption(type: string, option: StandardEncryptionManagerOptions){
    const resolveSHA_Signaturemanager = (option: StandardEncryptionManagerOptions, encryptionType) => {
        if(!objectImplementsSha256_SignatureManagerOptions(option)){
            throw "SignatureManagerOption invalid"
        }
        const shaOp = option as SHA256_SignatureManagerOptions
        let privateKey = null, publicKey = null
        if (shaOp.privateKey){
            privateKey = SHA256_SignatureManager_PrivateKeyInput_Provider(Buffer.from(shaOp.privateKey))
        }
        if (shaOp.privateKeyUrl){

        }
        if (shaOp.publicKey){
            publicKey = SHA256_SignatureManager_PublicKeyInput_Provider(Buffer.from(shaOp.publicKey))
        }
        if (shaOp.publicKeyUrl){

        }

        return new encryptionType(privateKey, publicKey)
    }

    switch(type){
        case StandardSignatureManagerType.SHA256_SignatureManager:
            return resolveSHA_Signaturemanager(option, SHA256_SignatureManager)
        case StandardSignatureManagerType.SHA512_SignatureManager:
            return resolveSHA_Signaturemanager(option, SHA512_SignatureManager)
        case (StandardSignatureManagerType.HMAC_SignatureManager):
            const hmacOp = option as HMAC_SignatureManagerOptions
            if (option.key){
                let key = Buffer.from(hmacOp.key)
                return new HMAC_SignatureManager(key, hmacOp.algorithm)
            
            }
            if (option.url){

            }
        default:
            "Cannot construct signature manager; No standard signature manager with name " + type
    }
}

function objectImplementsHMAC_SignatureManagerOptions(object){
    return objectImplements(object, ['algorithm'])
}

function objectImplementsSha256_SignatureManagerOptions(object){
    return objectImplements(object, ['privateKey', 'privateKeyUrl', 'publicKey', 'publicKeyUrl'])
}

function objectImplements(object: any, members: Array<string>): boolean {
    let result = false
    members.forEach((member) => {
        if ((member in object)){
            result = true
        }
    })

    return result
}

export class TreeMetadata implements ITreeMetadata {
    children?: Array<CID>
	treeType?: TreeType
}

export class FileMetadata implements IFileMetadata {
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
    tags?: string[];
    location?: string;
    copyright?: string;
    source?: string;
    categories?: string[];
    associatedSoftware?: string;
    duration?: string;
    related?: string[];
    encryptionMethod?: string;
    hash?: string;
    hashAlgorithm?: string;
    signature?: string;
    cid: CID
    metadataAuthor?: string
    referenceFrom?: string
    referenceTo?: string
}

export class Description{
    name?: string;
    description?: string;
    information?: string;
}

export class MashfileDetail extends Description implements IMashfileDetail{
    author?: string
    version?: string
}

export class Mashfile<Payload> implements IMashfile {
    detail: Description
    type: MashfileType
    id: string
    encrypted?: boolean
    encryptionMethod?: string;
    parent?: string
    payload?: Payload
    signature?: string
    hash?: string
    hashAlgorithm?: string
    mashfileVersion?: string

    constructor(){
        this.id = randomUUID()
        this.mashfileVersion = currentMashfileVersion
        this.detail = new Description()
    }
}

export class Root extends Mashfile<TreeMetadata>{
    constructor(){
        super()
        this.type = MashfileType.root
        this.payload = createTreeMetadata()
    }
}

export class File extends Mashfile<FileMetadata>{
    constructor(){
        super()
        this.type = MashfileType.file
        this.payload = createFileMetadata()
    }
}

export const createFileMetadata = () => {
    const data = new FileMetadata()
    return data
}

export const createTreeMetadata = () => {
    const data = new TreeMetadata()
    data.treeType = TreeType.dag
    data.children = []
    return data
}