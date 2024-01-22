import { IEncryptionManager, IHashManager, IMashfile, INamedData, ISignatureManager } from "src/interfaces/interfaces.js";
import { convertPayloadToString } from '../serialization/serialization.js'
import { promisify } from 'util'
import { 
    constants,
    privateDecrypt,
    privateEncrypt,
    publicDecrypt,
    publicEncrypt,
    randomBytes,
    createCipheriv,
    createDecipheriv,
    createPublicKey,
    createPrivateKey,
    createSign,
    createHmac,
    createVerify,
    createHash,
    PrivateKeyInput,
    PublicKeyInput,
    scrypt,
    KeyObject,
    generateKeyPair
} from 'crypto'

export const errorHashRequired = "mashfile.hash required to decrypt"
export const errorIdRequired = "mashfile.id required"

export class RSA_EncryptionManager {
    
    constructor(private privateKey?: Buffer, private publicKey?: Buffer) {
        this.ThrowIfNoKeyFound()
    }

    encryptTextPrivateKey(text: string): string {
        this.ThrowIfPrivateKeyMissing()
        const buffer = Buffer.from(text, 'utf8');
        const encrypted = privateEncrypt(this.privateKey, buffer)
        return encrypted.toString('base64')
    }

    encryptTextPublicKey(text: string): string {
        const key = this.privateKey || this.publicKey
        const buffer = Buffer.from(text, 'utf8');
        const encrypted = publicEncrypt(key, buffer)
        return encrypted.toString('base64')
    }

    decryptTextPrivateKey(encryptedText: string): string {
        this.ThrowIfPrivateKeyMissing()
        const buffer = Buffer.from(encryptedText, 'base64');
        const decrypted = privateDecrypt(this.privateKey, buffer);
        return decrypted.toString('utf8');
    }

    decryptTextPublicKey(encryptedText: string): string {
        var key = this.publicKey || this.privateKey
        const buffer = Buffer.from(encryptedText, 'base64');
        const decrypted = publicDecrypt(key, buffer);
        return decrypted.toString('utf8');
    }

    private ThrowIfPrivateKeyMissing(){
        if (!this.privateKey){
            throw 'private key required'
        }
    }

    private ThrowIfNoKeyFound(){
        if (!(this.privateKey || this.publicKey)){
            throw 'privateKey or publicKey required'
        }
    }
}


export class AES256_EncryptionManager implements IEncryptionManager {
    private key: Buffer;
    private encryptionMethod = 'aes-256'

    constructor(key: string|Buffer) {
        let builtKey: Buffer
        if (!key) throw "key required"
        if (typeof(key) == "string"){
            builtKey = Buffer.from(key, 'utf8')
        }
        else {
            builtKey = key
        }
        if (builtKey.byteLength != 32) throw "key required to be 32 bytes; byte length is " + builtKey.byteLength
        this.key = builtKey
    }
    async getDecryptedPayload(mashfile: IMashfile): Promise<any> {
        try{
            return this.decryptText(convertPayloadToString(mashfile))
        }
        catch (e){
            throw "decryption unsuccessful: " + e
        }
    }
    async encrypt(mashfile: IMashfile): Promise<void> {
        try{
            mashfile.payload = this.encryptText(convertPayloadToString(mashfile))
        }
        catch (e) {
            throw "encryption unsuccessful: " + e
        }
        mashfile.encrypted = true
        mashfile.encryptionMethod = this.encryptionMethod
    }
    async decrypt(mashfile: IMashfile): Promise<any> {
        mashfile.payload = await this.getDecryptedPayload(mashfile)
        mashfile.encrypted = false
        mashfile.encryptionMethod = null
        return mashfile.payload
    }

    encryptText(text: string): string {
        const iv = randomBytes(16);
        const cipher = createCipheriv('aes-256-cbc', this.key, iv);
        let encryptedText = cipher.update(text, 'utf8', 'hex');
        encryptedText += cipher.final('hex');
        return iv.toString('hex') + ':' + encryptedText;
    }

    decryptText(text: string): string {
        const textParts = text.split(':')
        const ivString = textParts.shift()
        const iv = Buffer.from(ivString, 'hex')
        const encryptedText = textParts.join(':')
        const decipher = createDecipheriv('aes-256-cbc', this.key, iv)
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8')
        decrypted += decipher.final('utf8')
        return decrypted
    }
}

class SHA_HashManager implements IHashManager {
    constructor(private algorithm: string){}
    async hash(mashfile: IMashfile){
        if (mashfile.encrypted){
            throw "cannot hash after encryption"
        }
        mashfile.hash = this.createHash(convertPayloadToString(mashfile))
        mashfile.hashAlgorithm = this.algorithm
    }
    async validate(mashfile: IMashfile){
        return this.validateHash(mashfile.hash, convertPayloadToString(mashfile))
    }

    createHash(payload: string): string {
        const hash = createHash(this.algorithm);
        hash.update(payload);
        return hash.digest('hex');
    }

    validateHash(hash: string, payload: string): boolean {
        const currentHash = this.createHash(payload);
        return hash === currentHash;
    }
}

export class SHA256_HashManager extends SHA_HashManager implements IHashManager {
    constructor(){
        super("sha256")
    }
}

export class SHA512_HashManager extends SHA_HashManager implements IHashManager {
    constructor(){
        super("sha512")
    }
}

class SHA_SignatureManager implements ISignatureManager {
    constructor(private privateKey: PrivateKeyInput | KeyObject, private publicKey: PublicKeyInput | KeyObject, private algorithm: string) {
    }
    async sign(mashfile: IMashfile) {
        mashfile.signature = this.signPayload(mashfile.payload)
    }
    async validate(mashfile: IMashfile): Promise<boolean> {
        var result = this.validatePayload(mashfile.payload, mashfile.signature)
        return result
    }

    signPayload(payload: string): string {
        const sign = createSign(this.algorithm);
        sign.update(payload);
        sign.end();
        const signature = sign.sign(this.privateKey);
        return signature.toString('base64');
    }

    validatePayload(payload: string, signature: string): boolean {
        const verify = createVerify(this.algorithm);
        verify.update(payload);
        verify.end();
        const result = verify.verify(this.publicKey, Buffer.from(signature, 'base64'));
        return result
    }
}

export class SHA256_SignatureManager extends SHA_SignatureManager implements ISignatureManager {
    constructor(privateKey: PrivateKeyInput | KeyObject, publicKey: PublicKeyInput | KeyObject) {
        super(privateKey, publicKey, "SHA256")
    }
}

export class SHA512_SignatureManager extends SHA_SignatureManager implements ISignatureManager {
    constructor(privateKey: PrivateKeyInput | KeyObject, publicKey: PublicKeyInput | KeyObject) {
        super(privateKey, publicKey, "SHA512")
    }
}

export class HMAC_SignatureManager implements ISignatureManager {
    constructor(private key: Buffer, private algorithm: string = 'SHA256') {
    }
    async sign(mashfile: IMashfile) {
        mashfile.signature = this.signPayload(mashfile.payload)
    }
    async validate(mashfile: IMashfile): Promise<boolean> {
        var result = this.validatePayload(mashfile.payload, mashfile.signature)
        return result
    }

    signPayload(payload: string): string {
        const sign = createHmac(this.algorithm, this.key);
        sign.update(payload);
        const signature = sign.digest('hex');
        return signature
    }

    validatePayload(payload: string, signature: string): boolean {
        return this.signPayload(payload) === signature
    }
}

var SignatureManager_PublicKeyInput_Provider = (publicKey: Buffer) =>{
    return {
        key: publicKey,
        format: 'pem',
        type: 'pkcs1',
    }
}

var SignatureManager_PrivateKeyInput_Provider = (privateKey: Buffer) =>{
    return {
            key: privateKey,
            format: 'pem',
            type: 'pkcs8',
    }
}

var createNewPrivateKeyFromPemInput = (privateKey: string, type:  "pkcs1" | "pkcs8" | "sec1" = 'pkcs1') => {
    return createPrivateKey({
        key: privateKey,
        format: 'pem',
        type: type,
    })
}

var createNewPublicKeyFromPemInput = (privateKey: string, type:  "pkcs1" | "spki" = 'pkcs1') => {
    return createPublicKey({
        key: privateKey,
        format: 'pem',
        type: type,
    })
}

const createPrivateKeyIV = () => {
    return randomBytes(16)
}

const randomString = (numberOfCharacters) => {
    return randomBytes(numberOfCharacters).toString("hex")
}

const createRandomAES_256_key = (size: number = 32) => {
    return randomBytes(size)
}

const generateRSAKeyPairWithCallback = (error, callback) => {
    generateKeyPair("rsa", {
        // The standard secure default length for RSA keys is 2048 bits
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem',
        }
      }, callback)
}

const generateRSAKeyPair = promisify(generateRSAKeyPairWithCallback)

const determineHamtBitmapPosition = (branchingFactor: number, hash: string, layerIndex: number = 0) => {
    hash = hash.toLowerCase()
    if (!hash.startsWith("0x")){
        hash = "0x" + hash
    }
    const hashNumber = Number(hash)
    const bits = []
    for(let i=0; i<branchingFactor-1; i++){
        bits.push("1")
    }
    const bitmaskString = "0b" + bits.join("")
    const bitmaskNumber = Number(bitmaskString)
    return hashNumber >> (layerIndex*branchingFactor) & bitmaskNumber
}

export { 
    SignatureManager_PublicKeyInput_Provider as SHA256_SignatureManager_PublicKeyInput_Provider,
    SignatureManager_PrivateKeyInput_Provider as SHA256_SignatureManager_PrivateKeyInput_Provider,
    createNewPrivateKeyFromPemInput,
    createNewPublicKeyFromPemInput,
    createPrivateKeyIV,
    generateRSAKeyPair,
    generateRSAKeyPairWithCallback,
    createRandomAES_256_key,
    randomString,
    determineHamtBitmapPosition
 }

 export class DumbEncryptionManager implements IEncryptionManager{
    async getDecryptedPayload(mashfile: IMashfile): Promise<any> {
        return mashfile.payload
    }
    async encrypt(mashfile: IMashfile): Promise<void> {
    }
    async decrypt(mashfile: IMashfile): Promise<any> {
        return mashfile.payload
    }

}

export class DumbSignatureManager implements ISignatureManager{
    async sign(mashfile: IMashfile): Promise<void> {
        
    }
    async validate(mashfile: IMashfile): Promise<boolean> {
        return true
    }
}

 export abstract class CryptoStore<StoreType> {
    constructor(private store: Map<string, StoreType> = new Map<string, StoreType>(), private dummy: StoreType){

    }

    get(key: string): StoreType{
        return this.store[key] || this.dummy
    }
    add(key: string, value: StoreType){
        this.store[key] = value
    }
    remove(key: string){
        this.store[key] = null
    }
    has(key: string) {
        return this.store.has(key)
    }
 }

 export class SignatureManagerStore extends CryptoStore<INamedData<ISignatureManager>>{
    constructor(sStore: Map<string, INamedData<ISignatureManager>> = new Map()){
        super(sStore, {name:"dumb", value: new DumbSignatureManager()})
    }
    async validate(mashfile: IMashfile, signName: string = null): Promise<boolean> {
        const id = signName || mashfile.id
        if (!id){
            throw errorHashRequired
        }
        if (!mashfile.signature){
            return true
        }
        const signatureManager = this.get(id).value
        return signatureManager.validate(mashfile)
    }

    sign(mashfile: IMashfile, signName: string = null): Promise<void> {
        const id = signName || mashfile.id
        if (!id){
            throw errorIdRequired
        }
        const signatureManager = this.get(id)
        signatureManager.value.sign(mashfile)
        return
    }
}

 export class EncryptionManagerStore extends CryptoStore<INamedData<IEncryptionManager>>{
    constructor(sStore: Map<string, INamedData<IEncryptionManager>> = new Map()){
        super(sStore, {name:"dumb", value: new DumbEncryptionManager()})
    }
    async decrypt(mashfile: IMashfile, encryptName: string = null): Promise<any> {
        const hash = mashfile.hash
        const id = encryptName || mashfile.id
        if (!id){
            throw errorIdRequired
        }
        if (!hash){
            throw errorHashRequired
        }
        if (!mashfile.encrypted){
            return mashfile.payload
        }
        const encryptionManager = this.get(id).value
        const decrypted = await encryptionManager.decrypt(mashfile)
        return decrypted
    }
    async encrypt(mashfile: IMashfile, encryptName: string = null): Promise<void> {
        const id = encryptName || mashfile.id
        const encryptionManager = this.get(id).value
        return await encryptionManager.encrypt(mashfile)
    }

    async getDecryptedPayload(mashfile: IMashfile, encryptName: string = null): Promise<any>{
        const hash = mashfile.hash
        const id = encryptName || mashfile.id
        if (!id){
            throw errorIdRequired
        }
        if (!hash){
            throw errorHashRequired
        }
        if (!mashfile.encrypted){
            return mashfile.payload
        }
        const encryptionManager = this.get(id).value
        return encryptionManager.getDecryptedPayload(mashfile)
    }
}

export { randomUUID } from 'crypto'