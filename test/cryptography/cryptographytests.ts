import { expect } from 'chai';
import { describe, it } from 'node:test';
import { 
    AES256_EncryptionManager, 
    SHA256_HashManager, 
    HMAC_SignatureManager, 
    SHA256_SignatureManager, 
    RSA_EncryptionManager, 
    createNewPrivateKeyFromPemInput, 
    createNewPublicKeyFromPemInput, 
    SHA512_SignatureManager,
    SHA512_HashManager,
    randomBytes
} from '../../src/cryptography/cryptography.js';
import { privateKey, publicKey } from './cryptographytesthelpers.js';

describe('AES256_EncryptionManager', () => {
    const key = randomBytes(32); // AES256 requires a 32-byte key
    const aes256_encryptionManager = new AES256_EncryptionManager(key)

    describe('encryptText', () => {
        it('should encrypt text correctly', () => {
            const text = 'Hello, World!';
            const encryptedText = aes256_encryptionManager.encryptText(text);
            expect(encryptedText).to.be.a('string');
            expect(encryptedText).to.not.equal(text);
        });
    });

    describe('decryptText', () => {
        it('should decrypt text correctly', () => {
            const text = 'Hello, World!';
            const encryptedText = aes256_encryptionManager.encryptText(text);
            const decryptedText = aes256_encryptionManager.decryptText(encryptedText);
            expect(decryptedText).to.equal(text);
        });
    });
});

describe('SHA256_HashManager', () => {
    const hash_manager = new SHA256_HashManager()

    describe('createHash', () => {
        it('should hash successfully', () => {
            const text = 'Hello, World!';
            const hash = hash_manager.createHash(text);
            expect(hash).to.not.equal(text);
        })
    })

    describe('validateHash', () => {
        it('should validate a hash successfully', () => {
            const text = 'Hello, World!';
            const hash = hash_manager.createHash(text);
            const validationResult = hash_manager.validateHash(hash, text);
            expect(validationResult).to.equal(true);
        })
    })
});

describe('SHA512_HashManager', () => {
    const hash_manager = new SHA512_HashManager()

    describe('createHash', () => {
        it('should hash successfully', () => {
            const text = 'Hello, World!';
            const hash = hash_manager.createHash(text);
            expect(hash).to.not.equal(text);
        })
    })

    describe('validateHash', () => {
        it('should validate a hash successfully', () => {
            const text = 'Hello, World!';
            const hash = hash_manager.createHash(text);
            const validationResult = hash_manager.validateHash(hash, text);
            expect(validationResult).to.equal(true);
        })
    })
});

describe('SHA256_SignatureManager', () => {
    const privKey = createNewPrivateKeyFromPemInput(privateKey)
    const pubKey = createNewPublicKeyFromPemInput(privateKey)
    var sigManager = new SHA256_SignatureManager(privKey, pubKey)
    describe('signPayload', () => {
        it('should sign successfully', () => {
            const text = 'Hello, World!';
            const signature = sigManager.signPayload(text)
            expect(signature).to.not.equal(text);
        })
    })

    describe('verifyPayload', () => {
        it('should sign successfully', () => {
            const text = 'Hello, World!';
            const signature = sigManager.signPayload(text)
            const verification = sigManager.validatePayload(text, signature)
            expect(verification).to.be.equal(true);
        })
    })
})

describe('SHA512_SignatureManager', () => {
    const privKey = createNewPrivateKeyFromPemInput(privateKey)
    const pubKey = createNewPublicKeyFromPemInput(privateKey)
    var sigManager = new SHA512_SignatureManager(privKey, pubKey)
    describe('signPayload', () => {
        it('should sign successfully', () => {
            const text = 'Hello, World!';
            const signature = sigManager.signPayload(text)
            expect(signature).to.not.equal(text);
        })
    })

    describe('verifyPayload', () => {
        it('should sign successfully', () => {
            const text = 'Hello, World!';
            const signature = sigManager.signPayload(text)
            const verification = sigManager.validatePayload(text, signature)
            expect(verification).to.be.equal(true);
        })
    })
})


describe('HMAC_SignatureManager', () => {
    var sigManager = new HMAC_SignatureManager(Buffer.from('test'))
    describe('signPayload', () => {
        it('should sign successfully', () => {
            const text = 'Hello, World!';
            const signature = sigManager.signPayload(text)
            expect(signature).to.not.equal(text);
        })
    })

    describe('verifyPayload', () => {
        it('should sign successfully', () => {
            const text = 'Hello, World!';
            const signature = sigManager.signPayload(text)
            const verification = sigManager.validatePayload(text, signature)
            expect(verification).to.be.equal(true);
        })
    })
})

describe('RSA_EncryptionManager', () => {
    var key = Buffer.from(privateKey, 'utf8')
    var pubKey = Buffer.from(publicKey, 'utf8')
    const encryptionManager = new RSA_EncryptionManager(key, pubKey)
    describe('encryptTextPrivateKey', () => {
        it('should return encrypted text', () => {
            var text = 'Hello World!'
            var encrypted = encryptionManager.encryptTextPrivateKey(text)
            expect(encrypted).to.not.be.equal(text)
        })
    })
    describe('decryptTextPrivateKey', () => {
        it('should decrypt to same value which was encrypted', () => {
            var text = 'Hello World!'
            var encrypted = encryptionManager.encryptTextPublicKey(text)
            var decrypted = encryptionManager.decryptTextPrivateKey(encrypted)
            expect(decrypted).to.be.equal(text)
        })
    })
}); 

describe("keys",() => {
    describe('createNewPrivateKeyFromPemInput', () => {
        it('should not error', () => {
            const result = createNewPrivateKeyFromPemInput(privateKey)
            expect(result).to.exist
        })
    })

    describe('createNewPublicKeyFromPemInput', () => {
        it('should not error', () => {
            const result = createNewPublicKeyFromPemInput(publicKey);
            expect(result).to.exist
        })
    })
})