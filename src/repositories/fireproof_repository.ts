import * as fireproofModule from '@fireproof/core/node'
import { Table } from './common/repository.js'
import { IDataStore } from 'src/interfaces/interfaces.js'

const Database = fireproofModule["Database"]
const Fireproof = fireproofModule["fireproof"]


export class FireproofDatastore implements IDataStore{
    keys: () => IterableIterator<string>
    
    private context
    createContext(config: any){
        if (!!this.fireproofKey){
            this.context = Fireproof(this.fireproofKey, config)
            return
        }
        throw "no fireproofKey configured"
    }
    constructor(private fireproofKey: string, config: any){
        this.createContext(config)
    }
    async get(key){
        return this.context.get(key)
    }
    async put(key: string, record: any){
        return this.context.put(key, record)
    }
    async delete(key: string){
        return this.context.delete(key)
    }
    async has(key: string){
        const item = this.get(key)
        return !!item
    }
}

export class FireproofTable<RecordType> extends Table<RecordType>{
    keys: () => IterableIterator<string>
    constructor(private fireproofKey: string, config: any){
        super(new FireproofDatastore(fireproofKey, config))
    }
}