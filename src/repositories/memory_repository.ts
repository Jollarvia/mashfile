import { IDataStore, IRepository, StandardEncryptionManagerOptions, StandardSignatureManagerOptions } from "src/interfaces/interfaces.js";
import { Table } from "./common/repository.js";

export class MemoryRepository implements IRepository{
    key = new MemoryTable<StandardEncryptionManagerOptions>()
    signature = new MemoryTable<StandardSignatureManagerOptions>()
}

export class MemoryTable<RecordType> extends Table<RecordType>{
    constructor(private map: Map<string,any> = new Map()){
        super(new MemoryDatastore(map))
    }
    keys = function(){
        return this.map.keys()
    }
}

export class MemoryDatastore implements IDataStore{
    constructor(public map: Map<string,any> = new Map()){
    }
    async has(key: string) {
        return this.map.has(key)
    }
    async get(key: string) {
        return this.map.get(key)
    }
    async put(key: string, record: any) {
        this.map.set(key, record)
    }
    async delete(key: string) {
        this.map.delete(key)
    }
    
}