import { IDataStore, ITable } from "src/interfaces/interfaces.js";


export abstract class Table<RecordType> implements ITable<RecordType>{
    constructor(private datastore: IDataStore){

    }
    abstract keys: () => IterableIterator<string>
    
    async get(key: string){
        return await this.datastore.get(key) as RecordType
    }
    async put(key: string, record: RecordType){
        return await this.datastore.put(key, record)
    }
    async delete(key: string){
        return await this.datastore.delete(key)
    }

    async has(key: string){
        return await this.datastore.has(key)
    }
}