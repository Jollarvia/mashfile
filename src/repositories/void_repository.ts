import { IDataStore, IRepository, StandardEncryptionManagerOptions, StandardSignatureManagerOptions } from "src/interfaces/interfaces.js";
import { Table } from "./common/repository.js";
import { voidIteratorFunction } from "src/utilities.js";

export class VoidRepository implements IRepository{
    key = new VoidTable<StandardEncryptionManagerOptions>()
    signature = new VoidTable<StandardSignatureManagerOptions>()
}

export class VoidTable<RecordType> extends Table<RecordType>{
    constructor(){
        super(null)
    }
    keys = voidIteratorFunction
}

export class VoidDataStore implements IDataStore{
    has = async function(){
        return false
    }
    get = async function(key: string) {
        return null
    }
    put = async function(key: string, record: any){

    }
    delete = async function(key: string){

    }
}