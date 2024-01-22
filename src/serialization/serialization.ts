import { IMashfile, IMashfileSerializer } from "src/interfaces/interfaces.js";
import { File, FileMetadata, MashfileType, Root, TreeMetadata } from "../entities/entities.js";

export function convertPayloadFromStringAsType<Type>(mashfile: IMashfile, create: () => Type): Type{
    const payload = convertPayloadFromString(mashfile)
    return Object.assign(create(), payload)
}

export function convertPayloadFromString(mashfile: IMashfile){
    if (typeof mashfile.payload == "string"){
        const serial = serializer.get(mashfile.type)
        if (!!serial){
            return serial.deserialize(mashfile)
        }
       
        try{
            return JSON.parse(mashfile.payload)
        }
        catch(error){
            return mashfile.payload
        }
    }
    else {
        return mashfile.payload
    }
}

export function convertPayloadToString(mashfile: IMashfile){
    const pre = mashfile.payload
    if (typeof pre === 'object'){
        return JSON.stringify(pre, null, 0)
    }
    if (typeof pre === 'string'){
        return pre
    }
    if (!!pre) {
        return pre.toString()
    }
    return ''
}

export function convertPayloadStringToType(payloadString: string, initializedInstance?: any){
    if(!initializedInstance){
        return payloadString;
    }
    const payloadObject = SerializationHelper.toInstance(initializedInstance, payloadString)
    return payloadObject
}

class SerializationHelper {
    static toInstance<T>(obj: T, json: string) : T {
        var jsonObj = JSON.parse(json);

        if (typeof obj["fromJSON"] === "function") {
            obj["fromJSON"](jsonObj);
        }
        else {
            for (var propName in jsonObj) {
                obj[propName] = jsonObj[propName]
            }
        }

        return obj;
    }
}

export class SerializationStore {
    constructor(private store: Map<string, IMashfileSerializer> = new Map()){
        const rootSerializer = new RootMashfileSerializer()
        const fileSerializer = new FileMashfileSerializer()
        this.add(MashfileType.root,rootSerializer)
        this.add(MashfileType.file, fileSerializer)
    }

    get(key: string): IMashfileSerializer{
        return this.store[key] || null
    }
    add(key: string, value: IMashfileSerializer){
        this.store[key] = value
    }
 }

 export abstract class MashfileSerializer<DeserializedType> implements IMashfileSerializer{
     abstract serialize: (mashfile: IMashfile) => string;
     abstract deserialize: (mashfile: IMashfile) => DeserializedType;  
 }

 export class FileMashfileSerializer extends MashfileSerializer<File>{
    serialize = convertPayloadToString
    deserialize = (mashfile: IMashfile) => convertPayloadStringToType(mashfile.payload, new FileMetadata())
 }

 export class RootMashfileSerializer extends MashfileSerializer<Root>{
    serialize = convertPayloadToString
    deserialize = (mashfile: IMashfile) => convertPayloadStringToType(mashfile.payload, new TreeMetadata())
 }

 export const serializer = new SerializationStore()

 export const addSerializer = (mashfileType: string, mashfileSerializer: IMashfileSerializer) => {
    serializer.add(mashfileType, mashfileSerializer)
 }