import { enumToSet } from "src/utilities.js"

export function operator<IdType, ApplyType>(id: IdType, apply: () => ApplyType){
    return {id, apply}
}

export {operator as op}

export abstract class EnumOptionsResolver<EnumType extends string, ResolvedType>{
    enumToSet = enumToSet
    defaultResolver?: () => ResolvedType = null
    abstract resolveType: (t: EnumType) => ResolvedType
    enum: Set<string>
    resolveWithFactory = function(t: (() => ResolvedType)|string){
        if (typeof(t) == "function"){
            return (t as any)() as ResolvedType
        }
        
        return this.resolve(t)
    }

    resolve = function(t: string): ResolvedType{
        if ((t == "default" || !t) && !!this.defaultResolver){
            return this.defaultResolver()
        }
        if (!this.enum.has(t)){
            throw "unknown enum type passed: " + t
        }
        
        return this.resolveType(t)
    }

}