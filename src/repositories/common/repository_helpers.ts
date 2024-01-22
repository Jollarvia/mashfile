import { EnumOptionsResolver } from "src/configuration/options.js";
import { MemoryRepository } from "../memory_repository.js";
import { VoidRepository } from "../void_repository.js";
import { IRepository } from "src/interfaces/interfaces.js";

export enum RepositoryTypes{
    unknown = "unknown",
    void = "void",
    memory = "memory"
}

function resolveRepositoryInternal(repositoryName: RepositoryTypes): IRepository{
    switch(repositoryName){
        case RepositoryTypes.void:
            return new VoidRepository()
        case RepositoryTypes.memory:
            return new MemoryRepository()
        default:
            throw "unknown repository: " + repositoryName
    }
}

export class RepositoryResolver extends EnumOptionsResolver<RepositoryTypes, IRepository>{
    enum = this.enumToSet(RepositoryTypes)
    resolveType = resolveRepositoryInternal
    defaultResolver = () => new VoidRepository()
}