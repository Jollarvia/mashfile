import { expect } from "chai";
import { EnumOptionsResolver } from "src/configuration/options.js";

enum TestEnum{
    a="a",
    b="b",
    c="c",
    default="default"
}
    
class TestOptionsResolve extends EnumOptionsResolver<TestEnum, string>{
    enum = this.enumToSet(TestEnum)
    resolveType = function(t: TestEnum){
        return t
    }

}

describe("EnumOptionsResolver", () => {
    const resolver = new TestOptionsResolve()
    describe("resolve", () => {
        it("should resolve enum type", () => {
            const result = resolver.resolve("a")
            expect(result).to.equal("a")
        })
        it("should resolve default type", () => {
            const result = resolver.resolve("default")
            expect(result).to.equal("default")
        })
        it("should resolve error on unknown type", () => {
            expect(() => resolver.resolve("excalibur")).to.throw
        })
    })
    describe("resolveWithFactory", () => {
        it("should resolve with factory", () => {
            const result = resolver.resolveWithFactory(() => "x")
            expect(result).to.equal("x")
        })
    })
})