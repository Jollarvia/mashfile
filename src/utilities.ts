export function createVoidIterator<type>(): IterableIterator<type> {
  const iterator = {
    next() {
      return { done: true, value: undefined }
    },
  }
  return createVoidIterator()
}

export function voidIteratorFunction<type>(){
  return createVoidIterator<type>()
}

export function enumToSet(obj){
  const map = Object.keys(obj)
  return new Set(map)
}