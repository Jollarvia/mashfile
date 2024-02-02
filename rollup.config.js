import commonjs from '@rollup/plugin-commonjs';
import nodeResolve from '@rollup/plugin-node-resolve';
import globals from 'rollup-plugin-node-globals';
import builtins from 'rollup-plugin-node-builtins';
import typescript from '@rollup/plugin-typescript';

export default {
input: {
 browser: 'index.ts'
},
output: {
    dir: 'browser',
    format: 'cjs'
  },
  external: [ 'fs' ], // tells Rollup 'I know what I'm doing here'
  plugins: [
    typescript(),
    nodeResolve({ preferBuiltins: false }), // or `true`
    commonjs(),
    globals(),
    builtins()
  ]
}