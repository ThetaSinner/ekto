import { resolve } from 'node:path';

export default {
  build: {
    lib: {
      entry: resolve(__dirname, "src/index.ts"),
      formats: ['es'],
    }
  }
}
