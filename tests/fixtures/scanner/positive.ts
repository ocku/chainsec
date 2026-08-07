declare const encoded: string;

const decoded: string = globalThis.atob(encoded);
const marker: string = String.fromCharCode(79, 75);
const run: (name: string) => string = Function("name", "return `hello ${name}`") as (name: string) => string;
eval(run(marker));
