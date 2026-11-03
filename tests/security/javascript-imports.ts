// Parse module references without resolving or executing repository code.
const parser = new Bun.Transpiler({ loader: 'js' });
const modules: { path: string; imports: string[] }[] = [];
for (const path of Bun.argv.slice(2)) {
  modules.push({ path, imports: parser.scanImports(await Bun.file(path).text()).map((entry) => entry.path) });
}
process.stdout.write(JSON.stringify(modules));
