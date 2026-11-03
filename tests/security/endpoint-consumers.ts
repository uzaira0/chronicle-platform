// Extract executable requests, following imported builders and forwarding wrappers.
import { resolve } from 'node:path';
import ts from '../../chronicle-web/node_modules/typescript';

const filenames = Bun.argv.slice(2).map((name) => resolve(name));
const program = ts.createProgram(filenames, {
  target: ts.ScriptTarget.Latest,
  module: ts.ModuleKind.ESNext,
  moduleResolution: ts.ModuleResolutionKind.Bundler,
  jsx: ts.JsxEmit.Preserve,
  baseUrl: resolve(import.meta.dir, '../../chronicle-web'),
  paths: { '@/*': ['src/modern/*'] },
  skipLibCheck: true,
  types: [],
});
const checker = program.getTypeChecker();
const files = filenames.map((name) => {
  const file = program.getSourceFile(name);
  if (!file) throw new Error(`Cannot read executable request source: ${name}`);
  return file;
});
const calls: ts.CallExpression[] = [];
const requests: { method: string; path: string; callee: string }[] = [];
const failures = new Set<string>();
type Bindings = Map<ts.Node, ts.Node>;
type Callable = ts.FunctionDeclaration | ts.ArrowFunction | ts.FunctionExpression;
function isCallable(node: ts.Node): node is Callable {
  return ts.isFunctionDeclaration(node) || ts.isArrowFunction(node) || ts.isFunctionExpression(node);
}
function declaration(node: ts.Node): ts.Node | undefined {
  if (!ts.isIdentifier(node)) return undefined;
  let symbol = checker.getSymbolAtLocation(node);
  if (symbol && symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
  return symbol?.valueDeclaration ?? symbol?.declarations?.[0];
}
function unwrap(node: ts.Node | undefined, bindings: Bindings, seen = new Set<ts.Node>()): ts.Node | undefined {
  if (!node || seen.has(node)) return node;
  seen.add(node);
  if (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isSatisfiesExpression(node))
    return unwrap(node.expression, bindings, seen);
  if (ts.isIdentifier(node)) {
    const target = declaration(node);
    if (target && bindings.has(target)) return unwrap(bindings.get(target), bindings, seen);
    if (target && ts.isVariableDeclaration(target)) return unwrap(target.initializer, bindings, seen);
    if (target && ts.isFunctionDeclaration(target)) return target;
  }
  return node;
}
function values(node: ts.Node | undefined, bindings: Bindings, seen = new Set<ts.Node>()): string[] {
  node = unwrap(node, bindings);
  if (!node || seen.has(node)) return [];
  seen = new Set(seen).add(node);
  if (ts.isStringLiteralLike(node)) return [node.text];
  if (ts.isTemplateExpression(node)) return templateValues(node, bindings, seen);
  if (ts.isConditionalExpression(node))
    return [...values(node.whenTrue, bindings, seen), ...values(node.whenFalse, bindings, seen)];
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    return concatenatedValues(node, bindings, seen);
  }
  if (ts.isCallExpression(node)) {
    return callValues(node, bindings, seen);
  }
  if (isCallable(node)) return returnValues(node, bindings, seen);
  return [];
}
function templateValues(node: ts.TemplateExpression, bindings: Bindings, seen: Set<ts.Node>): string[] {
  let paths = [node.head.text];
  for (const span of node.templateSpans) {
    const alternatives = values(span.expression, bindings, seen);
    paths = paths.flatMap((path) =>
      (alternatives.length ? alternatives : ['{}']).map((part) => path + part + span.literal.text),
    );
  }
  return paths;
}
function concatenatedValues(node: ts.BinaryExpression, bindings: Bindings, seen: Set<ts.Node>): string[] {
  const left = values(node.left, bindings, seen);
  const right = values(node.right, bindings, seen);
  if (!left.length && !right.length) return [];
  return (left.length ? left : ['{}']).flatMap((a) => (right.length ? right : ['{}']).map((b) => a + b));
}
function bindArguments(
  target: Callable | ts.SignatureDeclaration,
  call: ts.CallExpression,
  bindings: Bindings,
): Bindings {
  const bound = new Map(bindings);
  target.parameters.forEach((parameter, index) => {
    if (call.arguments[index]) bound.set(parameter, call.arguments[index]);
  });
  return bound;
}
function callValues(node: ts.CallExpression, bindings: Bindings, seen: Set<ts.Node>): string[] {
  if (ts.isIdentifier(node.expression) && node.expression.text === 'encodeURIComponent')
    return values(node.arguments[0], bindings, seen);
  const target = unwrap(node.expression, bindings);
  if (!target || !isCallable(target)) return [];
  return values(target, bindArguments(target, node, bindings), seen);
}
function returnValues(node: Callable, bindings: Bindings, seen: Set<ts.Node>): string[] {
  if (!node.body) return [];
  if (!ts.isBlock(node.body)) return values(node.body, bindings, seen);
  const alternatives: string[] = [];
  function returns(member: ts.Node) {
    if (ts.isReturnStatement(member)) alternatives.push(...values(member.expression, bindings, seen));
    else if (!ts.isFunctionLike(member)) ts.forEachChild(member, returns);
  }
  ts.forEachChild(node.body, returns);
  return alternatives;
}
function property(node: ts.Node | undefined, name: string, bindings: Bindings): ts.Node | undefined {
  node = unwrap(node, bindings);
  if (!node || !ts.isObjectLiteralExpression(node)) return undefined;
  for (const item of [...node.properties].reverse()) {
    if (ts.isPropertyAssignment(item) && item.name.getText().replace(/^['"]|['"]$/g, '') === name)
      return item.initializer;
    if (ts.isShorthandPropertyAssignment(item) && item.name.text === name) return item.name;
    if (ts.isSpreadAssignment(item)) {
      const found = property(item.expression, name, bindings);
      if (found) return found;
    }
  }
  return undefined;
}
function record(
  node: ts.Node | undefined,
  init?: ts.Node,
  callee = 'baseQuery',
  bindings: Bindings = new Map(),
  seen = new Set<ts.Node>(),
) {
  if (!node) return;
  const resolved = unwrap(node, bindings);
  const object = resolved && ts.isObjectLiteralExpression(resolved) ? resolved : undefined;
  const url = object ? property(object, 'url', bindings) : node;
  const paths = values(url, bindings);
  if (
    paths.length &&
    paths.every((path) => path.startsWith('/') || path.includes('/chronicle/') || /^https?:\/\//.test(path))
  )
    return recordPaths(paths, object ?? init, bindings, callee);
  if (forwardParameter(resolved, bindings, seen, (bound, next) => record(node, init, callee, bound, next))) return;
  failures.add(`Unresolved request: ${node.getSourceFile().fileName}: ${node.getText()}`);
}
function recordPaths(paths: string[], object: ts.Node | undefined, bindings: Bindings, callee: string) {
  const method = property(object, 'method', bindings);
  const methods = values(method, bindings);
  if (method && !methods.length) {
    failures.add(`Unresolved request method: ${method.getSourceFile().fileName}: ${method.getText()}`);
    return;
  }
  for (const path of paths)
    for (const verb of methods.length ? methods : ['GET']) requests.push({ method: verb.toUpperCase(), path, callee });
}
function forwardParameter(
  resolved: ts.Node | undefined,
  bindings: Bindings,
  seen: Set<ts.Node>,
  visit: (bound: Bindings, next: Set<ts.Node>) => void,
): boolean {
  // A parameter is resolved at every invocation of its forwarding function, never silently omitted.
  const parameter = resolved && declaration(resolved);
  if (parameter && ts.isParameter(parameter) && !seen.has(parameter.parent)) {
    const owner = parameter.parent;
    const callers = calls.filter((call) => unwrap(call.expression, bindings) === owner);
    if (callers.length) {
      for (const call of callers) {
        const bound = bindArguments(owner, call, bindings);
        visit(bound, new Set(seen).add(owner));
      }
      return true;
    }
  }
  return false;
}
function recordForwardedHelper(call: ts.CallExpression, bindings: Bindings = new Map(), seen = new Set<ts.Node>()) {
  const fetcher = unwrap(call.arguments[0], bindings);
  if (fetcher && ts.isIdentifier(fetcher) && fetcher.text === 'baseQuery') {
    record(call.arguments[1], undefined, 'baseQuery', bindings);
    return;
  }
  // Follow the fetcher and URL together. A helper called with a non-network function is not a consumer.
  forwardParameter(fetcher, bindings, seen, (bound, next) => recordForwardedHelper(call, bound, next));
}
for (const file of files) {
  function index(node: ts.Node) {
    if (ts.isCallExpression(node)) calls.push(node);
    ts.forEachChild(node, index);
  }
  index(file);
}
for (const call of calls) {
  const callee = call.expression.getText();
  if (/^(?:fetch|fetchWithCsrf|fetchWithActivity|baseQuery|rawBaseQuery)$/.test(callee))
    record(call.arguments[0], call.arguments[1], callee);
  if (/^(?:readAllRows|readAllPages|readRevisionedResource)$/.test(callee)) recordForwardedHelper(call);
  if (/\.(?:mutation|query)$/.test(callee)) {
    const query = unwrap(property(call.arguments[0], 'query', new Map()), new Map());
    if (query && (ts.isArrowFunction(query) || ts.isFunctionExpression(query))) {
      if (!ts.isBlock(query.body)) record(query.body);
      else
        query.body.statements.filter(ts.isReturnStatement).forEach((item) => {
          record(item.expression);
        });
    }
  }
}
if (failures.size) {
  process.stderr.write(`${[...failures].join('\n')}\n`);
  process.exitCode = 1;
} else process.stdout.write(JSON.stringify(requests));
