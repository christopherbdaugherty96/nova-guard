/**
 * Port of OpenClaw's skill code-safety rules, the ones `openclaw security
 * audit --deep` applies to installed skills: src/skills/security/scanner.ts
 * and scan-evidence.ts at b8324c64acf5979602711163cb4b5c01ea557388
 * (MIT License, Copyright (c) 2026 OpenClaw Foundation).
 *
 * Rules, patterns, severities, context windows, and the per-rule finding cap
 * are copied unchanged. One deliberate difference: OpenClaw attaches the
 * matched line (redacted only for recognized credentials) as evidence;
 * nova-guard keeps only the rule, severity, and line number, so no file
 * content can reach a report.
 */
import path from "node:path";

export type SkillRuleSeverity = "warn" | "critical";

export interface SkillRuleHit {
  ruleId: string;
  severity: SkillRuleSeverity;
  line: number;
  /** Only on a "<rule>-truncated" hit: matches dropped after the cap. */
  omitted?: number;
}

interface LineRule {
  ruleId: string;
  severity: SkillRuleSeverity;
  pattern: RegExp;
  /** If set, the rule only fires when the *full source* also matches this pattern. */
  requiresContext?: RegExp;
}

interface SourceRule extends LineRule {
  /** If set, secondary context must be within this many lines of the primary match. */
  requiresContextWindowLines?: number;
}

const scannableExtensions = new Set([".js", ".ts", ".mjs", ".cjs", ".mts", ".cts", ".jsx", ".tsx"]);
const maxLineRuleFindingsPerRule = 32;

export function isScannable(filePath: string): boolean {
  return scannableExtensions.has(path.extname(filePath).toLowerCase());
}

const lineRules: LineRule[] = [
  {
    ruleId: "dangerous-exec",
    severity: "critical",
    // Capture the method in group 1 for direct calls and group 2 for computed calls.
    pattern:
      /\b(exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(|["'](exec|execSync|spawn|spawnSync|execFile|execFileSync)["']\s*\]\s*\(/,
    requiresContext: /child_process/,
  },
  {
    ruleId: "dynamic-code-execution",
    severity: "critical",
    pattern: /\beval\s*\(|new\s+Function\s*\(/,
  },
  {
    ruleId: "crypto-mining",
    severity: "critical",
    pattern: /stratum\+tcp|stratum\+ssl|coinhive|cryptonight|xmrig/i,
  },
  {
    ruleId: "suspicious-network",
    severity: "warn",
    pattern: /new\s+WebSocket\s*\(\s*["']wss?:\/\/[^"']*:(\d+)/,
  },
];

const standardPorts = new Set([80, 443, 8080, 8443, 3000]);
const networkSendContextPattern = /\bfetch\s*\(|\bpost\s*\(|\.\s*post\s*\(|http\.request\s*\(/i;

const sourceRules: SourceRule[] = [
  {
    ruleId: "potential-exfiltration",
    severity: "warn",
    pattern: /readFileSync|readFile/,
    requiresContext: networkSendContextPattern,
  },
  {
    ruleId: "obfuscated-code",
    severity: "warn",
    pattern: /(\\x[0-9a-fA-F]{2}){6,}/,
  },
  {
    ruleId: "obfuscated-code",
    severity: "warn",
    pattern: /(?:atob|Buffer\.from)\s*\(\s*["'][A-Za-z0-9+/=]{200,}["']/,
  },
  {
    ruleId: "env-harvesting",
    severity: "critical",
    pattern: /process\.env/,
    requiresContext: networkSendContextPattern,
    requiresContextWindowLines: 8,
  },
];

const literalSecretPattern =
  /\b(?:sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|AIza[0-9A-Za-z_-]{35})(?![A-Za-z0-9_-])|-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----\r?\n(?=(?:[A-Za-z0-9+/=]\r?\n?){48,}-----END \1-----)(?:[A-Za-z0-9+/=]+\r?\n)+-----END \1-----/;

const skillContentRules: SourceRule[] = [
  { ruleId: "literal-secret", severity: "critical", pattern: literalSecretPattern },
  {
    ruleId: "shell-pipe-to-shell",
    severity: "critical",
    pattern: /\b(curl|wget)\b[^|\n]{0,120}\|\s*(sh|bash|zsh)\b/i,
  },
  {
    ruleId: "secret-exfiltration",
    severity: "critical",
    pattern: /\b(process\.env|env)\b.{0,80}\b(fetch|curl|wget|http|https)\b/i,
  },
  {
    ruleId: "destructive-delete",
    severity: "warn",
    pattern: /\brm\s+-rf\s+(\/|\$HOME|~|\.)/i,
  },
  {
    ruleId: "unsafe-permissions",
    severity: "warn",
    pattern: /\bchmod\s+(-R\s+)?777\b/i,
  },
];

const childProcessExecMethods = new Set(["exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync"]);

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Only imports/requires establish provenance; unrelated aliases must not match.
function collectChildProcessBindings(source: string): {
  methodAliases: Set<string>;
  namespaceAliases: Set<string>;
} {
  const methodAliases = new Set<string>();
  const namespaceAliases = new Set<string>();
  const esmNamed = /\bimport\s*\{([^}]*)\}\s*from\s*["'](?:node:)?child_process["']/g;
  const esmDefault = /\bimport\s+(\w+)\s+from\s*["'](?:node:)?child_process["']/g;
  const esmNamespace = /\bimport\s*\*\s*as\s+(\w+)\s+from\s*["'](?:node:)?child_process["']/g;
  const cjsDestructured =
    /\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\(\s*["'](?:node:)?child_process["']\s*\)/g;
  const cjsNamespace =
    /\b(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*["'](?:node:)?child_process["']\s*\)/g;

  const collectSpecifiers = (specText: string): void => {
    for (const rawSpec of specText.split(",")) {
      const spec = rawSpec.trim();
      // Renamed binding: `spawn as launch` (ESM) or `exec: run` (CJS)
      const asMatch = spec.match(/^(\w+)\s+(?:as)\s+(\w+)$/) ?? spec.match(/^(\w+)\s*:\s*(\w+)$/);
      if (asMatch?.[1] && asMatch[2] && childProcessExecMethods.has(asMatch[1])) {
        methodAliases.add(asMatch[2]);
      }
    }
  };
  for (const pattern of [esmNamed, cjsDestructured]) {
    for (const match of source.matchAll(pattern)) collectSpecifiers(match[1] ?? "");
  }
  for (const pattern of [esmDefault, esmNamespace, cjsNamespace]) {
    for (const match of source.matchAll(pattern)) {
      if (match[1]) namespaceAliases.add(match[1]);
    }
  }
  return { methodAliases, namespaceAliases };
}

// Report every standalone alias call in source order, excluding object members.
function matchAliasedChildProcessCalls(line: string, methodAliases: Set<string>): number[] {
  const calls: number[] = [];
  for (const alias of methodAliases) {
    const pattern = new RegExp(`(?<![\\w.])${escapeRegExp(alias)}\\s*\\(`, "g");
    for (const callMatch of line.matchAll(pattern)) calls.push(callMatch.index);
  }
  return calls.sort((a, b) => a - b);
}

// Retain the conventional child_process names alongside proven namespace aliases.
const literalNamespaceReceivers = new Set(["cp", "childProcess", "child_process"]);

function isBenignMemberExecMatch(line: string, match: RegExpMatchArray, namespaceAliases: Set<string>): boolean {
  // group 1 = direct call command, group 2 = computed-member command.
  const command = match[1] ?? match[2];
  if (!command) return false;
  const matchIndex = match.index ?? 0;
  const charAtMatch = line[matchIndex];
  let receiver: string | undefined;
  // Computed calls require a known receiver for every watched method;
  // direct calls require it only for .exec, excluding RegExp.exec.
  if (charAtMatch === '"' || charAtMatch === "'") {
    receiver = line.slice(0, matchIndex).match(/(\w+)\s*\[\s*$/)?.[1];
  } else if (command === "exec" && matchIndex > 0 && line[matchIndex - 1] === ".") {
    receiver = line.slice(0, matchIndex - 1).match(/(\w+)\s*$/)?.[1];
  } else {
    return false;
  }
  return !receiver || (!namespaceAliases.has(receiver) && !literalNamespaceReceivers.has(receiver));
}

function stripCommentsForHeuristics(source: string): string {
  let stripped = "";
  let quote: "'" | '"' | "`" | null = null;
  let escaped = false;
  let inBlockComment = false;
  for (let i = 0; i < source.length; i++) {
    const ch = source[i] ?? "";
    const next = source[i + 1] ?? "";
    if (inBlockComment) {
      if (ch === "*" && next === "/") {
        inBlockComment = false;
        i++;
        continue;
      }
      if (ch === "\n") stripped += "\n";
      continue;
    }
    if (quote) {
      stripped += ch;
      if (escaped) {
        escaped = false;
      } else if (ch === "\\") {
        escaped = true;
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }
    if (ch === "'" || ch === '"' || ch === "`") {
      quote = ch;
      stripped += ch;
      continue;
    }
    if (ch === "/" && next === "/") {
      while (i < source.length && source[i] !== "\n") i++;
      if (source[i] === "\n") stripped += "\n";
      continue;
    }
    if (ch === "/" && next === "*") {
      inBlockComment = true;
      i++;
      continue;
    }
    stripped += ch;
  }
  return stripped;
}

function findSourceRuleLine(rule: SourceRule, source: string, lines: string[]): number | null {
  const sourceMatch = rule.pattern.exec(source);
  if (!sourceMatch) return null;
  if (rule.requiresContext && !rule.requiresContext.test(source)) return null;
  for (let i = 0; i < lines.length; i++) {
    if (!rule.pattern.test(lines[i] ?? "")) continue;
    if (rule.requiresContext && rule.requiresContextWindowLines !== undefined) {
      const start = Math.max(0, i - rule.requiresContextWindowLines);
      const end = Math.min(lines.length, i + rule.requiresContextWindowLines + 1);
      if (!rule.requiresContext.test(lines.slice(start, end).join("\n"))) continue;
    }
    return i + 1;
  }
  if (rule.requiresContextWindowLines !== undefined) return null;
  // Multiline rules cannot match any one line; report where the match starts.
  let line = 1;
  for (let i = 0; i < sourceMatch.index; i++) {
    if (source.charCodeAt(i) === 10) line += 1;
  }
  return line;
}

function scanSourceRules(rules: readonly SourceRule[], source: string): SkillRuleHit[] {
  const hits: SkillRuleHit[] = [];
  const lines = source.split("\n");
  for (const rule of rules) {
    const line = findSourceRuleLine(rule, source, lines);
    if (line !== null) hits.push({ ruleId: rule.ruleId, severity: rule.severity, line });
  }
  return hits;
}

/** OpenClaw's rules for script files (and, in the audit, SKILL.md too). */
export function scanSource(source: string): SkillRuleHit[] {
  const hits: SkillRuleHit[] = [];
  const lines = source.split("\n");
  const heuristicSource = stripCommentsForHeuristics(source);
  const { methodAliases, namespaceAliases } = collectChildProcessBindings(heuristicSource);

  for (const rule of lineRules) {
    if (rule.requiresContext && !rule.requiresContext.test(source)) continue;
    let accepted = 0;
    let omitted = 0;
    let lastOmittedLine: number | undefined;
    const add = (lineNumber: number): void => {
      if (accepted >= maxLineRuleFindingsPerRule) {
        omitted += 1;
        lastOmittedLine = lineNumber;
        return;
      }
      hits.push({ ruleId: rule.ruleId, severity: rule.severity, line: lineNumber });
      accepted += 1;
    };
    const global = new RegExp(rule.pattern.source, rule.pattern.flags.includes("g") ? rule.pattern.flags : `${rule.pattern.flags}g`);
    for (const [i, line] of lines.entries()) {
      const literalDangerousExecIndexes = new Set<number>();
      for (const match of line.matchAll(global)) {
        if (rule.ruleId === "dangerous-exec" && isBenignMemberExecMatch(line, match, namespaceAliases)) continue;
        if (rule.ruleId === "suspicious-network" && standardPorts.has(Number.parseInt(match[1] ?? "", 10))) continue;
        add(i + 1);
        if (rule.ruleId === "dangerous-exec") literalDangerousExecIndexes.add(match.index ?? -1);
      }
      // Aliases follow literal matches; don't emit a call twice if both patterns match.
      if (rule.ruleId === "dangerous-exec" && methodAliases.size > 0) {
        for (const index of matchAliasedChildProcessCalls(line, methodAliases)) {
          if (!literalDangerousExecIndexes.has(index)) add(i + 1);
        }
      }
    }
    if (lastOmittedLine !== undefined) {
      hits.push({ ruleId: `${rule.ruleId}-truncated`, severity: rule.severity, line: lastOmittedLine, omitted });
    }
  }

  hits.push(...scanSourceRules(sourceRules, heuristicSource));
  return hits;
}

/** OpenClaw's rules for skill text (SKILL.md). */
export function scanSkillContent(content: string): SkillRuleHit[] {
  return scanSourceRules(skillContentRules, content);
}
