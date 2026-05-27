import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { spawn } from "node:child_process";

const SENTINEL_URL = process.env.SENTINEL_URL ?? "http://127.0.0.1:9800";
const SENTINEL_COMMAND = process.env.SENTINEL_COMMAND ?? "sentinel";
const SENTINEL_CONFIG = process.env.SENTINEL_CONFIG;

type Transition = { to: string; trigger: string; guards?: Array<{ field: string; pattern: string }> };
type SentinelState =
  | "idle"
  | "thinking"
  | "planning"
  | "reading"
  | "writing"
  | "testing"
  | "committing"
  | "pushing"
  | "developing"
  | "reviewing";

type InferredState = { state: SentinelState; reason: string };

async function post(path: string, body: unknown, signal?: AbortSignal) {
  const response = await fetch(`${SENTINEL_URL}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    signal,
  });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json() as Promise<any>;
}

async function get(path: string, signal?: AbortSignal) {
  const response = await fetch(`${SENTINEL_URL}${path}`, { signal });
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json() as Promise<any>;
}

async function healthy(signal?: AbortSignal) {
  try {
    await get("/health", signal);
    return true;
  } catch {
    return false;
  }
}

function startSentinel() {
  const args = SENTINEL_CONFIG ? ["--config", SENTINEL_CONFIG, "start"] : ["start"];
  const child = spawn(SENTINEL_COMMAND, args, {
    detached: true,
    stdio: "ignore",
    windowsHide: true,
    shell: process.platform === "win32",
  });
  child.unref();
  return true;
}

function formatTransitions(transitions: Transition[] = []) {
  if (transitions.length === 0) return "none";
  return transitions
    .map((t) => {
      const guards = t.guards?.length
        ? ` if ${t.guards.map((g) => `${g.field}~${g.pattern}`).join(" & ")}`
        : "";
      return `${t.to} (${t.trigger}${guards})`;
    })
    .join(", ");
}

function formatToolList(tools: string[] = [], max = 6) {
  if (tools.length <= max) return tools.join(", ") || "none";
  return `${tools.slice(0, max).join(", ")} +${tools.length - max} more`;
}

function inferStateFromText(text: string): InferredState {
  const normalized = text.toLowerCase();
  if (/\b(push|publish|upload)\b.*\b(commit|branch|remote|origin)\b|\bgit\s+push\b/.test(normalized)) {
    return { state: "pushing", reason: "user context mentions pushing" };
  }
  if (/\b(commit|committing)\b|\bgit\s+commit\b/.test(normalized)) {
    return { state: "committing", reason: "user context mentions committing" };
  }
  if (/\b(test|tests|testing|pytest|cargo\s+test|npm\s+test|pnpm\s+test)\b/.test(normalized)) {
    return { state: "testing", reason: "user context mentions testing" };
  }
  if (/\b(review|reviewing|audit|inspect|investigate|analy[sz]e|look into)\b/.test(normalized)) {
    return { state: "reviewing", reason: "user context requests review/inspection" };
  }
  if (
    /\b(plan|planning|design|approach|outline|think through)\b/.test(normalized) ||
    /\b(no code|read[- ]only|don'?t (edit|change|write|modify)|without (editing|changing|writing|modifying))\b/.test(normalized)
  ) {
    return { state: "planning", reason: "user context requests planning" };
  }
  if (/\b(read|show|open|find|search|grep|list|status|diff|log)\b/.test(normalized)) {
    return { state: "reading", reason: "user context requests reading" };
  }
  if (/\b(write|edit|change|modify|implement|fix|add|remove|refactor|update)\b/.test(normalized)) {
    return { state: "writing", reason: "user context requests writing" };
  }
  return { state: "thinking", reason: "user context requires thinking" };
}

function isTestCommand(command: string) {
  return /\b(npm|pnpm|yarn|bun)\s+(run\s+)?test\b|\b(pytest|cargo\s+test|go\s+test|dotnet\s+test|mvn\s+test|gradle\s+test)\b/.test(command);
}

function isCommitCommand(command: string) {
  return /^\s*git\s+commit\b/.test(command);
}

function isPushCommand(command: string) {
  return /^\s*git\s+push\b/.test(command);
}

function isReadOnlyBash(command: string) {
  return /^\s*(ls|dir|pwd|echo|cat|type|find|rg|grep|git\s+(status|diff|log|show|branch)|npm\s+ls|pnpm\s+ls)\b/.test(command);
}

function inferStateFromToolCall(toolName: string, input: any): InferredState | undefined {
  if (toolName === "bash" && typeof input?.command === "string") {
    const command = input.command;
    if (isTestCommand(command)) return { state: "testing", reason: "bash command runs tests" };
    if (isCommitCommand(command)) return { state: "committing", reason: "bash command creates commit" };
    if (isPushCommand(command)) return { state: "pushing", reason: "bash command pushes commits" };
    if (isReadOnlyBash(command)) return { state: "reading", reason: "bash command is read-only" };
    return { state: "writing", reason: "bash command may change files" };
  }

  if (toolName === "read") return { state: "reading", reason: "read tool called" };
  if (["edit", "write"].includes(toolName)) return { state: "writing", reason: `${toolName} tool called` };
  if (toolName === "multi_tool_use.parallel") return { state: "reading", reason: "parallel tool call started" };
  return undefined;
}

export default function (pi: ExtensionAPI) {
  let warnedDown = false;
  let started = false;
  // Keep the status-line indicator on by default. The larger widget is opt-in
  // so the same Sentinel state is not rendered twice in the normal TUI.
  let widgetVisible = false;
  let verboseWidget = false;
  let lastDecision = "startup";
  let lastTool = "none";
  let nextAgentState: InferredState = { state: "thinking", reason: "startup" };
  let refreshTimer: ReturnType<typeof setInterval> | undefined;

  function sessionPayload(ctx: ExtensionContext, reason: string) {
    const sessionFile = ctx.sessionManager.getSessionFile();
    return {
      source: "pi",
      reason,
      session_file: sessionFile,
      session_id: sessionFile ?? `${ctx.cwd}:ephemeral`,
      cwd: ctx.cwd,
    };
  }

  async function registerSession(ctx: ExtensionContext, reason: string) {
    await post("/session", sessionPayload(ctx, reason), ctx.signal);
  }

  async function endSession(ctx: ExtensionContext, reason: string) {
    await post("/session/end", sessionPayload(ctx, reason), ctx.signal);
  }

  async function transition(ctx: ExtensionContext, toState: string, reason: string) {
    try {
      const state = await get("/state", ctx.signal);
      if (state.current === toState) return;
      await post("/transition", { to_state: toState, reason }, ctx.signal);
    } catch {
      // Sentinel automation is fail-open; never break pi because the sidecar is down or lacks a state.
    }
  }

  async function refreshUi(ctx: ExtensionContext, notify = false) {
    try {
      const [health, state] = await Promise.all([get("/health", ctx.signal), get("/state", ctx.signal)]);
      warnedDown = false;
      const chain = health.chain_length ?? "?";
      ctx.ui.setStatus("sentinel", `🛡 ${state.current} · ${chain}r`);

      if (widgetVisible) {
        const lines = verboseWidget
          ? [
              `🛡 ${state.current} · ${chain}r · ${Math.floor((health.uptime ?? 0) / 60)}m`,
              `last ${lastDecision}:${lastTool}`,
              `allow ${formatToolList(state.allowed_tools, 6)}`,
              `next ${formatTransitions(state.available_transitions)}`,
            ]
          : [`🛡 ${state.current} · ${chain}r · ${lastDecision}:${lastTool}`];
        ctx.ui.setWidget("sentinel", lines, { placement: "belowEditor" });
      } else {
        ctx.ui.setWidget("sentinel", undefined);
      }

      if (notify) ctx.ui.notify(`Sentinel: ${state.current}, ${chain} receipts`, "info");
    } catch (error) {
      ctx.ui.setStatus("sentinel", "🛡 off");
      if (widgetVisible) {
        ctx.ui.setWidget("sentinel", [`🛡 off · fail-open · ${SENTINEL_URL}`], { placement: "belowEditor" });
      }
      if (notify) ctx.ui.notify(`Sentinel unavailable: ${String(error)}`, "error");
    }
  }

  pi.on("session_start", async (event, ctx) => {
    if (!(await healthy())) {
      started = startSentinel();
      if (started) await new Promise((resolve) => setTimeout(resolve, 800));
    }

    if (await healthy()) {
      warnedDown = false;
      try {
        await registerSession(ctx, event.reason);
      } catch (error) {
        ctx.ui.notify(`Sentinel session log failed: ${String(error)}`, "warning");
      }
    } else {
      ctx.ui.notify("Sentinel off; fail-open.", "warning");
      warnedDown = true;
    }

    await refreshUi(ctx);
    if (refreshTimer) clearInterval(refreshTimer);
    refreshTimer = setInterval(() => void refreshUi(ctx), 10_000);
  });

  pi.on("session_shutdown", async (event, ctx) => {
    if (refreshTimer) clearInterval(refreshTimer);
    refreshTimer = undefined;
    nextAgentState = { state: "thinking", reason: "session shutdown" };
    if (["quit", "new", "resume", "fork"].includes(event.reason)) {
      try {
        await endSession(ctx, event.reason);
      } catch {
        // Best-effort: session shutdown should not block pi teardown/switching.
      }
    }
    ctx.ui.setWidget("sentinel", undefined);
    ctx.ui.setStatus("sentinel", undefined);
  });

  pi.on("input", async (event) => {
    nextAgentState = inferStateFromText(event.text);
    return { action: "continue" };
  });

  pi.on("before_agent_start", async (event) => {
    // Re-check after input transforms/templates/skills so expanded context drives the state.
    nextAgentState = inferStateFromText(event.prompt);
  });

  pi.on("agent_start", async (_event, ctx) => {
    await transition(ctx, nextAgentState.state, `pi agent started: ${nextAgentState.reason}`);
    await refreshUi(ctx);
  });

  pi.on("agent_end", async (_event, ctx) => {
    nextAgentState = { state: "thinking", reason: "agent ended" };
    await transition(ctx, "idle", "pi agent ended");
    await refreshUi(ctx);
  });

  pi.on("tool_call", async (event, ctx) => {
    lastTool = event.toolName;

    const inferred = inferStateFromToolCall(event.toolName, event.input);
    if (inferred) {
      await transition(ctx, inferred.state, `pi tool context: ${inferred.reason}`);
      await refreshUi(ctx);
    }

    try {
      const result = await post("/gate", {
        source: "pi",
        tool_name: event.toolName,
        tool_input: event.input,
        tool_call_id: event.toolCallId,
      }, ctx.signal);

      lastDecision = result?.decision ?? "allow";
      await refreshUi(ctx);
      if (result?.decision === "deny") {
        return { block: true, reason: result.reason ?? "Blocked by Sentinel" };
      }
    } catch (error) {
      lastDecision = "fail-open";
      await refreshUi(ctx);
      if (!warnedDown) {
        ctx.ui.notify(`Sentinel off; fail-open (${String(error)})`, "warning");
        warnedDown = true;
      }
    }
  });

  pi.on("tool_result", async (event, ctx) => {
    try {
      await post("/receipt", {
        source: "pi",
        tool_name: event.toolName,
        tool_input: event.input,
        tool_call_id: event.toolCallId,
        tool_response: {
          content: event.content,
          details: event.details,
          isError: event.isError,
        },
      }, ctx.signal);
      await refreshUi(ctx);
    } catch {
      // Receipt generation is best-effort/fail-open so Sentinel never bricks pi.
    }
  });

  pi.registerCommand("sentinel-state", {
    description: "Show Sentinel state",
    handler: async (_args, ctx) => {
      try {
        const [health, state] = await Promise.all([get("/health"), get("/state")]);
        ctx.ui.notify(
          [
            `🛡 ${state.current} · ${health.chain_length}r · ${Math.floor((health.uptime ?? 0) / 60)}m`,
            `allow ${state.allowed_tools.join(", ")}`,
            `next ${formatTransitions(state.available_transitions)}`,
          ].join("\n"),
          "info",
        );
        await refreshUi(ctx);
      } catch (error) {
        ctx.ui.notify(`Sentinel unavailable: ${String(error)}`, "error");
      }
    },
  });

  pi.registerCommand("sentinel-ui", {
    description: "Control Sentinel widget",
    handler: async (args, ctx) => {
      const action = args.trim().toLowerCase() || "toggle";
      if (action === "on") widgetVisible = true;
      else if (action === "off") widgetVisible = false;
      else if (action === "toggle") widgetVisible = !widgetVisible;
      else if (action === "verbose") { widgetVisible = true; verboseWidget = true; }
      else if (action === "compact") { widgetVisible = true; verboseWidget = false; }
      else if (action !== "refresh") {
        ctx.ui.notify("Usage: /sentinel-ui <on|off|toggle|verbose|compact|refresh>", "warning");
        return;
      }
      await refreshUi(ctx, action === "refresh");
    },
  });

  pi.registerCommand("sentinel-transition", {
    description: "Transition Sentinel state",
    handler: async (args, ctx) => {
      const toState = args.trim();
      if (!toState) {
        ctx.ui.notify("Usage: /sentinel-transition <state>", "warning");
        return;
      }
      try {
        const state = await post("/transition", { to_state: toState, reason: "pi command" });
        ctx.ui.notify(`🛡 ${state.previous} → ${state.current}`, "info");
        await refreshUi(ctx);
      } catch (error) {
        ctx.ui.notify(`Sentinel transition failed: ${String(error)}`, "error");
      }
    },
  });
}
