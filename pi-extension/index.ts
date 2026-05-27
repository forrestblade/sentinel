import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { spawn } from "node:child_process";

const SENTINEL_URL = process.env.SENTINEL_URL ?? "http://127.0.0.1:9800";
const SENTINEL_COMMAND = process.env.SENTINEL_COMMAND ?? "sentinel";
const SENTINEL_CONFIG = process.env.SENTINEL_CONFIG;

type Transition = { to: string; trigger: string; guards?: Array<{ field: string; pattern: string }> };

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

function looksLikePlanningRequest(text: string) {
  const normalized = text.toLowerCase();
  return (
    /\b(plan|planning|design|approach|outline|review|inspect|investigate|analy[sz]e|think through|look into)\b/.test(normalized) ||
    /\b(no code|read[- ]only|don'?t (edit|change|write|modify)|without (editing|changing|writing|modifying))\b/.test(normalized)
  );
}

function isTestCommand(command: string) {
  return /\b(npm|pnpm|yarn|bun)\s+(run\s+)?test\b|\b(pytest|cargo\s+test|go\s+test|dotnet\s+test|mvn\s+test|gradle\s+test)\b/.test(command);
}

function isReadOnlyBash(command: string) {
  return /^\s*(ls|dir|pwd|echo|cat|type|find|rg|grep|git\s+(status|diff|log|show|branch)|npm\s+ls|pnpm\s+ls)\b/.test(command);
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
  let nextAgentState: "planning" | "developing" = "developing";
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
    nextAgentState = "developing";
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
    nextAgentState = looksLikePlanningRequest(event.text) ? "planning" : "developing";
    return { action: "continue" };
  });

  pi.on("before_agent_start", async (event) => {
    // Re-check after input transforms/templates/skills so expanded planning prompts count too.
    nextAgentState = looksLikePlanningRequest(event.prompt) ? "planning" : nextAgentState;
  });

  pi.on("agent_start", async (_event, ctx) => {
    await transition(ctx, nextAgentState, `pi agent started (${nextAgentState})`);
    await refreshUi(ctx);
  });

  pi.on("agent_end", async (_event, ctx) => {
    nextAgentState = "developing";
    await transition(ctx, "idle", "pi agent ended");
    await refreshUi(ctx);
  });

  pi.on("tool_call", async (event, ctx) => {
    lastTool = event.toolName;

    if (event.toolName === "bash" && typeof event.input?.command === "string") {
      const command = event.input.command;
      if (isTestCommand(command)) {
        await transition(ctx, "testing", "pi running tests");
        await refreshUi(ctx);
      } else if (!isReadOnlyBash(command)) {
        await transition(ctx, "developing", "pi bash command may change state");
        await refreshUi(ctx);
      }
    } else if (["edit", "write"].includes(event.toolName)) {
      await transition(ctx, "developing", `pi ${event.toolName} tool called`);
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
