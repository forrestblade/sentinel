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

export default function (pi: ExtensionAPI) {
  let warnedDown = false;
  let started = false;
  let widgetVisible = true;
  let verboseWidget = false;
  let lastDecision = "startup";
  let lastTool = "none";
  let refreshTimer: ReturnType<typeof setInterval> | undefined;

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

  pi.on("session_start", async (_event, ctx) => {
    if (!(await healthy())) {
      started = startSentinel();
      if (started) await new Promise((resolve) => setTimeout(resolve, 800));
    }

    if (await healthy()) {
      warnedDown = false;
    } else {
      ctx.ui.notify("Sentinel off; fail-open.", "warning");
      warnedDown = true;
    }

    await refreshUi(ctx);
    refreshTimer = setInterval(() => void refreshUi(ctx), 10_000);
  });

  pi.on("session_shutdown", async (_event, ctx) => {
    if (refreshTimer) clearInterval(refreshTimer);
    refreshTimer = undefined;
    ctx.ui.setWidget("sentinel", undefined);
    ctx.ui.setStatus("sentinel", undefined);
  });

  pi.on("tool_call", async (event, ctx) => {
    lastTool = event.toolName;
    try {
      const result = await post("/gate", {
        source: "pi",
        tool_name: event.toolName,
        tool_input: event.input,
        tool_call_id: event.toolCallId,
      }, ctx.signal);

      const output = result?.hookSpecificOutput;
      lastDecision = output?.permissionDecision ?? "allow";
      await refreshUi(ctx);
      if (output?.permissionDecision === "deny") {
        return { block: true, reason: output.permissionDecisionReason ?? "Blocked by Sentinel" };
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
      // Receipt generation is best-effort/fail-open, matching Sentinel's Claude hook behavior.
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
