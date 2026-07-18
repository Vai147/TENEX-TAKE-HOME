"use client";

import { useEffect, useRef, useState } from "react";

import { sendChatMessage, type ChatContext, type ChatTurn } from "@/lib/api";

interface ChatMessage {
  from: "claude" | "you";
  text: string;
}

const GREETING: ChatMessage = {
  from: "claude",
  text: "I've reviewed this upload. Ask me anything about the findings, the timeline, or a specific source IP.",
};

interface AskClaudeProps {
  uploadId?: number;
  /** Analysis facts passed to the (stubbed) backend for grounded answers. */
  context?: ChatContext | null;
}

export function AskClaude({ uploadId, context = null }: AskClaudeProps) {
  const [open, setOpen] = useState(false);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([GREETING]);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight });
  }, [messages, open]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    const text = input.trim();
    if (!text || sending) return;

    // Build history from the turns so far, before this message and minus the
    // static greeting. The backend appends `text` itself, so it is excluded here.
    const history: ChatTurn[] = messages.slice(1).map((m) => ({
      role: m.from === "you" ? "user" : "assistant",
      content: m.text,
    }));

    setMessages((prev) => [...prev, { from: "you", text }]);
    setInput("");
    setSending(true);
    try {
      const reply = await sendChatMessage(uploadId ?? 0, text, context, history);
      setMessages((prev) => [...prev, { from: "claude", text: reply }]);
    } catch {
      setMessages((prev) => [
        ...prev,
        { from: "claude", text: "Something went wrong reaching the assistant." },
      ]);
    } finally {
      setSending(false);
    }
  }

  return (
    <>
      {open && (
        <div className="fixed bottom-[84px] right-6 z-20 flex h-[440px] w-[360px] max-w-[calc(100vw-48px)] flex-col rounded-xl border border-border bg-surface shadow-panel">
          <div className="flex items-center gap-2 border-b border-divider px-4 py-3">
            <span className="h-1.5 w-1.5 rounded-full bg-accent" aria-hidden="true" />
            <span className="text-[12px] font-semibold text-ink-primary">
              Ask Claude
            </span>
            <button
              type="button"
              onClick={() => setOpen(false)}
              aria-label="Close chat"
              className="ml-auto text-[18px] leading-none text-ink-faint transition-colors hover:text-ink-primary"
            >
              ×
            </button>
          </div>

          <div
            ref={listRef}
            className="flex flex-1 flex-col gap-3 overflow-y-auto p-4"
          >
            {messages.map((msg, i) => (
              <Bubble key={i} msg={msg} />
            ))}
          </div>

          <form
            onSubmit={onSubmit}
            className="flex gap-2 border-t border-divider p-3"
          >
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="ask about this analysis…"
              className="flex-1 rounded-lg border border-border-strong bg-surface px-2.5 py-2 text-[12px] text-ink-primary outline-none transition focus:border-accent focus:ring-4 focus:ring-accent/15"
            />
            <button
              type="submit"
              disabled={sending}
              className="rounded-lg bg-accent px-4 text-[13px] font-semibold text-white transition-colors hover:bg-accent-hover disabled:opacity-60"
            >
              Send
            </button>
          </form>
        </div>
      )}

      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="fixed bottom-6 right-6 z-20 inline-flex items-center gap-2 rounded-full bg-accent px-5 py-3 text-[13px] font-semibold text-white shadow-fab transition-colors hover:bg-accent-hover"
      >
        <span className="h-[7px] w-[7px] rounded-full bg-white" aria-hidden="true" />
        Ask Claude
      </button>
    </>
  );
}

function Bubble({ msg }: { msg: ChatMessage }) {
  const isClaude = msg.from === "claude";
  return (
    <div
      className={`max-w-[85%] rounded-[10px] border px-3 py-2.5 ${
        isClaude
          ? "self-start border-accent-soft-border bg-accent-soft"
          : "self-end border-divider bg-surface-alt"
      }`}
    >
      <p
        className={`text-[9px] font-semibold tracking-[0.06em] ${
          isClaude ? "text-accent" : "text-ink-muted"
        }`}
      >
        {isClaude ? "CLAUDE" : "YOU"}
      </p>
      <p className="mt-1.5 whitespace-pre-line text-[12px] leading-relaxed text-ink-secondary">
        {msg.text}
      </p>
    </div>
  );
}
