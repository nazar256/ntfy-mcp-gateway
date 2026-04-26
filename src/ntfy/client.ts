import { validateTopic, validateMessageBytes, validateHeaderValue } from "../security/validators.ts";
import type { NtfyConfig } from "../security/validators.ts";

export interface NotificationRequest {
  message: string;
  title?: string;
  topic?: string;
  tags?: string[];
  priority?: number;
  click?: string;
  delay?: string;
  markdown?: boolean;
  attach?: string;
  filename?: string;
}

export interface NtfyPublishResult {
  success: boolean;
  status?: number;
  error?: string;
}

export async function publishNotification(
  req: NotificationRequest,
  config: NtfyConfig,
  fetchFn: typeof fetch = fetch
): Promise<NtfyPublishResult> {
  try {
    validateMessageBytes(req.message);
  } catch (e) {
    return { success: false, error: (e as Error).message };
  }

  let topic: string;
  if (req.topic) {
    if (!config.allowTopicOverride) {
      return { success: false, error: "Topic override is not allowed for this connection" };
    }
    try {
      topic = validateTopic(req.topic);
    } catch (e) {
      return { success: false, error: (e as Error).message };
    }
  } else {
    topic = config.defaultTopic;
  }

  const url = `${config.ntfyBaseUrl}/${topic}`;
  const headers: Record<string, string> = {
    "Content-Type": "text/plain; charset=utf-8",
  };

  if (config.ntfyAccessToken) {
    headers["Authorization"] = `Bearer ${config.ntfyAccessToken}`;
  }

  if (req.title) {
    try { validateHeaderValue(req.title, "title"); } catch (e) { return { success: false, error: (e as Error).message }; }
    headers["Title"] = req.title;
  }
  if (req.priority !== undefined) {
    if (req.priority < 1 || req.priority > 5) {
      return { success: false, error: "Priority must be 1–5" };
    }
    headers["Priority"] = String(req.priority);
  }
  if (req.tags && req.tags.length > 0) {
    const tagStr = req.tags.join(",");
    try { validateHeaderValue(tagStr, "tags"); } catch (e) { return { success: false, error: (e as Error).message }; }
    headers["Tags"] = tagStr;
  }
  if (req.click) {
    try { validateHeaderValue(req.click, "click"); } catch (e) { return { success: false, error: (e as Error).message }; }
    headers["Click"] = req.click;
  }
  if (req.delay) {
    try { validateHeaderValue(req.delay, "delay"); } catch (e) { return { success: false, error: (e as Error).message }; }
    headers["Delay"] = req.delay;
  }
  if (req.markdown) {
    headers["Markdown"] = "yes";
  }
  if (req.attach) {
    try { validateHeaderValue(req.attach, "attach"); } catch (e) { return { success: false, error: (e as Error).message }; }
    headers["Attach"] = req.attach;
  }
  if (req.filename) {
    try { validateHeaderValue(req.filename, "filename"); } catch (e) { return { success: false, error: (e as Error).message }; }
    headers["Filename"] = req.filename;
  }

  let response: Response;
  try {
    response = await fetchFn(url, {
      method: "POST",
      headers,
      body: req.message,
    });
  } catch (e) {
    return { success: false, error: `Network error: ${(e as Error).message}` };
  }

  if (!response.ok) {
    const body = await response.text().catch(() => "");
    return { success: false, status: response.status, error: `ntfy returned ${response.status}: ${body.slice(0, 200)}` };
  }

  return { success: true, status: response.status };
}
