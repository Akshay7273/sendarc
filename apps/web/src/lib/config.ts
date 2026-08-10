let publicUrl: string | undefined;

export async function loadConfig(): Promise<void> {
  try {
    const res = await fetch('/config.json');
    if (!res.ok) return;
    const data = await res.json();
    publicUrl = data.publicUrl || undefined;
  } catch {
    // config.json is optional; fall through to auto-detection.
  }
}

export function baseUrl(): string {
  return publicUrl ?? (typeof window === 'undefined' ? '' : window.location.href);
}
