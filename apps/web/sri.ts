import { createHash } from 'node:crypto';
import type { IndexHtmlTransformContext, Plugin } from 'vite';

/**
 * SRI hashing for the built bundle. Vite emits content-addressed filenames, so a
 * hash recorded at build time stays valid for as long as the served files are the
 * built ones. The Go server serves the dist directory byte-for-byte, so the
 * integrity attributes hold in production.
 */

export function computeIntegrity(content: Uint8Array | string): string {
  const buf = typeof content === 'string' ? Buffer.from(content, 'utf8') : Buffer.from(content);
  return `sha384-${createHash('sha384').update(buf).digest('base64')}`;
}

/** Inject integrity + crossorigin attributes into script and stylesheet tags. */
export function injectSriAttributes(html: string, integrity: ReadonlyMap<string, string>): string {
  return html
    .replace(/<script([^>]*)src="([^"]+)"([^>]*)>/g, (match, pre, src, post) => {
      const hash = integrity.get(bareName(src));
      if (!hash) return match;
      const cross = /\bcrossorigin\b/.test(pre + post) ? '' : ' crossorigin="anonymous"';
      return `<script${pre}src="${src}" integrity="${hash}"${cross}${post}>`;
    })
    .replace(/<link([^>]*)href="([^"]+)"([^>]*)(?:\/?>)/g, (match, pre, href, post) => {
      const hash = integrity.get(bareName(href));
      if (!hash) return match;
      const cross = /\bcrossorigin\b/.test(pre + post) ? '' : ' crossorigin="anonymous"';
      return `<link${pre}href="${href}" integrity="${hash}"${cross}${post}>`;
    });
}

function bareName(url: string): string {
  const [path] = url.split('?');
  return (path ?? url).replace(/^\//, '');
}

/** Vite plugin: add SRI to every local script and stylesheet in the built HTML. */
export function viteSri(): Plugin {
  return {
    name: 'sendarc-sri',
    apply: 'build',
    enforce: 'post',
    transformIndexHtml: {
      order: 'post',
      handler(html: string, ctx: IndexHtmlTransformContext) {
        if (!ctx.bundle) return html;
        const integrity = new Map<string, string>();
        for (const [name, item] of Object.entries(ctx.bundle)) {
          if (item.type === 'chunk') {
            integrity.set(name, computeIntegrity(item.code));
          } else if (item.type === 'asset') {
            integrity.set(name, computeIntegrity(item.source));
          }
        }
        return injectSriAttributes(html, integrity);
      },
    },
  };
}
