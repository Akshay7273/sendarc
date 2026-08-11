<script lang="ts">
  import { onMount } from 'svelte';
  import QRCode from 'qrcode';

  let { data, size = 180 }: { data: string; size?: number } = $props();
  let canvas: HTMLCanvasElement | undefined = $state();

  onMount(async () => {
    if (!canvas || !data) return;
    try {
      await QRCode.toCanvas(canvas, data, {
        width: size,
        margin: 2,
        color: { dark: '#000', light: '#fff' },
      });
    } catch {
      // QR code generation failed silently.
    }
  });
</script>

<canvas bind:this={canvas} aria-label="QR code for the invite link"></canvas>
