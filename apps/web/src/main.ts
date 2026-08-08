import { mount } from 'svelte';
import App from './App.svelte';

const target = document.getElementById('app');
if (!target) {
  throw new Error('missing #app mount point');
}

const app = mount(App, { target });

export default app;
