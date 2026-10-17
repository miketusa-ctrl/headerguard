import html from '../public/index.html';
import docs from '../public/docs.html';
import js from '../public/app.js.txt';
import css from '../public/style.css';
import { createApp } from './app.js';

const handle = createApp({ html, docs, js, css });
export default { fetch: (req, env, ctx) => handle(req, env, ctx) };
