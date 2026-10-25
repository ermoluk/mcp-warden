# Demo animation

`docs/demo.gif` is rendered from [`demo.html`](demo.html). Every frame is a
pure function of time (`render(t)`), so the GIF is reproducible. Open
`demo.html` in a browser to watch it live while editing.

Regenerate:

```bash
npm i puppeteer-core                                   # once, in any folder
NODE_PATH=<that folder>/node_modules node docs/demo/render.cjs /tmp/frames 15
ffmpeg -y -framerate 15 -i /tmp/frames/f%04d.png \
  -vf "scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle" \
  -loop 0 docs/demo.gif
```

`render.cjs` uses the local Google Chrome (override with `CHROME=/path/to/chrome`).
Fonts (Archivo, IBM Plex Mono) load from Google Fonts, so render online.
Text shown as mcp-warden output — the refusal message, the Telegram prompt —
is copied from the code; keep it in sync if those strings change.
