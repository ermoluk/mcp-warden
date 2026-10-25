// Renders docs/demo/demo.html to PNG frames with headless Chrome.
//
//   npm i puppeteer-core            # once, anywhere on NODE_PATH
//   node docs/demo/render.cjs <out-dir> [fps]          # every frame
//   node docs/demo/render.cjs <out-dir> --at 7.5 15.4  # selected moments
//
// Then build the GIF (see docs/demo/README.md):
//   ffmpeg -framerate 15 -i <out-dir>/f%04d.png ... docs/demo.gif
const path = require('path');
const fs = require('fs');
const puppeteer = require('puppeteer-core');

const CHROME = process.env.CHROME ||
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

(async () => {
  const [outDir, ...rest] = process.argv.slice(2);
  if (!outDir) throw new Error('usage: render.cjs <out-dir> [fps | --at t1 t2 …]');
  fs.mkdirSync(outDir, { recursive: true });

  const browser = await puppeteer.launch({ executablePath: CHROME, headless: true });
  const page = await browser.newPage();
  await page.setViewport({ width: 1280, height: 720, deviceScaleFactor: 1 });
  await page.goto('file://' + path.join(__dirname, 'demo.html'));
  await page.evaluate(() => document.fonts.ready);

  const shoot = async (t, file) => {
    await page.evaluate((t) => window.render(t), t);
    await page.screenshot({ path: path.join(outDir, file) });
  };

  if (rest[0] === '--at') {
    for (const t of rest.slice(1).map(Number)) await shoot(t, `at-${t.toFixed(2)}.png`);
  } else {
    const fps = Number(rest[0] || 15);
    const duration = await page.evaluate(() => window.DURATION);
    const n = Math.round(duration * fps);
    for (let i = 0; i < n; i++) await shoot(i / fps, `f${String(i).padStart(4, '0')}.png`);
    console.log(`${n} frames @ ${fps} fps → ${outDir}`);
  }
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
