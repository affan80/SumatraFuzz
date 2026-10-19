const assert = require('node:assert/strict');
const { existsSync, readFileSync } = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const repositoryRoot = path.resolve(__dirname, '..');
const desktopRoot = path.join(repositoryRoot, 'apps', 'desktop');
const desktopPackage = JSON.parse(readFileSync(path.join(desktopRoot, 'package.json'), 'utf8'));

test('desktop package main, preload and renderer resolve to built files', () => {
  assert.equal(existsSync(path.join(desktopRoot, desktopPackage.main)), true);
  assert.equal(existsSync(path.join(desktopRoot, 'dist', 'src', 'preload', 'index.js')), true);
  assert.equal(existsSync(path.join(desktopRoot, 'dist', 'renderer', 'index.html')), true);
});
