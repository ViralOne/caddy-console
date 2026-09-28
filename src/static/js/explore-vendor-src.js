// Vendor entry for the Explore view. Bundled to explore-vendor.js by
// `npm run build:vendor` and committed, exactly like editor.bundle.js.
//
// htm is a tagged-template replacement for JSX, so app code needs no build
// step: only this file does, and only when the dependency is bumped.
export { h, render } from 'preact';
export { useState, useEffect, useMemo, useRef, useCallback } from 'preact/hooks';
export { default as htm } from 'htm';
