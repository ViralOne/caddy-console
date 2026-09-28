import { basicSetup, EditorView } from 'codemirror';
import { EditorState, StateEffect, StateField, RangeSetBuilder } from '@codemirror/state';
import { keymap, Decoration } from '@codemirror/view';
import { StreamLanguage, HighlightStyle, syntaxHighlighting } from '@codemirror/language';
import { tags } from '@lezer/highlight';
import { indentWithTab } from '@codemirror/commands';

window.CM = {
  EditorView, EditorState, keymap, StreamLanguage, basicSetup, indentWithTab,
  // Used to build the editor theme from the app's design tokens rather than
  // shipping a second, unrelated dark theme.
  HighlightStyle, syntaxHighlighting, tags,
  // Used by the find bar to highlight matches and the current row.
  Decoration, StateEffect, StateField, RangeSetBuilder,
};
