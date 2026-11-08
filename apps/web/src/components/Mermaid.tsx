import { useEffect, useId, useState } from 'react';
import mermaid from 'mermaid';
import { useTheme, type Theme } from '../lib/theme';

const FONT = "'Archivo', 'Helvetica Neue', Arial, sans-serif";

// Matches styles.css for each theme: green for the happy path / notes, red for alt branches.
const VARS: Record<Theme, Record<string, string>> = {
  light: {
    background: '#ffffff', primaryColor: '#ffffff', primaryTextColor: '#0b0b0b', primaryBorderColor: '#0b0b0b',
    secondaryColor: '#e3f6e9', tertiaryColor: '#f6f5f0', lineColor: '#0b0b0b', textColor: '#0b0b0b',
    mainBkg: '#ffffff', nodeBorder: '#0b0b0b', clusterBkg: '#f6f5f0', clusterBorder: '#0b0b0b',
    actorBkg: '#0b0b0b', actorBorder: '#0b0b0b', actorTextColor: '#ffffff', actorLineColor: '#9a9a93',
    signalColor: '#0b0b0b', signalTextColor: '#0b0b0b', labelBoxBkgColor: '#00a63e', labelBoxBorderColor: '#0b0b0b',
    labelTextColor: '#ffffff', loopTextColor: '#0b0b0b', noteBkgColor: '#e3f6e9', noteBorderColor: '#00a63e',
    noteTextColor: '#0b0b0b', activationBkgColor: '#e3f6e9', activationBorderColor: '#00a63e',
    sequenceNumberColor: '#ffffff', altBackground: '#fde6e4', edgeLabelBackground: '#ffffff',
  },
  dark: {
    background: '#131313', primaryColor: '#131313', primaryTextColor: '#f1f1ea', primaryBorderColor: '#e9e9e3',
    secondaryColor: '#0d2a18', tertiaryColor: '#1b1b1a', lineColor: '#c9c9c1', textColor: '#f1f1ea',
    mainBkg: '#131313', nodeBorder: '#e9e9e3', clusterBkg: '#1b1b1a', clusterBorder: '#3a3a36',
    actorBkg: '#f1f1ea', actorBorder: '#f1f1ea', actorTextColor: '#0b0b0b', actorLineColor: '#5a5a55',
    signalColor: '#e9e9e3', signalTextColor: '#f1f1ea', labelBoxBkgColor: '#00c04b', labelBoxBorderColor: '#00c04b',
    labelTextColor: '#0b0b0b', loopTextColor: '#f1f1ea', noteBkgColor: '#0d2a18', noteBorderColor: '#00c04b',
    noteTextColor: '#f1f1ea', activationBkgColor: '#0d2a18', activationBorderColor: '#00c04b',
    sequenceNumberColor: '#0b0b0b', altBackground: '#2e0e0b', edgeLabelBackground: '#131313',
  },
};

const configure = (theme: Theme) =>
  mermaid.initialize({
    startOnLoad: false,
    theme: 'base',
    securityLevel: 'strict',
    fontFamily: FONT,
    sequence: { showSequenceNumbers: true, mirrorActors: false, messageAlign: 'left' },
    themeVariables: { fontSize: '14px', ...VARS[theme] },
  });

export function Mermaid({ code, title }: { code: string; title?: string }) {
  const id = useId().replace(/:/g, '');
  const [svg, setSvg] = useState('');
  const [err, setErr] = useState('');
  const [showSrc, setShowSrc] = useState(false);
  const theme = useTheme();

  useEffect(() => {
    let cancelled = false;
    configure(theme); // mermaid config is global, so set it right before each render
    mermaid
      .render(`m${id}${theme}`, code)
      .then(({ svg }) => !cancelled && setSvg(svg))
      .catch((e) => !cancelled && setErr(String(e?.message ?? e)));
    return () => { cancelled = true; };
  }, [code, id, theme]);

  return (
    <figure className="diagram">
      {title && <figcaption>{title} <button className="link" onClick={() => setShowSrc((s) => !s)}>{showSrc ? 'diagram' : 'source'}</button></figcaption>}
      {showSrc ? <pre className="code">{code}</pre> : err ? <pre className="error">{err}</pre> : <div className="svg" dangerouslySetInnerHTML={{ __html: svg }} />}
    </figure>
  );
}
