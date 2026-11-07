import { useEffect, useId, useState } from 'react';
import mermaid from 'mermaid';

mermaid.initialize({
  startOnLoad: false,
  theme: 'base',
  securityLevel: 'strict',
  fontFamily: "'Archivo', 'Helvetica Neue', Arial, sans-serif",
  sequence: { showSequenceNumbers: true, mirrorActors: false, messageAlign: 'left' },
  // Matches styles.css: black ink on white, green for the happy path, red for alerts.
  themeVariables: {
    fontSize: '14px',
    background: '#ffffff',
    primaryColor: '#ffffff', primaryTextColor: '#0b0b0b', primaryBorderColor: '#0b0b0b',
    secondaryColor: '#e3f6e9', tertiaryColor: '#f6f5f0',
    lineColor: '#0b0b0b', textColor: '#0b0b0b', mainBkg: '#ffffff', nodeBorder: '#0b0b0b',
    clusterBkg: '#f6f5f0', clusterBorder: '#0b0b0b',
    actorBkg: '#0b0b0b', actorBorder: '#0b0b0b', actorTextColor: '#ffffff', actorLineColor: '#9a9a93',
    signalColor: '#0b0b0b', signalTextColor: '#0b0b0b',
    labelBoxBkgColor: '#00a63e', labelBoxBorderColor: '#0b0b0b', labelTextColor: '#ffffff', loopTextColor: '#0b0b0b',
    noteBkgColor: '#e3f6e9', noteBorderColor: '#00a63e', noteTextColor: '#0b0b0b',
    activationBkgColor: '#e3f6e9', activationBorderColor: '#00a63e',
    sequenceNumberColor: '#ffffff',
    altBackground: '#fde6e4',
    edgeLabelBackground: '#ffffff',
  },
});

export function Mermaid({ code, title }: { code: string; title?: string }) {
  const id = useId().replace(/:/g, '');
  const [svg, setSvg] = useState('');
  const [err, setErr] = useState('');
  const [showSrc, setShowSrc] = useState(false);

  useEffect(() => {
    let cancelled = false;
    mermaid
      .render(`m${id}`, code)
      .then(({ svg }) => !cancelled && setSvg(svg))
      .catch((e) => !cancelled && setErr(String(e?.message ?? e)));
    return () => { cancelled = true; };
  }, [code, id]);

  return (
    <figure className="diagram">
      {title && <figcaption>{title} <button className="link" onClick={() => setShowSrc((s) => !s)}>{showSrc ? 'diagram' : 'source'}</button></figcaption>}
      {showSrc ? <pre className="code">{code}</pre> : err ? <pre className="error">{err}</pre> : <div className="svg" dangerouslySetInnerHTML={{ __html: svg }} />}
    </figure>
  );
}
