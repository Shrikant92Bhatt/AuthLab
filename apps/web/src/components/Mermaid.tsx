import { useEffect, useId, useState } from 'react';
import mermaid from 'mermaid';

mermaid.initialize({
  startOnLoad: false,
  theme: 'dark',
  securityLevel: 'strict',
  fontFamily: 'Inter, system-ui, sans-serif',
  sequence: { showSequenceNumbers: true, mirrorActors: false, messageAlign: 'left' },
  themeVariables: { primaryColor: '#312e81', primaryBorderColor: '#6366f1', lineColor: '#94a3b8', fontSize: '14px' },
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
