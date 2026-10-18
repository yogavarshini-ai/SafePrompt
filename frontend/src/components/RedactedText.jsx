const TOKEN_SPLIT = /(\{\{TOKEN_[0-9a-fA-F]+\}\}|\[[A-Z_]+_\d+\])/

// Shows masked tokens such as [PERSON_1] as redaction bars.
export default function RedactedText({ text }) {
  if (!text) return null
  return (
    <span className="whitespace-pre-wrap break-words">
      {text.split(TOKEN_SPLIT).map((part, index) =>
        index % 2 === 1 ? (
          <span
            key={index}
            className="mx-0.5 inline-block rounded-sm bg-[#0b1220] px-1.5 py-px align-baseline font-mono text-[0.78em] leading-snug text-slate-100"
            title="Masked before leaving the network"
          >
            {part}
          </span>
        ) : (
          part
        ),
      )}
    </span>
  )
}
