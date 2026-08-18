import { useState } from 'react'

/**
 * A field guide on the landing page: how to actually produce the files the three
 * upload zones accept, on a real server. The GC-log flags differ by Java version,
 * so a small toggle switches the version-specific commands.
 */
export default function CaptureGuide() {
  const [jver, setJver] = useState('11')   // '8' | '11'
  const modern = jver === '11'

  return (
    <div className="border-t border-ink-700/40 pt-12 mt-12 animate-fade-in">
      <div className="flex items-center gap-3 mb-3">
        <span className="label">// field guide</span>
        <div className="h-px flex-1 bg-ink-600/50 max-w-[200px]" />
      </div>
      <h2 className="font-display text-2xl md:text-3xl text-bone-100 tracking-tightest mb-3">
        Don’t have the files yet? Capture them on the server.
      </h2>
      <p className="text-bone-400 max-w-2xl text-sm md:text-base leading-relaxed mb-6">
        SSH in (PuTTY on Windows), find the Java process, and run the right command for your
        JDK. Then drop the output into the matching zone above.
      </p>

      <div className="flex items-center gap-2 flex-wrap mb-8">
        <span className="label text-bone-400">your app runs</span>
        <button onClick={() => setJver('8')}
                className={`badge ${jver === '8' ? 'badge-ok' : 'badge-neutral'}`}>Java 8</button>
        <button onClick={() => setJver('11')}
                className={`badge ${modern ? 'badge-ok' : 'badge-neutral'}`}>Java 11+ / 17 / 21</button>
        <span className="font-mono text-[10px] text-bone-500 ml-1">
          (check with <code className="text-bone-300">java -version</code>)
        </span>
      </div>

      <div className="space-y-8">
        <Step n="01" title="Connect to the server">
          <P>From Windows use PuTTY (host, port 22, Open). From macOS/Linux, SSH directly:</P>
          <Cmd cmd="ssh youruser@your-server-host" />
        </Step>

        <Step n="02" title="Find the Java process (PID)">
          <P>List running JVMs with the JDK’s own tool, or fall back to <code className="codei">ps</code>:</P>
          <Cmd cmd="jps -l" note="lists each Java PID with its main class" />
          <Cmd cmd="ps -ef | grep [j]ava" note="if jps isn’t on the box" />
          <P>For <strong className="text-bone-200">high CPU</strong>, find the hot threads inside that PID:</P>
          <Cmd cmd="top -H -p <pid>" note="per-thread CPU; note the TID burning CPU" />
          <Cmd cmd="printf '%x\\n' <tid>" note="convert the TID to hex → matches nid=0x… in the thread dump" />
        </Step>

        <Step n="03" title="Thread dump — high CPU, hangs, deadlocks">
          <P>Take <strong className="text-bone-200">3 dumps ~5–10s apart</strong> so you can see what’s
            actually stuck or looping (the comparison view pinpoints threads stuck across all three):</P>
          {modern ? (
            <Cmd cmd="jcmd <pid> Thread.print > td-$(date +%F-%H%M%S).txt" note="preferred on modern JDKs" />
          ) : (
            <Cmd cmd="jstack <pid> > td-$(date +%F-%H%M%S).txt" />
          )}
          <Cmd cmd="kill -3 <pid>" note="no JDK tools on the box? signals the JVM — dump goes to its stdout/console log" />
          {modern && (
            <Cmd cmd="jcmd <pid> Thread.dump_to_file -format=json td.json"
                 note="Java 21+ with virtual threads (Project Loom)" />
          )}
        </Step>

        <Step n="04" title="Heap dump — memory leak, OutOfMemoryError">
          <P>Captures every object on the heap (can be large — write it to a disk with room):</P>
          {modern ? (
            <Cmd cmd="jcmd <pid> GC.heap_dump /var/tmp/heap-$(date +%F).hprof" note="preferred on modern JDKs" />
          ) : (
            <Cmd cmd="jmap -dump:live,format=b,file=/var/tmp/heap-$(date +%F).hprof <pid>"
                 note="‘live’ runs a GC first → smaller dump of only reachable objects" />
          )}
          <P>Better still, capture one <strong className="text-bone-200">automatically on OOM</strong> (add to startup flags):</P>
          <Cmd cmd="-XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/var/log/app/" />
        </Step>

        <Step n="05" title="GC log — GC pressure, throughput, leak trend">
          <P>These are JVM <strong className="text-bone-200">startup flags</strong> — add them and restart the app:</P>
          {modern ? (
            <Cmd cmd="-Xlog:gc*:file=/var/log/app/gc.log:time,uptime,level,tags:filecount=5,filesize=20M"
                 note="unified logging (Java 9+)" />
          ) : (
            <Cmd cmd="-XX:+PrintGCDetails -XX:+PrintGCDateStamps -Xloggc:/var/log/app/gc.log"
                 note="legacy GC logging (Java 8)" />
          )}
          {modern && (
            <>
              <P>Can’t restart right now? Turn it on at runtime (Java 11+):</P>
              <Cmd cmd="jcmd <pid> VM.log output=/var/log/app/gc.log decorators=time,uptime what=gc*" />
            </>
          )}
        </Step>
      </div>

      <p className="text-bone-500 text-xs font-mono mt-8">
        → then drag each file onto its zone above. Analyze a thread dump + heap dump (+ GC log)
        together to unlock cross-dump correlation.
      </p>
    </div>
  )
}

function Step({ n, title, children }) {
  return (
    <div className="flex gap-4">
      <div className="font-mono text-flag-ok text-sm shrink-0 w-7">{n}</div>
      <div className="flex-1 min-w-0 space-y-3">
        <h3 className="font-display text-lg text-bone-100">{title}</h3>
        {children}
      </div>
    </div>
  )
}

function P({ children }) {
  return <p className="text-sm text-bone-400 leading-relaxed">{children}</p>
}

function Cmd({ cmd, note }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    try {
      navigator.clipboard?.writeText(cmd).then(() => {
        setCopied(true)
        setTimeout(() => setCopied(false), 1200)
      }).catch(() => {})
    } catch {}
  }
  return (
    <div>
      <div className="panel-inset flex items-start gap-3 px-3 py-2">
        <code className="flex-1 font-mono text-[11px] text-bone-200 whitespace-pre overflow-x-auto leading-relaxed">
          {cmd}
        </code>
        <button
          onClick={copy}
          className="font-mono text-[10px] uppercase tracking-wider text-bone-500 hover:text-bone-200 shrink-0"
        >
          {copied ? 'copied' : 'copy'}
        </button>
      </div>
      {note && <p className="text-[11px] text-bone-500 mt-1 leading-snug">{note}</p>}
    </div>
  )
}
