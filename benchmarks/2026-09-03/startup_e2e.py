"""Process startup: time from exec to 'listening', for the server and for a
client with each format (the client pre-warms its format's DFAs)."""
import json, os, subprocess, sys, tempfile, time
ROOT='/Users/kpdyer/sandbox/github/fteproxy/.claude/worktrees/fteproxy-cli-ergonomics-476910'
sys.path.insert(0, ROOT)
import benchmark as B
out={}
dest=B.LoopServer(B.free_port(), mode='echo'); dest.start()
state=tempfile.mkdtemp(prefix='fteproxy-startup-')
sport=B.free_port()
py=sys.executable
t0=time.perf_counter()
srv=subprocess.Popen([py,'-m','fteproxy','server','-q','--listen','127.0.0.1:%d'%sport,
  '--advertise','127.0.0.1:%d'%sport,'--allow','127.0.0.1:%d'%dest.port,'--state-dir',state],
  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
B.wait_listening(sport)
out['server_ms']=(time.perf_counter()-t0)*1e3
uri=open(os.path.join(state,'connection.txt')).read().strip()
for fmt in ('http','ftp','smtp','sip','dns'):
    eport=B.free_port()
    t0=time.perf_counter()
    cli=subprocess.Popen([py,'-m','fteproxy','client',uri,'-q','--no-check','--format',fmt,
      '-L','127.0.0.1:%d:127.0.0.1:%d'%(eport,dest.port),'--state-dir',state],
      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    B.wait_listening(eport)
    out['client_%s_ms'%fmt]=(time.perf_counter()-t0)*1e3
    cli.terminate(); cli.wait(timeout=5)
srv.terminate(); srv.wait(timeout=5); dest.stop()
print(json.dumps(out))
