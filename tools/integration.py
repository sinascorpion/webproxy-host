#!/usr/bin/env python3
# Copyright (c) 2026 sinascorpion. SPDX-License-Identifier: MIT
"""Isolated Linux integration check; requires nginx, openssl and cryptography."""
import http.client,json,os,pathlib,signal,ssl,subprocess,time,tempfile,sys,importlib.util
repo=pathlib.Path(__file__).resolve().parents[1]
binary=pathlib.Path(sys.argv[1]).resolve() if len(sys.argv)>1 else repo/"dist/webproxy-host_linux_amd64"
root=pathlib.Path(tempfile.mkdtemp(prefix="webproxy-host-check-"))
app=None
nginx=False
try:
 cert=root/"cert.pem";key=root/"key.pem"
 subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-days","1","-subj","/CN=example.com","-addext","subjectAltName=DNS:example.com,DNS:example.org","-keyout",str(key),"-out",str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 env={**os.environ,"ADMIN_PASSWORD":"integration-test-password-only","ADMIN_UID":"integration-control-0123456789","PUBLIC_URL":"https://example.com","HOST":"127.0.0.1","SERVER_PORT":"19380","CORE_PORT":"19381","CORE_API_PORT":"19382","DATA_DIR":str(root/"data")}
 logfile=(root/"app.log").open("w")
 app=subprocess.Popen([str(binary)],env=env,stdout=logfile,stderr=logfile)
 def req(path,body=None,cookie="",csrf=""):
  conn=http.client.HTTPConnection("127.0.0.1",19380,timeout=10)
  headers={"Host":"example.com","Origin":"https://example.com","Content-Type":"application/json"}
  if cookie:headers["Cookie"]=cookie
  if csrf:headers["X-CSRF-Token"]=csrf
  conn.request("GET" if body is None else "POST",path,None if body is None else json.dumps(body),headers)
  r=conn.getresponse();data=r.read();h=dict(r.getheaders());status=r.status;conn.close();return status,h,data
 for _ in range(100):
  try:
   if req("/healthz")[0]==200:break
  except OSError:pass
  time.sleep(.1)
 base="/integration-control-0123456789/api/"
 code,headers,body=req(base+"login",{"password":env["ADMIN_PASSWORD"]})
 assert code==200,(code,body)
 cookie=headers["Set-Cookie"].split(";",1)[0];csrf=json.loads(body)["csrf"]
 secret="12"*16
 code,_,body=req(base+"deploy",{"profiles":[{"domain":"example.com","secret":secret,"tag":""}]},cookie,csrf)
 assert code==202,(code,body)
 for _ in range(120):
  code,_,body=req(base+"state",cookie=cookie)
  state=json.loads(body)
  if state["job"]!="deploying":break
  time.sleep(1)
 assert state["job"]=="deployed" and state["running"],state["job"]
 config=root/"nginx.conf"
 config.write_text(f"pid {root}/nginx.pid;\nerror_log {root}/error.log;\nevents {{}}\nhttp {{ client_body_temp_path {root}/body; proxy_temp_path {root}/proxy; fastcgi_temp_path {root}/fastcgi; uwsgi_temp_path {root}/uwsgi; scgi_temp_path {root}/scgi; access_log off; server {{ listen 127.0.0.1:19443 ssl; server_name example.com; ssl_certificate {cert}; ssl_certificate_key {key}; location / {{ proxy_pass http://127.0.0.1:19380; proxy_set_header Host $host; proxy_http_version 1.1; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection \"upgrade\"; proxy_buffering off; proxy_read_timeout 120s; }} }} }}")
 subprocess.run(["nginx","-p",str(root),"-c",str(config)],check=True);nginx=True
 spec=importlib.util.spec_from_file_location("probe",str(repo/"tools/probe.py"))
 probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)
 original=probe.ssl.create_default_context
 def trusted_context(*args,**kwargs):return original(cafile=str(cert))
 probe.ssl.create_default_context=trusted_context
 def verify(host, value):
  os.environ["MTP_SECRET"]=value
  sys.argv=["probe","--host",host,"--connect-ip","127.0.0.1","--connect-port","19443","--telegram"]
  probe.main()
 verify("example.com",secret)
 profiles=[{"domain":"example.com","secret":secret,"tag":""},{"domain":"example.org","secret":"34"*16,"tag":""},{"domain":"example.com","secret":"56"*16,"tag":""}]
 assert req(base+"deploy",{"profiles":profiles},cookie,csrf)[0]==202
 for _ in range(60):
  state=json.loads(req(base+"state",cookie=cookie)[2])
  if state["job"]!="deploying":break
  time.sleep(.5)
 assert state["job"]=="deployed" and state["running"],state["job"]
 for profile in profiles:verify(profile["domain"],profile["secret"])
 print("PASS: multiple domains, multiple Secrets and redeploy preserving the first Secret")
 assert req(base+"deploy",{"profiles":[{"domain":"does-not-exist.invalid","secret":secret}]},cookie,csrf)[0]==202
 for _ in range(30):
  state=json.loads(req(base+"state",cookie=cookie)[2])
  if state["job"]!="deploying":break
  time.sleep(.5)
 assert state["job"].startswith("Deployment failed:") and state["running"] and len(state["profiles"])==3
 verify("example.com",secret)
 print("PASS: failed DNS deployment preserves the active proxy and Secrets")
 rss=[]
 children=pathlib.Path(f"/proc/{app.pid}/task/{app.pid}/children").read_text().split()
 for pid in [str(app.pid)]+children:
  try:
   status=pathlib.Path(f"/proc/{pid}/status").read_text().splitlines()
   rss.append((status[0],next(line for line in status if line.startswith("VmRSS:"))))
  except (OSError,StopIteration):pass
 print("Observed process RSS:",rss)
 code,_,body=req(base+"stop",{},cookie,csrf);assert code==202
 for _ in range(20):
  state=json.loads(req(base+"state",cookie=cookie)[2])
  if state["job"]=="disabled":break
  time.sleep(.5)
 assert not state["running"] and len(state["profiles"])==3
 assert json.loads((root/"data/state.json").read_text())["enabled"] is False
 app.terminate();app.wait(timeout=15)
 app=subprocess.Popen([str(binary)],env=env,stdout=logfile,stderr=logfile)
 for _ in range(100):
  try:
   if req("/healthz")[0]==200:break
  except OSError:pass
  time.sleep(.1)
 code,headers,body=req(base+"login",{"password":env["ADMIN_PASSWORD"]});assert code==200
 cookie=headers["Set-Cookie"].split(";",1)[0]
 state=json.loads(req(base+"state",cookie=cookie)[2]);assert not state["running"] and len(state["profiles"])==3
 print("PASS: admin login, async deploy, disable and durable disabled state after restart")

except BaseException:
 if (root/"app.log").exists():print((root/"app.log").read_text())
 raise
finally:
 if nginx:subprocess.run(["nginx","-p",str(root),"-c",str(root/"nginx.conf"),"-s","quit"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 if app:
  app.terminate()
  try:app.wait(timeout=15)
  except subprocess.TimeoutExpired:app.kill();app.wait()
 import shutil
 shutil.rmtree(root)
