"""MailSleuth analiza archivos EML de forma local para apoyar investigación de phishing."""
import argparse, email, json, re
from email import policy
from pathlib import Path
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument("message",type=Path);p.add_argument("--output",type=Path);a=p.parse_args();m=email.message_from_bytes(a.message.read_bytes(),policy=policy.default);body=m.get_body(preferencelist=("plain","html"));text=body.get_content() if body else "";urls=re.findall(r'https?://[^\s<>"\']+',text);find=[]
 for u in urls:
  if "@" in u or re.search(r'\d{1,3}(?:\.\d{1,3}){3}',u):find.append({"severity":"medium","rule":"suspicious-link","evidence":u})
 if not m.get("Authentication-Results"):find.append({"severity":"low","rule":"missing-auth-results","evidence":"No hay cabecera Authentication-Results"})
 data={"from":str(m.get("From","")),"subject":str(m.get("Subject","")),"received_hops":len(m.get_all("Received",[])),"urls":urls,"findings":find};out=json.dumps(data,indent=2);print(out)
 if a.output:a.output.write_text(out+"\n")
if __name__=="__main__":main()
