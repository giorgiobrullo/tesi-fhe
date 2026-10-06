"""Capture one already terminal, validated case from exact saved raw bytes."""
from pathlib import Path
import hashlib,json,os
HERE=Path(__file__).resolve().parent
RAW=HERE.parents[1]/"runs/first-key1/stdout.jsonl"
REVIEW=HERE.parent/"independent-review/review.json"
def save(name,data):
    fd=os.open(HERE/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"wb") as f:
        f.write(data);f.flush();os.fsync(f.fileno())
def main():
    expected_review="8a960134f81f10840a5f98c17ebfe605952a702a11c154737ee58c73b5dd83a6"
    rb=REVIEW.read_bytes()
    assert hashlib.sha256(rb).hexdigest()==expected_review
    review=json.loads(rb)
    h=hashlib.sha256(); selected=[]; indices=[]; count=0
    with RAW.open("rb") as f:
        for i,line in enumerate(f,1):
            h.update(line);count=i
            r=json.loads(line)
            if r.get("keyset")==0 and r.get("scene")=="dense_nonzero" and r.get("x")==17:
                selected.append(line);indices.append(i)
    assert count==17703 and h.hexdigest()==review["raw_sha256"]
    blob=b"".join(selected)
    assert len(selected)==632
    save("selected-case.jsonl",blob)
    meta=dict(schema="a182-selected-validated-case-v1",raw_sha256=h.hexdigest(),raw_lines=count,
        source_review_sha256=expected_review,selected_case=dict(keyset=0,scene="dense_nonzero",x=17),
        selected_lines=indices,selected_case_sha256=hashlib.sha256(blob).hexdigest(),selected_count=len(selected),
        evidence_level="Deterministic replay of preserved observations; no independent secret-membership attestation.")
    save("CAPTURE.json",(json.dumps(meta,indent=2,sort_keys=True)+"\n").encode())
    print(json.dumps({"status":"EXACT_VALIDATED_CASE_CAPTURED","selected_count":len(selected),"raw_lines":count}))
if __name__=="__main__":main()
