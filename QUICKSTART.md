# CipherAtlas 60-second start

### Windows / VS Code

```powershell
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`.

### Fast demo

Go to **Migration rehearsal**.

1. Click **1 · Silent fallback**. Expected measured result: connection succeeds but the observed group is `X25519`, so `X25519MLKEM768` was **not** achieved.
2. Click **3 · Modern pass**. Expected measured result: `X25519MLKEM768` is observed and the state becomes `VALIDATED_IN_TEST_ENV`.
3. Click **Show raw evidence** or **Download JSON** when a judge asks for proof.

### Live mode

If the laptop's local OpenSSL exposes `X25519MLKEM768`, choose **This laptop · live OpenSSL probe**. If not, the app returns `INCONCLUSIVE` rather than fabricating a result.
